#!/usr/bin/env python3
"""
Project #14 - Cloud Security Monitoring Tool (AWS)

Checks a real AWS account (via boto3 + your configured credentials/profile)
for common misconfigurations across three services:

  S3   - public bucket access, missing default encryption, missing versioning
  IAM  - overly permissive ("*"/"*") policies, stale access keys, users
         without MFA
  EC2  - security groups with sensitive ports open to 0.0.0.0/0 or ::/0

Fully testable without any real cloud account or cost using `moto`
(see selftest.py, built alongside this tool) -- moto intercepts boto3 calls
and simulates AWS services in-memory. When you DO set up a real AWS
account, this tool needs no code changes: just configure credentials
(aws configure, or env vars, or --profile) and point it at a region.

Usage (against real AWS, once you have an account):
    python3 cloud_security_monitor.py scan --services s3,iam,ec2 --region us-east-1
    python3 cloud_security_monitor.py scan --profile myprofile -o report.json

Usage (self-test against a simulated AWS account, no credentials needed):
    python3 selftest.py
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
    445: "SMB", 21: "FTP", 23: "Telnet", 1433: "MSSQL",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

STALE_KEY_DAYS = 90


# ---------------------------------------------------------------------------
# Session handling
# ---------------------------------------------------------------------------

def get_session(profile: str = None, region: str = None) -> boto3.Session:
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


# ---------------------------------------------------------------------------
# S3 checks
# ---------------------------------------------------------------------------

def check_s3(session: boto3.Session) -> list:
    findings = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, NoCredentialsError, EndpointConnectionError) as e:
        return [{"resource": "s3", "severity": "error",
                 "reasons": [f"Could not list buckets: {e}"]}]

    for bucket in buckets:
        name = bucket["Name"]
        reasons = []
        severity = "info"

        # Public access via ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri:
                    reasons.append(f"Bucket ACL grants '{grant['Permission']}' to AllUsers (fully public)")
                    severity = "critical"
                elif "AuthenticatedUsers" in uri:
                    reasons.append(f"Bucket ACL grants '{grant['Permission']}' to AuthenticatedUsers (any AWS account)")
                    severity = "high" if severity != "critical" else severity
        except ClientError as e:
            reasons.append(f"Could not read bucket ACL: {e.response['Error']['Code']}")

        # Public access via bucket policy
        try:
            policy_raw = s3.get_bucket_policy(Bucket=name)["Policy"]
            policy = json.loads(policy_raw)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal")
                effect = stmt.get("Effect")
                is_wildcard_principal = principal == "*" or principal == {"AWS": "*"}
                if effect == "Allow" and is_wildcard_principal and "Condition" not in stmt:
                    reasons.append("Bucket policy allows '*' principal with no condition (publicly accessible)")
                    severity = "critical"
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                reasons.append(f"Could not read bucket policy: {e.response['Error']['Code']}")

        # Default encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                reasons.append("No default encryption configured")
                if severity == "info":
                    severity = "medium"

        # Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                reasons.append("Versioning not enabled (no protection against accidental/malicious deletion)")
                if severity == "info":
                    severity = "low"
        except ClientError as e:
            reasons.append(f"Could not read versioning config: {e.response['Error']['Code']}")

        if reasons:
            findings.append({
                "resource": f"s3://{name}",
                "severity": severity,
                "reasons": reasons,
            })

    return findings


# ---------------------------------------------------------------------------
# IAM checks
# ---------------------------------------------------------------------------

def _policy_is_wildcard_admin(doc: dict) -> bool:
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action")
        resource = stmt.get("Resource")
        action_is_wild = action == "*" or (isinstance(action, list) and "*" in action)
        resource_is_wild = resource == "*" or (isinstance(resource, list) and "*" in resource)
        if action_is_wild and resource_is_wild:
            return True
    return False


def check_iam(session: boto3.Session) -> list:
    findings = []
    iam = session.client("iam")

    # Customer-managed policies with wildcard admin grants
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"]
                    )
                    doc = version["PolicyVersion"]["Document"]
                    if _policy_is_wildcard_admin(doc):
                        findings.append({
                            "resource": f"iam-policy://{policy['PolicyName']}",
                            "severity": "critical",
                            "reasons": ["Policy grants Action:'*' on Resource:'*' (full admin access)"],
                        })
                except ClientError as e:
                    findings.append({
                        "resource": f"iam-policy://{policy['PolicyName']}",
                        "severity": "error",
                        "reasons": [f"Could not read policy version: {e.response['Error']['Code']}"],
                    })
    except ClientError as e:
        findings.append({"resource": "iam-policies", "severity": "error",
                          "reasons": [f"Could not list policies: {e}"]})

    # Users: stale access keys + missing MFA
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                user_reasons = []
                severity = "info"

                try:
                    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                    now = datetime.now(timezone.utc)
                    for key in keys:
                        if key["Status"] != "Active":
                            continue
                        age_days = (now - key["CreateDate"]).days
                        if age_days > STALE_KEY_DAYS:
                            user_reasons.append(
                                f"Access key {key['AccessKeyId']} is {age_days} days old "
                                f"(exceeds {STALE_KEY_DAYS}-day rotation threshold)"
                            )
                            severity = "medium"
                except ClientError as e:
                    user_reasons.append(f"Could not list access keys: {e.response['Error']['Code']}")

                try:
                    mfa = iam.list_mfa_devices(UserName=username)["MFADevices"]
                    if not mfa:
                        user_reasons.append("No MFA device configured")
                        if severity == "info":
                            severity = "high"
                except ClientError as e:
                    user_reasons.append(f"Could not check MFA status: {e.response['Error']['Code']}")

                if user_reasons:
                    findings.append({
                        "resource": f"iam-user://{username}",
                        "severity": severity,
                        "reasons": user_reasons,
                    })
    except ClientError as e:
        findings.append({"resource": "iam-users", "severity": "error",
                          "reasons": [f"Could not list users: {e}"]})

    return findings


# ---------------------------------------------------------------------------
# EC2 security group checks
# ---------------------------------------------------------------------------

def check_ec2(session: boto3.Session) -> list:
    findings = []
    ec2 = session.client("ec2")

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except (ClientError, NoCredentialsError, EndpointConnectionError) as e:
        return [{"resource": "ec2-security-groups", "severity": "error",
                 "reasons": [f"Could not describe security groups: {e}"]}]

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        reasons = []
        severity = "info"

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            ip_protocol = perm.get("IpProtocol")

            open_ranges = []
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") in OPEN_CIDRS:
                    open_ranges.append(r["CidrIp"])
            for r in perm.get("Ipv6Ranges", []):
                if r.get("CidrIpv6") in OPEN_CIDRS:
                    open_ranges.append(r["CidrIpv6"])

            if not open_ranges:
                continue

            # All ports open (ip_protocol == "-1" means all protocols/ports)
            if ip_protocol == "-1" or (from_port == 0 and to_port == 65535):
                reasons.append(f"ALL ports open to {', '.join(open_ranges)}")
                severity = "critical"
                continue

            if from_port is None:
                continue

            for port, service_name in SENSITIVE_PORTS.items():
                if from_port <= port <= (to_port or from_port):
                    reasons.append(
                        f"Port {port} ({service_name}) open to {', '.join(open_ranges)}"
                    )
                    severity = "critical" if port in (22, 3389) else "high"

        if reasons:
            findings.append({
                "resource": f"ec2-sg://{sg_name} ({sg_id})",
                "severity": severity,
                "reasons": reasons,
            })

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

CHECKS = {
    "s3": check_s3,
    "iam": check_iam,
    "ec2": check_ec2,
}


def run_scan(session: boto3.Session, services: list, quiet: bool = False) -> dict:
    all_findings = []
    for service in services:
        check_fn = CHECKS.get(service)
        if check_fn is None:
            continue
        all_findings.extend(check_fn(session))

    result = {
        "timestamp": datetime.now().isoformat(),
        "services_checked": services,
        "findings_count": len([f for f in all_findings if f["severity"] != "error"]),
        "errors_count": len([f for f in all_findings if f["severity"] == "error"]),
        "findings": all_findings,
    }

    if not quiet:
        _print_report(result)

    return result


def _print_report(result: dict):
    print(f"[*] Services checked: {', '.join(result['services_checked'])}")
    print(f"[*] Findings: {result['findings_count']}  (errors: {result['errors_count']})")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "error": 5}
    for finding in sorted(result["findings"], key=lambda f: severity_rank.get(f["severity"], 9)):
        print(f"\n  [{finding['severity'].upper()}] {finding['resource']}")
        for reason in finding["reasons"]:
            print(f"      - {reason}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")

    parser = argparse.ArgumentParser(description="Cloud Security Monitoring Tool (Project #14)", parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan AWS account for misconfigurations", parents=[common])
    p_scan.add_argument("--services", default="s3,iam,ec2",
                         help="Comma-separated services to check (default: s3,iam,ec2)")
    p_scan.add_argument("--profile", help="AWS CLI profile name to use")
    p_scan.add_argument("--region", help="AWS region (defaults to your configured/default region)")
    p_scan.add_argument("-o", "--output", help="Write JSON report to this file")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            services = [s.strip().lower() for s in args.services.split(",") if s.strip()]
            unknown = [s for s in services if s not in CHECKS]
            if unknown:
                print(f"[!] Unknown service(s): {', '.join(unknown)}. Valid: {', '.join(CHECKS)}", file=sys.stderr)
                sys.exit(1)

            session = get_session(profile=args.profile, region=args.region)
            result = run_scan(session, services, quiet=args.quiet)

            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2, default=str))
                if not args.quiet:
                    print(f"\n[+] Report written to {args.output}")

            if result["findings_count"] > 0:
                sys.exit(2)

    except NoCredentialsError:
        print("[!] No AWS credentials found. Run 'aws configure' or set AWS_ACCESS_KEY_ID / "
              "AWS_SECRET_ACCESS_KEY environment variables, then try again.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
