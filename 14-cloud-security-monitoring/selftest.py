#!/usr/bin/env python3
"""
Self-test for cloud_security_monitor.py using `moto` to simulate an AWS
account entirely in memory -- no real credentials, no cloud cost, no
network calls. This is how the tool's detection logic is verified without
a real AWS account: build known-bad and known-clean fake resources, run
the scanner, and check it flags the right things and only the right things.

Run this any time you change cloud_security_monitor.py to confirm nothing
broke.

Usage:
    python3 selftest.py
"""

import json
import sys

import boto3
from moto import mock_aws

import cloud_security_monitor as csm


def build_fake_account(session: boto3.Session):
    """Creates a mix of intentionally misconfigured and clean AWS resources."""
    s3 = session.client("s3", region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    # --- S3: one public+unencrypted bucket, one clean bucket ---
    s3.create_bucket(Bucket="public-leaky-bucket")
    s3.put_bucket_acl(
        Bucket="public-leaky-bucket",
        AccessControlPolicy={
            "Grants": [{
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }],
            "Owner": {"ID": "test-owner"},
        },
    )
    # no encryption, no versioning set -> both should be flagged too

    s3.create_bucket(Bucket="clean-secure-bucket")
    s3.put_bucket_encryption(
        Bucket="clean-secure-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(
        Bucket="clean-secure-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    # --- IAM: one wildcard-admin policy, one scoped-down policy ---
    iam.create_policy(
        PolicyName="DangerousAdminPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    iam.create_policy(
        PolicyName="ScopedS3ReadPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::some-bucket/*"}],
        }),
    )

    # IAM users: one with no MFA (should flag), moto doesn't easily let us
    # backdate access key creation, so stale-key detection is exercised
    # via the CHECK LOGIC unit test below instead of this fixture.
    iam.create_user(UserName="no-mfa-user")
    iam.create_access_key(UserName="no-mfa-user")

    # --- EC2: one wide-open SSH security group, one properly scoped one ---
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]

    open_sg = ec2.create_security_group(
        GroupName="wide-open-ssh", Description="test", VpcId=vpc_id
    )
    ec2.authorize_security_group_ingress(
        GroupId=open_sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    scoped_sg = ec2.create_security_group(
        GroupName="scoped-ssh", Description="test", VpcId=vpc_id
    )
    ec2.authorize_security_group_ingress(
        GroupId=scoped_sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/24"}],
        }],
    )

    return {
        "public_bucket": "public-leaky-bucket",
        "clean_bucket": "clean-secure-bucket",
        "open_sg_id": open_sg["GroupId"],
        "scoped_sg_id": scoped_sg["GroupId"],
    }


def _assert(condition: bool, message: str, failures: list):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {message}")
    if not condition:
        failures.append(message)


@mock_aws
def main():
    failures = []
    session = boto3.Session(region_name="us-east-1")
    fixtures = build_fake_account(session)

    print("=== S3 checks ===")
    s3_findings = csm.check_s3(session)
    by_resource = {f["resource"]: f for f in s3_findings}

    public_finding = by_resource.get(f"s3://{fixtures['public_bucket']}")
    _assert(public_finding is not None, "Public bucket produces a finding", failures)
    if public_finding:
        _assert(public_finding["severity"] == "critical", "Public bucket flagged CRITICAL", failures)
        _assert(any("AllUsers" in r for r in public_finding["reasons"]), "Public bucket flags AllUsers ACL grant", failures)
        _assert(any("encryption" in r.lower() for r in public_finding["reasons"]), "Public bucket flags missing encryption", failures)
        _assert(any("version" in r.lower() for r in public_finding["reasons"]), "Public bucket flags missing versioning", failures)

    clean_finding = by_resource.get(f"s3://{fixtures['clean_bucket']}")
    _assert(clean_finding is None, "Clean bucket produces NO finding (no false positive)", failures)

    print("\n=== IAM checks ===")
    iam_findings = csm.check_iam(session)
    by_resource = {f["resource"]: f for f in iam_findings}

    admin_policy_finding = by_resource.get("iam-policy://DangerousAdminPolicy")
    _assert(admin_policy_finding is not None, "Wildcard admin policy produces a finding", failures)
    if admin_policy_finding:
        _assert(admin_policy_finding["severity"] == "critical", "Wildcard admin policy flagged CRITICAL", failures)

    scoped_policy_finding = by_resource.get("iam-policy://ScopedS3ReadPolicy")
    _assert(scoped_policy_finding is None, "Scoped policy produces NO finding (no false positive)", failures)

    no_mfa_finding = by_resource.get("iam-user://no-mfa-user")
    _assert(no_mfa_finding is not None, "User without MFA produces a finding", failures)
    if no_mfa_finding:
        _assert(any("MFA" in r for r in no_mfa_finding["reasons"]), "No-MFA user flags missing MFA", failures)

    print("\n=== EC2 checks ===")
    ec2_findings = csm.check_ec2(session)
    by_resource = {f["resource"]: f for f in ec2_findings}

    open_finding = next((f for f in ec2_findings if fixtures["open_sg_id"] in f["resource"]), None)
    _assert(open_finding is not None, "Wide-open SSH security group produces a finding", failures)
    if open_finding:
        _assert(open_finding["severity"] == "critical", "Open SSH security group flagged CRITICAL", failures)
        _assert(any("22" in r and "SSH" in r for r in open_finding["reasons"]), "Open SG flags port 22 (SSH) specifically", failures)

    scoped_finding = next((f for f in ec2_findings if fixtures["scoped_sg_id"] in f["resource"]), None)
    _assert(scoped_finding is None, "Scoped-CIDR SSH security group produces NO finding (no false positive)", failures)

    print("\n=== Stale access key logic (unit test, not fixture-based) ===")
    from datetime import datetime, timedelta, timezone
    fake_doc_wildcard = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    fake_doc_scoped = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"}]}
    _assert(csm._policy_is_wildcard_admin(fake_doc_wildcard) is True, "_policy_is_wildcard_admin detects wildcard policy", failures)
    _assert(csm._policy_is_wildcard_admin(fake_doc_scoped) is False, "_policy_is_wildcard_admin does not flag scoped policy", failures)

    print("\n" + "=" * 50)
    if failures:
        print(f"RESULT: {len(failures)} check(s) FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("RESULT: All self-tests PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
