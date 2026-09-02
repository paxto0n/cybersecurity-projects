#!/usr/bin/env python3
"""
Project #18 - Mobile Application Security Testing (Static APK Analysis)

Static analysis of Android APK files using androguard (pure Python, no
Android SDK/emulator/physical device required). Checks:

  - AndroidManifest.xml misconfigurations: debuggable=true, allowBackup=true,
    exported components (activities/services/receivers/providers) without
    a permission requirement, cleartext traffic allowed
  - Dangerous permissions (SMS, contacts, location, phone state, etc.)
  - Hardcoded secrets in decompiled strings -- reuses Project #17's DLP
    detection patterns (credit cards via Luhn, AWS keys, private keys,
    generic API tokens) against the APK's extracted string pool
  - Weak/deprecated cryptography usage signals (DES, MD5, ECB mode
    references in class/method names or strings)

Usage:
    python3 mobile_security_scanner.py scan -f app.apk
    python3 mobile_security_scanner.py scan -f app.apk -o report.json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

# androguard's default logging (via loguru) is extremely verbose at DEBUG
# level -- silence it down to WARNING so normal tool output isn't buried.
from loguru import logger as _androguard_logger
_androguard_logger.remove()
_androguard_logger.add(sys.stderr, level="WARNING")

from androguard.misc import AnalyzeAPK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.RECEIVE_SMS": "Intercept incoming SMS",
    "android.permission.READ_CONTACTS": "Read contacts",
    "android.permission.WRITE_CONTACTS": "Modify contacts",
    "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
    "android.permission.CAMERA": "Camera access",
    "android.permission.RECORD_AUDIO": "Microphone access",
    "android.permission.READ_PHONE_STATE": "Read phone identifiers/state",
    "android.permission.CALL_PHONE": "Place phone calls",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.GET_ACCOUNTS": "Read on-device account list",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write to shared storage",
    "android.permission.READ_EXTERNAL_STORAGE": "Read shared storage",
}

WEAK_CRYPTO_SIGNATURES = [
    (r"\bDES\b(?!CRIPT)", "DES (broken, trivially crackable)"),
    (r"\bMD5\b", "MD5 (broken hash, collision-prone)"),
    (r"\bECB\b", "AES/DES in ECB mode (pattern-leaking, no semantic security)"),
    (r"\bRC4\b", "RC4 (broken stream cipher)"),
    (r"TrustAllCerts|X509TrustManager.*\{\s*\}", "Custom TrustManager that may disable certificate validation"),
]

# ---------------------------------------------------------------------------
# Reused from Project #17's DLP patterns -- same detection logic, applied to
# an APK's decompiled string pool instead of files on disk
# ---------------------------------------------------------------------------

def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    end_part = value[-keep_end:] if keep_end > 0 else ""
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + end_part


CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
GENERIC_API_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"
)


def scan_strings_for_secrets(strings: list) -> list:
    findings = []
    for s in strings:
        if not isinstance(s, str) or len(s) > 2000:
            continue  # skip binary junk / oversized blobs

        for m in CREDIT_CARD_RE.finditer(s):
            digits_only = re.sub(r"[ -]", "", m.group())
            if 13 <= len(digits_only) <= 19 and _luhn_check(digits_only):
                findings.append({
                    "type": "hardcoded_credit_card", "severity": "critical",
                    "detail": _redact(digits_only),
                })

        for m in AWS_ACCESS_KEY_RE.finditer(s):
            findings.append({
                "type": "hardcoded_aws_key", "severity": "critical",
                "detail": _redact(m.group()),
            })

        for m in PRIVATE_KEY_RE.finditer(s):
            findings.append({
                "type": "hardcoded_private_key", "severity": "critical",
                "detail": m.group() + " [...]",
            })

        for m in GENERIC_API_KEY_RE.finditer(s):
            findings.append({
                "type": "hardcoded_api_key", "severity": "high",
                "detail": f"{m.group(1)}={_redact(m.group(2))}",
            })

    return findings


def scan_strings_for_weak_crypto(strings: list) -> list:
    findings = []
    seen = set()
    for s in strings:
        if not isinstance(s, str):
            continue
        for pattern, description in WEAK_CRYPTO_SIGNATURES:
            if re.search(pattern, s) and description not in seen:
                findings.append({
                    "type": "weak_cryptography", "severity": "medium",
                    "detail": description,
                })
                seen.add(description)
    return findings


# ---------------------------------------------------------------------------
# Manifest analysis
# ---------------------------------------------------------------------------

def _get_exported_components(apk) -> list:
    """
    Walks the raw manifest XML tree to find exported components. A
    component is considered exported if android:exported="true" is
    explicit, OR (for activities/receivers with an intent-filter and no
    explicit exported attribute on API < 31 behavior) it's implicitly
    exported -- we only flag the EXPLICIT case here to avoid false
    positives from misjudging implicit-export edge cases across API
    levels; that nuance is a known scope limitation, noted below.
    """
    findings = []
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        return findings

    component_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
    for tag in component_tags:
        for element in manifest.iter(tag):
            exported = element.get(f"{ANDROID_NS}exported")
            name = element.get(f"{ANDROID_NS}name", "(unnamed)")
            permission = element.get(f"{ANDROID_NS}permission")

            if exported == "true":
                severity = "high" if permission else "critical"
                detail = f"{tag} '{name}' is exported"
                if not permission:
                    detail += " with NO permission requirement (any app can interact with it)"
                else:
                    detail += f" but requires permission '{permission}'"
                findings.append({"type": f"exported_{tag}", "severity": severity, "detail": detail})

    return findings


def analyze_manifest(apk) -> list:
    findings = []

    if apk.get_attribute_value("application", "debuggable") == "true":
        findings.append({
            "type": "debuggable", "severity": "critical",
            "detail": "android:debuggable=\"true\" -- app can be debugged/attached to in production, "
                      "exposing internals and allowing runtime manipulation",
        })

    if apk.get_attribute_value("application", "allowBackup") in (None, "true"):
        # AndroidManifest default for allowBackup IS true when unspecified
        findings.append({
            "type": "backup_allowed", "severity": "medium",
            "detail": "android:allowBackup is true (or unspecified, which defaults to true) -- "
                      "app data can be extracted via 'adb backup' without root",
        })

    uses_cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
    if uses_cleartext in (None, "true"):
        findings.append({
            "type": "cleartext_traffic", "severity": "high",
            "detail": "usesCleartextTraffic is true (or unspecified, defaulting to true on API < 28) -- "
                      "app may transmit data over unencrypted HTTP",
        })

    dangerous = [p for p in apk.get_permissions() if p in DANGEROUS_PERMISSIONS]
    for p in dangerous:
        findings.append({
            "type": "dangerous_permission", "severity": "low",
            "detail": f"{p} -- {DANGEROUS_PERMISSIONS[p]}",
        })

    findings.extend(_get_exported_components(apk))

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def scan_apk(apk_path: str, quiet: bool = False) -> dict:
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    # AnalyzeAPK gives (apk, dex_list, analysis) -- the manifest data lives
    # on `apk`, but string extraction requires the DEX objects (`apk` alone
    # has no get_strings() method in this androguard version; that gap was
    # caught and fixed during testing -- see the note in the changelog).
    apk, dex_list, _analysis = AnalyzeAPK(str(path))

    manifest_findings = analyze_manifest(apk)

    strings = []
    for dex in dex_list:
        try:
            strings.extend(dex.get_strings())
        except Exception:
            continue
    secret_findings = scan_strings_for_secrets(strings)
    crypto_findings = scan_strings_for_weak_crypto(strings)

    all_findings = manifest_findings + secret_findings + crypto_findings

    result = {
        "apk_path": str(path),
        "package": apk.get_package(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "timestamp": datetime.now().isoformat(),
        "permissions_count": len(apk.get_permissions()),
        "findings_count": len(all_findings),
        "findings": all_findings,
    }

    if not quiet:
        _print_report(result)

    return result


def _print_report(result: dict):
    print(f"[*] Package: {result['package']}")
    print(f"[*] Min SDK: {result['min_sdk']}  Target SDK: {result['target_sdk']}")
    print(f"[*] Permissions requested: {result['permissions_count']}")
    print(f"[*] Findings: {result['findings_count']}")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for finding in sorted(result["findings"], key=lambda f: severity_rank.get(f["severity"], 9)):
        print(f"\n  [{finding['severity'].upper()}] {finding['type']}")
        print(f"      {finding['detail']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")

    parser = argparse.ArgumentParser(description="Mobile Application Security Testing Tool (Project #18)", parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Static analysis of an APK file", parents=[common])
    p_scan.add_argument("-f", "--file", required=True, help="Path to the .apk file to analyze")
    p_scan.add_argument("-o", "--output", help="Write JSON report to this file")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            result = scan_apk(args.file, quiet=args.quiet)
            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2))
                if not args.quiet:
                    print(f"\n[+] Report written to {args.output}")
            if result["findings_count"] > 0:
                sys.exit(2)

    except FileNotFoundError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
