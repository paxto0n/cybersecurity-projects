#!/usr/bin/env python3
"""
Project #17 - Data Leakage Prevention (DLP) Tool

Scans files/directories for sensitive data patterns commonly involved in
data leaks: credit card numbers, SSNs, AWS access keys, private key
material, and generic API tokens.

Key design choice: credit card matches are validated with the Luhn
algorithm before being reported. A naive 16-digit regex flags huge numbers
of false positives (order IDs, phone numbers, random digit strings); Luhn
validation is the actual checksum credit card numbers must satisfy, so it
meaningfully cuts noise -- this is standard practice in real DLP tooling,
not just an academic flourish.

Findings are always REDACTED in output -- the actual sensitive value is
never printed in full, only a masked preview, so running this tool and
sharing its report doesn't itself leak anything.

Usage:
    python3 dlp_scanner.py scan -p /path/to/scan
    python3 dlp_scanner.py scan -p /path/to/scan -o report.json
    python3 dlp_scanner.py watch -p /path/to/watch
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

MAX_FILE_SIZE_MB = 20
TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini",
    ".cfg", ".conf", ".env", ".py", ".js", ".java", ".c", ".cpp", ".h",
    ".sh", ".md", ".sql", ".pem", ".key", ".properties",
}

# ---------------------------------------------------------------------------
# Luhn algorithm -- the actual checksum credit card numbers must satisfy
# ---------------------------------------------------------------------------

def luhn_check(number: str) -> bool:
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


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Each pattern: (name, compiled regex, severity, needs_luhn_validation)
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_KEY_RE = re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
GENERIC_API_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _redact(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Masks a sensitive value for safe display -- never show the full value.
    NOTE: value[-0:] in Python equals value[0:] (the whole string), since
    -0 == 0 -- so keep_end=0 must be handled explicitly, not via a naive
    negative-index slice, or this silently stops redacting anything."""
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    end_part = value[-keep_end:] if keep_end > 0 else ""
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + end_part


def find_credit_cards(text: str) -> list:
    findings = []
    for match in CREDIT_CARD_RE.finditer(text):
        raw = match.group()
        digits_only = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits_only) <= 19 and luhn_check(digits_only):
            findings.append({
                "type": "credit_card",
                "severity": "critical",
                "redacted": _redact(digits_only),
                "position": match.start(),
            })
    return findings


def find_ssns(text: str) -> list:
    return [{
        "type": "ssn",
        "severity": "critical",
        "redacted": "***-**-" + m.group()[-4:],
        "position": m.start(),
    } for m in SSN_RE.finditer(text)]


def find_aws_keys(text: str) -> list:
    findings = []
    for m in AWS_ACCESS_KEY_RE.finditer(text):
        findings.append({
            "type": "aws_access_key",
            "severity": "critical",
            "redacted": _redact(m.group()),
            "position": m.start(),
        })
    for m in AWS_SECRET_KEY_RE.finditer(text):
        findings.append({
            "type": "aws_secret_key",
            "severity": "critical",
            "redacted": _redact(m.group(1)),
            "position": m.start(),
        })
    return findings


def find_private_keys(text: str) -> list:
    return [{
        "type": "private_key",
        "severity": "critical",
        "redacted": m.group() + " [...] (key body omitted)",
        "position": m.start(),
    } for m in PRIVATE_KEY_RE.finditer(text)]


def find_generic_api_keys(text: str) -> list:
    findings = []
    for m in GENERIC_API_KEY_RE.finditer(text):
        findings.append({
            "type": "api_key_or_token",
            "severity": "high",
            "redacted": f"{m.group(1)}={_redact(m.group(2))}",
            "position": m.start(),
        })
    return findings


def find_emails(text: str) -> list:
    # Lower severity -- emails alone are much less sensitive than the above,
    # but still worth flagging (e.g. a hardcoded list of customer emails)
    findings = []
    for m in EMAIL_RE.finditer(text):
        local, _, domain = m.group().partition("@")
        findings.append({
            "type": "email",
            "severity": "low",
            "redacted": _redact(local, keep_start=2, keep_end=0) + "@" + domain,
            "position": m.start(),
        })
    return findings


DETECTORS = [
    find_credit_cards,
    find_ssns,
    find_aws_keys,
    find_private_keys,
    find_generic_api_keys,
    find_emails,
]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_text(text: str) -> list:
    findings = []
    for detector in DETECTORS:
        findings.extend(detector(text))
    return findings


def scan_file(file_path: Path) -> list:
    try:
        if file_path.suffix.lower() not in TEXT_EXTENSIONS:
            return []
        if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            return []
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []

    findings = scan_text(text)
    for f in findings:
        f["file"] = str(file_path)
        # Convert character position to an approximate line number for readability
        f["line"] = text.count("\n", 0, f["position"]) + 1
        del f["position"]
    return findings


def scan_directory(root_path: str, quiet: bool = False) -> dict:
    root = Path(root_path)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    all_findings = []
    files_scanned = 0

    if root.is_file():
        files_scanned = 1
        all_findings.extend(scan_file(root))
    else:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                files_scanned += 1
                all_findings.extend(scan_file(path))

    result = {
        "scanned_path": str(root),
        "timestamp": datetime.now().isoformat(),
        "files_scanned": files_scanned,
        "findings_count": len(all_findings),
        "findings": all_findings,
    }

    if not quiet:
        _print_report(result)

    return result


def _print_report(result: dict):
    print(f"[*] Scanned: {result['scanned_path']}")
    print(f"[*] Files scanned: {result['files_scanned']}")
    print(f"[*] Findings: {result['findings_count']}")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for finding in sorted(result["findings"], key=lambda f: severity_rank.get(f["severity"], 9)):
        print(f"\n  [{finding['severity'].upper()}] {finding['type']} in {finding['file']}:{finding['line']}")
        print(f"      {finding['redacted']}")


# ---------------------------------------------------------------------------
# Watch mode (real-time monitoring of newly created/modified files)
# ---------------------------------------------------------------------------

def run_watch(watch_path: str, quiet: bool = False):
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("[!] watchdog not installed. Install it with:")
        print("    pip install watchdog --break-system-packages")
        sys.exit(1)

    class DLPHandler(FileSystemEventHandler):
        def _handle(self, path_str):
            path = Path(path_str)
            if not path.is_file():
                return
            findings = scan_file(path)
            if findings:
                print(f"\n[!] Sensitive data detected in {path}:")
                for f in findings:
                    print(f"    [{f['severity'].upper()}] {f['type']}: {f['redacted']} (line {f['line']})")

        def on_created(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

    if not quiet:
        print(f"[*] Watching {watch_path} for sensitive data in new/modified files... (Ctrl+C to stop)")

    observer = Observer()
    observer.schedule(DLPHandler(), watch_path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Stopped.")
    observer.join()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")

    parser = argparse.ArgumentParser(description="Data Leakage Prevention Tool (Project #17)", parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a file or directory for sensitive data", parents=[common])
    p_scan.add_argument("-p", "--path", required=True, help="File or directory path to scan")
    p_scan.add_argument("-o", "--output", help="Write JSON report to this file")

    p_watch = sub.add_parser("watch", help="Watch a directory in real time for sensitive data", parents=[common])
    p_watch.add_argument("-p", "--path", required=True, help="Directory path to watch")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            result = scan_directory(args.path, quiet=args.quiet)
            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2))
                if not args.quiet:
                    print(f"\n[+] Report written to {args.output}")
            if result["findings_count"] > 0:
                sys.exit(2)

        elif args.command == "watch":
            run_watch(args.path, quiet=args.quiet)

    except FileNotFoundError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
