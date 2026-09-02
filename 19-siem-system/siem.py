#!/usr/bin/env python3
"""
Project #19 - SIEM System (Security Information and Event Management)

Centralizes and correlates security events from across this project
portfolio. Two ingestion paths:

  1. JSON reports -- Projects #13, #14, #15, #17, and #18 all independently
     converged on the same report schema:
         {"findings_count": N, "findings": [{"severity": ..., ...}, ...]}
     This tool ingests that schema directly, normalizing each finding into
     a unified Event record tagged with its source tool. This is a real
     integration point across the portfolio, not a simulated one -- point
     it at an actual report.json from any of those tools and it works.

  2. Generic text logs -- for simpler "TIMESTAMP | ... " style logs (the
     pattern used by Project #13's usb_alerts.log, #16's access_log.txt,
     etc.), via a configurable regex.

Events are normalized into a common schema (timestamp, source, severity,
event_type, message) and stored in SQLite for querying. A basic
correlation rule flags "bursts" -- multiple high-severity events from the
same source within a short time window, which is often more actionable
than any single event alone.

Usage:
    python3 siem.py ingest-json -f report.json -s dlp_scanner
    python3 siem.py ingest-log -f alerts.log -s usb_detector
    python3 siem.py query --severity critical --source dlp_scanner
    python3 siem.py stats
    python3 siem.py correlate --window-minutes 10 --threshold 3
    python3 siem.py serve --port 5070
"""

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, g

DB_DEFAULT = "siem.db"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Generic log line pattern matching this portfolio's common alert-log style:
# "2026-09-02T10:00:00 | SOME_LABEL | rest of message"
DEFAULT_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s*\|\s*(?P<label>[A-Z_]+)\s*\|\s*(?P<message>.*)$"
)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            raw TEXT,
            ingested_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    conn.commit()
    conn.close()


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def insert_event(conn: sqlite3.Connection, timestamp: str, source: str, severity: str,
                  event_type: str, message: str, raw: str = None):
    conn.execute(
        "INSERT INTO events (timestamp, source, severity, event_type, message, raw, ingested_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, source, severity.lower(), event_type, message, raw, datetime.now().isoformat())
    )


# ---------------------------------------------------------------------------
# Ingestion: JSON reports (shared schema across #13/#14/#15/#17/#18)
# ---------------------------------------------------------------------------

def ingest_json_report(db_path: str, report_path: str, source: str) -> int:
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")

    data = json.loads(path.read_text())
    findings = data.get("findings", [])
    report_timestamp = data.get("timestamp", datetime.now().isoformat())

    conn = get_connection(db_path)
    count = 0
    for finding in findings:
        severity = finding.get("severity", "info")
        # Different tools name their "what happened" field differently --
        # normalize across the schema variations actually present in this
        # portfolio's tools rather than assuming one canonical field name.
        event_type = (
            finding.get("type") or finding.get("technique") or
            finding.get("resource", "").split("://")[0] or "unknown"
        )
        message = (
            finding.get("detail") or finding.get("reasons") or
            finding.get("evidence") or finding.get("redacted") or
            finding.get("reason") or str(finding)
        )
        if isinstance(message, list):
            message = "; ".join(str(m) for m in message)

        insert_event(
            conn, timestamp=report_timestamp, source=source, severity=severity,
            event_type=str(event_type), message=str(message), raw=json.dumps(finding)
        )
        count += 1

    conn.commit()
    conn.close()
    return count


# ---------------------------------------------------------------------------
# Ingestion: generic "TIMESTAMP | LABEL | message" text logs
# ---------------------------------------------------------------------------

def _infer_severity_from_label(label: str) -> str:
    label = label.upper()
    if label in ("CRITICAL", "DENIED", "ALERT"):
        return "critical" if label != "DENIED" else "medium"
    if label in ("HIGH", "WARNING"):
        return "high"
    if label in ("MEDIUM",):
        return "medium"
    if label in ("LOW", "INFO", "ALLOWED"):
        return "low"
    return "info"


def ingest_text_log(db_path: str, log_path: str, source: str, pattern: re.Pattern = None) -> int:
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log not found: {log_path}")

    pattern = pattern or DEFAULT_LOG_PATTERN
    conn = get_connection(db_path)
    count = 0
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        match = pattern.match(line)
        if not match:
            continue
        groups = match.groupdict()
        severity = _infer_severity_from_label(groups.get("label", ""))
        insert_event(
            conn, timestamp=groups.get("timestamp", datetime.now().isoformat()),
            source=source, severity=severity, event_type=groups.get("label", "log_line"),
            message=groups.get("message", line), raw=line
        )
        count += 1

    conn.commit()
    conn.close()
    return count


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------

def query_events(db_path: str, severity: str = None, source: str = None,
                  limit: int = 100) -> list:
    conn = get_connection(db_path)
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity.lower())
    if source:
        query += " AND source = ?"
        params.append(source)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats(db_path: str) -> dict:
    conn = get_connection(db_path)
    total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]

    by_severity = {r["severity"]: r["c"] for r in conn.execute(
        "SELECT severity, COUNT(*) as c FROM events GROUP BY severity"
    ).fetchall()}

    by_source = {r["source"]: r["c"] for r in conn.execute(
        "SELECT source, COUNT(*) as c FROM events GROUP BY source"
    ).fetchall()}

    conn.close()
    return {"total_events": total, "by_severity": by_severity, "by_source": by_source}


# ---------------------------------------------------------------------------
# Correlation: burst detection
# ---------------------------------------------------------------------------

def _parse_timestamp(ts: str):
    """Best-effort ISO timestamp parsing; tolerant of the slight format
    variations across this portfolio's different tools."""
    for fmt in (None, "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            if fmt is None:
                return datetime.fromisoformat(ts)
            return datetime.strptime(ts, fmt)
        except (ValueError, TypeError):
            continue
    return None


def correlate_bursts(db_path: str, window_minutes: int = 10, threshold: int = 3) -> list:
    """
    Flags sources that produced >= threshold high/critical-severity events
    within any window_minutes-wide sliding window. A burst is often a
    stronger signal than any single high-severity event -- e.g. a scanner
    hammering many endpoints, or a single compromised account triggering
    repeated denials.
    """
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM events WHERE severity IN ('critical', 'high') ORDER BY source, timestamp"
    ).fetchall()
    conn.close()

    events_by_source = {}
    for row in rows:
        ts = _parse_timestamp(row["timestamp"])
        if ts is None:
            continue
        events_by_source.setdefault(row["source"], []).append((ts, dict(row)))

    correlations = []
    window = timedelta(minutes=window_minutes)
    for source, events in events_by_source.items():
        events.sort(key=lambda e: e[0])
        for i in range(len(events)):
            window_events = [e for e in events[i:] if e[0] - events[i][0] <= window]
            if len(window_events) >= threshold:
                correlations.append({
                    "source": source,
                    "window_start": events[i][0].isoformat(),
                    "window_minutes": window_minutes,
                    "event_count": len(window_events),
                    "severities": [e[1]["severity"] for e in window_events],
                    "event_ids": [e[1]["id"] for e in window_events],
                })
                break  # one flagged burst per source is enough signal

    return correlations


# ---------------------------------------------------------------------------
# Flask dashboard
# ---------------------------------------------------------------------------

def create_app(db_path: str = DB_DEFAULT) -> Flask:
    app = Flask(__name__)

    @app.route("/events")
    def events_endpoint():
        severity = request.args.get("severity")
        source = request.args.get("source")
        limit = int(request.args.get("limit", 100))
        results = query_events(db_path, severity=severity, source=source, limit=limit)
        return jsonify({"count": len(results), "events": results})

    @app.route("/stats")
    def stats_endpoint():
        return jsonify(get_stats(db_path))

    @app.route("/correlations")
    def correlations_endpoint():
        window = int(request.args.get("window_minutes", 10))
        threshold = int(request.args.get("threshold", 3))
        return jsonify({"correlations": correlate_bursts(db_path, window, threshold)})

    return app


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SIEM System (Project #19)")
    parser.add_argument("--db", default=DB_DEFAULT, help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_json = sub.add_parser("ingest-json", help="Ingest a JSON report (shared schema from #13/#14/#15/#17/#18)")
    p_json.add_argument("-f", "--file", required=True)
    p_json.add_argument("-s", "--source", required=True, help="Label for which tool produced this report")

    p_log = sub.add_parser("ingest-log", help="Ingest a generic 'TIMESTAMP | LABEL | message' text log")
    p_log.add_argument("-f", "--file", required=True)
    p_log.add_argument("-s", "--source", required=True)

    p_query = sub.add_parser("query", help="Query stored events")
    p_query.add_argument("--severity")
    p_query.add_argument("--source")
    p_query.add_argument("--limit", type=int, default=100)

    sub.add_parser("stats", help="Show event statistics")

    p_corr = sub.add_parser("correlate", help="Detect high-severity event bursts")
    p_corr.add_argument("--window-minutes", type=int, default=10)
    p_corr.add_argument("--threshold", type=int, default=3)

    p_serve = sub.add_parser("serve", help="Run the Flask dashboard API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=5070)

    args = parser.parse_args()
    init_db(args.db)

    try:
        if args.command == "ingest-json":
            count = ingest_json_report(args.db, args.file, args.source)
            print(f"[+] Ingested {count} events from {args.file} (source: {args.source})")

        elif args.command == "ingest-log":
            count = ingest_text_log(args.db, args.file, args.source)
            print(f"[+] Ingested {count} events from {args.file} (source: {args.source})")

        elif args.command == "query":
            results = query_events(args.db, severity=args.severity, source=args.source, limit=args.limit)
            print(f"[*] {len(results)} event(s)")
            for e in results:
                print(f"  [{e['severity'].upper()}] {e['timestamp']} | {e['source']} | {e['event_type']} | {e['message'][:100]}")

        elif args.command == "stats":
            stats = get_stats(args.db)
            print(f"[*] Total events: {stats['total_events']}")
            print(f"[*] By severity: {stats['by_severity']}")
            print(f"[*] By source: {stats['by_source']}")

        elif args.command == "correlate":
            correlations = correlate_bursts(args.db, args.window_minutes, args.threshold)
            print(f"[*] {len(correlations)} correlated burst(s) found")
            for c in correlations:
                print(f"  [BURST] {c['source']}: {c['event_count']} high/critical events "
                      f"within {c['window_minutes']}min starting {c['window_start']}")

        elif args.command == "serve":
            app = create_app(args.db)
            app.run(host=args.host, port=args.port)

    except FileNotFoundError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Error: Invalid JSON in report file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
