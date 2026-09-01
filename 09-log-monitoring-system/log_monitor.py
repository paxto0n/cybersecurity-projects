import subprocess
import sys
import re
import time
from datetime import datetime
from collections import defaultdict

SUSPICIOUS_PATTERNS = [
    (re.compile(r"Failed password for.*from\s+(\S+)"), "high", "Failed SSH login"),
    (re.compile(r"Failed password for invalid user.*from\s+(\S+)"), "high", "Failed login for non-existent user"),
    (re.compile(r"Invalid user\s+\S+\s+from\s+(\S+)"), "medium", "Login attempt for invalid username"),
    (re.compile(r"authentication failure.*rhost=(\S+)"), "medium", "PAM authentication failure"),
    (re.compile(r"sudo:.*COMMAND=.*(?:passwd|useradd|usermod|visudo)"), "medium", "Sudo used for a sensitive account-management command"),
    (re.compile(r"pam_unix\(sudo:auth\): authentication failure"), "high", "Failed sudo authentication"),
    (re.compile(r"session opened for user root"), "low", "Root session opened"),
    (re.compile(r"Accepted (?:password|publickey) for (\S+) from\s+(\S+)"), "info", "Successful SSH login"),
]

# Brute-force detection thresholds — same pattern as the Project #1
# port scan detector: N events from the same source within a time window.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

# Patterns that count toward brute-force tracking (failed auth events only)
FAILURE_LABELS = {
    "Failed SSH login",
    "Failed login for non-existent user",
    "PAM authentication failure",
    "Failed sudo authentication",
}


def classify_line(line):
    for pattern, severity, label in SUSPICIOUS_PATTERNS:
        match = pattern.search(line)
        if match:
            ip = None
            if match.groups():
                candidate = match.groups()[-1]
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
                    ip = candidate
            return severity, label, ip
    return None


def stream_journal():
    cmd = ["journalctl", "-f", "-n", "0", "--no-pager", "-o", "short-iso"]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    try:
        for line in process.stdout:
            yield line.rstrip("\n")
    finally:
        process.terminate()


def format_alert(severity, label, ip, line):
    timestamp = datetime.now().strftime("%H:%M:%S")
    ip_str = f" from {ip}" if ip else ""
    return f"[{timestamp}] [{severity.upper()}] {label}{ip_str}\n    {line}"


class BruteForceTracker:
    """
    Tracks failed-auth timestamps per source IP. Old entries outside the
    time window are pruned on each check, so memory doesn't grow forever
    and the threshold is always evaluated against a genuinely recent window.
    """
    def __init__(self, threshold=BRUTE_FORCE_THRESHOLD, window=BRUTE_FORCE_WINDOW_SECONDS):
        self.threshold = threshold
        self.window = window
        self.attempts = defaultdict(list)
        self.already_alerted = set()

    def record_failure(self, ip):
        if not ip:
            return False

        now = time.time()
        self.attempts[ip].append(now)
        self.attempts[ip] = [t for t in self.attempts[ip] if now - t <= self.window]

        if len(self.attempts[ip]) >= self.threshold:
            if ip not in self.already_alerted:
                self.already_alerted.add(ip)
                return True
            return False
        else:
            # attempts dropped back below threshold (window rolled past them) —
            # allow a fresh alert if it crosses the threshold again later
            self.already_alerted.discard(ip)
            return False

    def count_for(self, ip):
        return len(self.attempts.get(ip, []))


def monitor():
    print("\nLog Monitoring System — watching live journald output")
    print(f"Brute-force threshold: {BRUTE_FORCE_THRESHOLD} failures in {BRUTE_FORCE_WINDOW_SECONDS}s")
    print("Press Ctrl+C to stop.\n")

    tracker = BruteForceTracker()

    try:
        for line in stream_journal():
            result = classify_line(line)
            if not result:
                continue

            severity, label, ip = result
            print(format_alert(severity, label, ip, line))

            if label in FAILURE_LABELS and ip:
                is_brute_force = tracker.record_failure(ip)
                if is_brute_force:
                    count = tracker.count_for(ip)
                    print(f"\n{'!'*60}")
                    print(f"BRUTE-FORCE ALERT: {count} failed auth attempts from {ip} "
                          f"in the last {BRUTE_FORCE_WINDOW_SECONDS}s")
                    print(f"{'!'*60}\n")

    except KeyboardInterrupt:
        print("\n\nStopped monitoring.")


if __name__ == "__main__":
    monitor()
