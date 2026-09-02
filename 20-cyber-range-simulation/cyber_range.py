#!/usr/bin/env python3
"""
Project #20 - Cyber Range Simulation Environment

Orchestrates intentionally-vulnerable Docker containers as isolated
practice targets, each paired with the specific tool(s) already built in
this project portfolio. This is the intended capstone: a place to
actually point your own tools at something real.

Scenarios:
  sqli-lab       - vulnerable Flask+SQLite login/search app (built from
                   embedded source, same vulnerability pattern validated
                   in Project #15's test harness) -- practice with
                   Project #15 (SQL Injection Detector) and #10 (webapp scanner)
  weak-ssh-lab   - SSH server with a weak/default password and a flag file
                   only readable after login -- practice with Project #5
                   (password strength reasoning) and manual/hydra brute-forcing
  port-scan-lab  - multi-port fake-service target -- practice with
                   Project #4 (Port Scanner) and #7 (Vulnerability Scanner)

Each scenario has a real, checkable "flag" -- exploiting the
vulnerability is how you confirm you actually solved it, not just ran a
tool and read output.

IMPORTANT: Docker container lifecycle (build/run/stop) requires a real
Docker daemon, which is not available in the environment this tool was
developed and tested in. The Docker orchestration code is written against
the standard `docker` CLI (via subprocess) and its command construction
is unit-tested with mocked subprocess calls, but has NOT been verified
against a live Docker daemon. Test `up`/`down`/`status` on your Kali VM
(which has real Docker, already used for Juice Shop in earlier projects)
and report back if anything needs adjusting.

The sqli-lab scenario's flag-check logic IS fully verified end-to-end
against a real running instance of its target app (see selftest.py) --
that part needs no further verification.

Usage:
    python3 cyber_range.py list
    python3 cyber_range.py up sqli-lab
    python3 cyber_range.py info sqli-lab
    python3 cyber_range.py check-flag sqli-lab --host 127.0.0.1 --port 5090
    python3 cyber_range.py down sqli-lab
    python3 cyber_range.py status
"""

import argparse
import socket
import subprocess
import sys
import time

import requests

RANGE_PREFIX = "cyber-range-"
RANGE_NETWORK = "cyber-range-net"


# ---------------------------------------------------------------------------
# Scenario: sqli-lab
# ---------------------------------------------------------------------------

SQLI_LAB_APP_SOURCE = '''
from flask import Flask, request, jsonify
import sqlite3, os

app = Flask(__name__)
DB_PATH = "/tmp/sqli_lab.db"

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES (\\'admin\\', \\'FLAG{sqli_bypass_successful}\\')")
    conn.commit()
    conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT password FROM users WHERE username = \\'{username}\\' AND password = \\'{password}\\'"
    try:
        cur.execute(query)
        row = cur.fetchone()
        conn.close()
        if row:
            return jsonify({"authenticated": True, "flag": row[0]})
        return jsonify({"authenticated": False})
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": f"SQLite error: {str(e)}"}), 500

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
'''

SQLI_LAB_DOCKERFILE = f"""FROM python:3.11-slim
RUN pip install flask
WORKDIR /app
COPY app.py .
EXPOSE 5000
CMD ["python3", "app.py"]
"""


def check_flag_sqli_lab(host: str, port: int) -> tuple:
    """
    Attempts the same boolean-based auth bypass validated in Project #15's
    test harness. Success means the login endpoint returns the flag.
    """
    url = f"http://{host}:{port}/login"
    payload = {"username": "' OR '1'='1'--", "password": "anything"}
    try:
        resp = requests.post(url, json=payload, timeout=5)
    except requests.RequestException as e:
        return False, f"Could not reach target: {e}"

    if resp.status_code == 200 and resp.json().get("authenticated"):
        flag = resp.json().get("flag", "")
        return True, f"Flag captured: {flag}"
    return False, "Bypass did not succeed -- target may not be running or already patched"


# ---------------------------------------------------------------------------
# Scenario: weak-ssh-lab
# ---------------------------------------------------------------------------

WEAK_SSH_LAB_DOCKERFILE = """FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssh-server && rm -rf /var/lib/apt/lists/*
RUN mkdir /var/run/sshd
RUN useradd -m -s /bin/bash labuser && echo 'labuser:password123' | chpasswd
RUN echo 'FLAG{weak_ssh_credentials_found}' > /home/labuser/flag.txt && chown labuser:labuser /home/labuser/flag.txt
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
"""


def check_flag_weak_ssh_lab(host: str, port: int) -> tuple:
    """
    Attempts SSH login with the known weak credential, then reads the
    flag file. Requires `paramiko` (pip install paramiko).
    """
    try:
        import paramiko
    except ImportError:
        return False, "paramiko not installed. Run: pip install paramiko --break-system-packages"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username="labuser", password="password123", timeout=5)
        _, stdout, _ = client.exec_command("cat /home/labuser/flag.txt")
        flag = stdout.read().decode().strip()
        client.close()
        return True, f"Flag captured: {flag}"
    except Exception as e:
        return False, f"SSH login/flag read failed: {e}"


# ---------------------------------------------------------------------------
# Scenario: port-scan-lab
# ---------------------------------------------------------------------------

PORT_SCAN_LAB_PORTS = {
    2121: "FTP-FAKE (vsftpd 2.3.4 banner)",
    8080: "HTTP-ALT (fake admin panel)",
    3307: "MySQL-FAKE (5.5.8-log banner)",
    6380: "Redis-FAKE (no auth required)",
}

PORT_SCAN_LAB_DOCKERFILE = """FROM alpine:latest
RUN apk add --no-cache socat
COPY start_listeners.sh /start_listeners.sh
RUN chmod +x /start_listeners.sh
EXPOSE 2121 8080 3307 6380
CMD ["/start_listeners.sh"]
"""

PORT_SCAN_LAB_LISTENER_SCRIPT = """#!/bin/sh
(echo "220 (vsFTPd 2.3.4)" | socat -T5 TCP-LISTEN:2121,fork,reuseaddr SYSTEM:"cat" &)
(echo "HTTP/1.1 200 OK\\r\\n\\r\\nFake Admin Panel v1.0" | socat -T5 TCP-LISTEN:8080,fork,reuseaddr SYSTEM:"cat" &)
(echo "5.5.8-log MySQL Community Server" | socat -T5 TCP-LISTEN:3307,fork,reuseaddr SYSTEM:"cat" &)
(echo "+PONG" | socat -T5 TCP-LISTEN:6380,fork,reuseaddr SYSTEM:"cat" &)
wait
"""


def check_flag_port_scan_lab(host: str, port_map: dict = None) -> tuple:
    """Confirms all expected ports are open and responding -- the 'flag'
    here is successfully fingerprinting every exposed service."""
    port_map = port_map or PORT_SCAN_LAB_PORTS
    found = []
    for port, expected_service in port_map.items():
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                banner = sock.recv(256).decode(errors="ignore").strip()
                found.append((port, banner))
        except (socket.error, ConnectionRefusedError, OSError):
            continue

    if len(found) == len(port_map):
        summary = "; ".join(f"{p}:{b[:40]}" for p, b in found)
        return True, f"All {len(port_map)} services fingerprinted: {summary}"
    return False, f"Only {len(found)}/{len(port_map)} expected ports responded"


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS = {
    "sqli-lab": {
        "description": "Vulnerable login endpoint -- practice SQL injection detection",
        "dockerfile": SQLI_LAB_DOCKERFILE,
        "build_files": {"app.py": SQLI_LAB_APP_SOURCE},
        "container_port": 5000,
        "suggested_tools": [
            "Project #15: python3 sql_injection_detector.py scan -u \"http://<host>:<port>/login\" -X POST -d '{\"username\":\"admin\",\"password\":\"x\"}' --json",
            "Project #10: python3 webapp_scanner.py -u http://<host>:<port>",
        ],
        "check_flag": check_flag_sqli_lab,
    },
    "weak-ssh-lab": {
        "description": "SSH server with a default/weak password -- practice credential auditing",
        "dockerfile": WEAK_SSH_LAB_DOCKERFILE,
        "build_files": {},
        "container_port": 22,
        "suggested_tools": [
            "Manual: ssh labuser@<host> -p <port>  (password: password123)",
            "hydra -l labuser -P rockyou.txt ssh://<host>:<port>",
        ],
        "check_flag": check_flag_weak_ssh_lab,
    },
    "port-scan-lab": {
        "description": "Multiple fake services on non-standard ports -- practice service fingerprinting",
        "dockerfile": PORT_SCAN_LAB_DOCKERFILE,
        "build_files": {"start_listeners.sh": PORT_SCAN_LAB_LISTENER_SCRIPT},
        "container_port": None,  # multiple ports, handled specially
        "suggested_tools": [
            "Project #4: python3 scanner.py -t <host> -p 2121,3307,6380,8080",
            "Project #7: python3 scanner.py -t <host>  (full vuln assessment)",
        ],
        "check_flag": check_flag_port_scan_lab,
    },
}


# ---------------------------------------------------------------------------
# Docker orchestration (via subprocess -- requires a real Docker daemon,
# untested in the sandbox this was built in; verify on Kali)
# ---------------------------------------------------------------------------

def _run_docker(args: list, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker"] + args, capture_output=True, text=True, check=check)


def build_context_dir(scenario_name: str, scenario: dict) -> str:
    import tempfile
    from pathlib import Path

    build_dir = Path(tempfile.mkdtemp(prefix=f"cyberrange-{scenario_name}-"))
    (build_dir / "Dockerfile").write_text(scenario["dockerfile"])
    for filename, content in scenario["build_files"].items():
        (build_dir / filename).write_text(content)
    return str(build_dir)


def range_up(scenario_name: str, host_port: int = None):
    scenario = SCENARIOS.get(scenario_name)
    if scenario is None:
        raise ValueError(f"Unknown scenario: {scenario_name}. Run 'list' to see available scenarios.")

    container_name = RANGE_PREFIX + scenario_name
    image_tag = container_name

    build_dir = build_context_dir(scenario_name, scenario)
    print(f"[*] Building image from {build_dir} ...")
    _run_docker(["build", "-t", image_tag, build_dir])

    _run_docker(["network", "create", RANGE_NETWORK], check=False)  # ok if it already exists

    cmd = ["run", "-d", "--name", container_name, "--network", RANGE_NETWORK]
    if scenario["container_port"]:
        port = host_port or scenario["container_port"]
        cmd += ["-p", f"{port}:{scenario['container_port']}"]
    elif scenario_name == "port-scan-lab":
        for cport in PORT_SCAN_LAB_PORTS:
            cmd += ["-p", f"{cport}:{cport}"]
    cmd.append(image_tag)

    print(f"[*] Starting container {container_name} ...")
    _run_docker(cmd)
    print(f"[+] {scenario_name} is up. Run 'info {scenario_name}' for target details.")


def range_down(scenario_name: str):
    container_name = RANGE_PREFIX + scenario_name
    print(f"[*] Stopping and removing {container_name} ...")
    _run_docker(["stop", container_name], check=False)
    _run_docker(["rm", container_name], check=False)
    print(f"[+] {scenario_name} torn down.")


def range_status():
    result = _run_docker(["ps", "--filter", f"name={RANGE_PREFIX}", "--format",
                           "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"], check=False)
    print(result.stdout or "No cyber-range containers running.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_scenario_list():
    print("[*] Available scenarios:\n")
    for name, s in SCENARIOS.items():
        print(f"  {name}")
        print(f"    {s['description']}")


def print_scenario_info(scenario_name: str):
    scenario = SCENARIOS.get(scenario_name)
    if scenario is None:
        print(f"[!] Unknown scenario: {scenario_name}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] {scenario_name}")
    print(f"    {scenario['description']}")
    print(f"\n    Suggested tools from this portfolio:")
    for tool in scenario["suggested_tools"]:
        print(f"      - {tool}")


def main():
    parser = argparse.ArgumentParser(description="Cyber Range Simulation Environment (Project #20)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available scenarios")

    p_up = sub.add_parser("up", help="Build and start a scenario")
    p_up.add_argument("scenario")
    p_up.add_argument("--host-port", type=int, help="Host port to map to the container's port")

    p_down = sub.add_parser("down", help="Stop and remove a scenario")
    p_down.add_argument("scenario")

    sub.add_parser("status", help="Show running cyber-range containers")

    p_info = sub.add_parser("info", help="Show target details and suggested tools for a scenario")
    p_info.add_argument("scenario")

    p_check = sub.add_parser("check-flag", help="Attempt to verify a scenario's flag is capturable")
    p_check.add_argument("scenario")
    p_check.add_argument("--host", default="127.0.0.1")
    p_check.add_argument("--port", type=int, help="Required for sqli-lab and weak-ssh-lab")

    args = parser.parse_args()

    try:
        if args.command == "list":
            print_scenario_list()

        elif args.command == "up":
            range_up(args.scenario, args.host_port)

        elif args.command == "down":
            range_down(args.scenario)

        elif args.command == "status":
            range_status()

        elif args.command == "info":
            print_scenario_info(args.scenario)

        elif args.command == "check-flag":
            scenario = SCENARIOS.get(args.scenario)
            if scenario is None:
                print(f"[!] Unknown scenario: {args.scenario}", file=sys.stderr)
                sys.exit(1)

            if args.scenario == "port-scan-lab":
                success, message = check_flag_port_scan_lab(args.host)
            else:
                if args.port is None:
                    print(f"[!] --port is required for {args.scenario}", file=sys.stderr)
                    sys.exit(1)
                success, message = scenario["check_flag"](args.host, args.port)

            status = "CAPTURED" if success else "NOT CAPTURED"
            print(f"[{'+' if success else '!'}] {status}: {message}")
            sys.exit(0 if success else 1)

    except ValueError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] Docker command failed: {e.stderr}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
