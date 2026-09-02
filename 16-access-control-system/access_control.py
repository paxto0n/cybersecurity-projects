#!/usr/bin/env python3
"""
Project #16 - Access Control System (RBAC)

A Flask-based Role-Based Access Control system. Core security property:
role is ALWAYS read from the server-side session + database, never trusted
from client input -- so a client cannot escalate privileges by tampering
with a request field. Self-registration always creates "user"-role
accounts; only an existing admin can promote another account.

Roles (least to most privileged): user < manager < admin
Resources:
    GET  /public              - no auth required
    POST /register             - create account (role always forced to "user")
    POST /login / POST /logout - session auth
    GET  /profile               - any authenticated user
    GET  /reports                - manager or admin
    GET  /admin/dashboard         - admin only
    GET  /admin/audit-log          - admin only, view the access audit trail
    POST /admin/promote             - admin only, change another user's role

Every access attempt (allowed or denied) is written to an audit log --
same file-based alert-logging pattern as Project #9/#11.

Password strength is enforced at registration using Project #5's
password_checker.py when available, with a safe fallback if not.

Usage (as a library, for testing):
    from access_control import create_app
    app = create_app(db_path=":memory:")   # or a real file path

Usage (as a standalone server):
    python3 access_control.py --db access_control.db --port 5060
"""

import argparse
import functools
import hashlib
import hmac
import importlib.util
import os
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import Flask, request, session, jsonify, g

ROLE_RANK = {"user": 1, "manager": 2, "admin": 3}
AUDIT_LOG_DEFAULT = "access_log.txt"


# ---------------------------------------------------------------------------
# Optional integration with Project #5's password strength checker
# ---------------------------------------------------------------------------

def _load_password_checker():
    candidates = [
        Path(__file__).resolve().parent.parent / "password_checker" / "checker.py",
        Path.home() / "password_checker" / "checker.py",
    ]
    for path in candidates:
        if path.exists():
            spec = importlib.util.spec_from_file_location("checker", path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                return module
            except Exception:
                return None
    return None


def _password_is_strong_enough(password: str) -> tuple:
    """Returns (is_ok, reason). Uses Project #5's checker if available and
    compatible; falls back to a basic length+variety check if not, so
    registration still works standalone."""
    checker = _load_password_checker()
    if checker is not None:
        for fn_name in ("check_password_strength", "check_strength", "analyze_password"):
            if hasattr(checker, fn_name):
                try:
                    result = getattr(checker, fn_name)(password)
                    # Accept a couple of plausible return shapes defensively
                    if isinstance(result, dict):
                        strong = result.get("strong", result.get("is_strong", result.get("score", 0) >= 3))
                        return bool(strong), result.get("reason", "Password does not meet strength requirements")
                    if isinstance(result, (int, float)):
                        return result >= 3, "Password strength score too low"
                except Exception:
                    break  # fall through to local fallback

    # Fallback: basic policy if Project #5's checker isn't found/compatible
    if len(password) < 10:
        return False, "Password must be at least 10 characters"
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    if not (has_upper and has_digit and has_symbol):
        return False, "Password must include an uppercase letter, a digit, and a symbol"
    return True, ""


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2, stdlib only -- no extra dependency)
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return digest.hex(), salt.hex()


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, stored_hash_hex)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g.db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_access(log_path: str, username: str, role: str, endpoint: str, allowed: bool, reason: str = ""):
    status = "ALLOWED" if allowed else "DENIED"
    line = f"{datetime.now().isoformat()} | {status} | user={username or 'anonymous'} " \
           f"role={role or 'none'} endpoint={endpoint}"
    if reason:
        line += f" | reason={reason}"
    with open(log_path, "a") as f:
        f.write(line + "\n")


# ---------------------------------------------------------------------------
# Access control decorator
# ---------------------------------------------------------------------------

def require_role(min_role: str):
    """
    Enforces that the CURRENT SESSION's role (fetched fresh from the
    database via the session's user_id -- never from client-supplied
    request data) meets or exceeds min_role's rank. This is the core
    anti-privilege-escalation property: a client cannot simply send
    role=admin in a form field or cookie value and have it trusted.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            if user_id is None:
                log_access(g.audit_log_path, None, None, request.path, allowed=False, reason="not authenticated")
                return jsonify({"error": "Authentication required"}), 401

            db = get_db()
            row = db.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                log_access(g.audit_log_path, None, None, request.path, allowed=False, reason="stale session")
                return jsonify({"error": "Authentication required"}), 401

            username, role = row["username"], row["role"]
            if ROLE_RANK.get(role, 0) < ROLE_RANK.get(min_role, 999):
                log_access(g.audit_log_path, username, role, request.path, allowed=False,
                           reason=f"requires role >= {min_role}")
                return jsonify({"error": "Forbidden: insufficient privileges"}), 403

            log_access(g.audit_log_path, username, role, request.path, allowed=True)
            g.current_username = username
            g.current_role = role
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(db_path: str = "access_control.db", audit_log_path: str = AUDIT_LOG_DEFAULT) -> Flask:
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)

    if db_path != ":memory:":
        init_db(db_path)
    else:
        # Shared in-memory DB across requests needs a persistent connection;
        # Flask's per-request g.db would otherwise get a FRESH empty :memory:
        # db each request. Use a file-backed temp path instead for tests
        # that pass ":memory:" as a convenience alias.
        raise ValueError("Use a real file path (e.g. a tempfile), not ':memory:' -- "
                          "SQLite in-memory DBs don't persist across Flask's per-request connections.")

    @app.before_request
    def _setup():
        g.db_path = db_path
        g.audit_log_path = audit_log_path

    @app.teardown_appcontext
    def _close_db(exception=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.route("/public")
    def public():
        return jsonify({"message": "This endpoint requires no authentication."})

    @app.route("/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if not username or not password:
            return jsonify({"error": "username and password are required"}), 400

        strong_enough, reason = _password_is_strong_enough(password)
        if not strong_enough:
            return jsonify({"error": f"Weak password: {reason}"}), 400

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return jsonify({"error": "Username already taken"}), 409

        password_hash, salt = hash_password(password)
        # SECURITY: role is ALWAYS 'user' on self-registration, regardless
        # of anything the client sends -- any "role" field in the request
        # body is silently ignored, not read at all.
        db.execute(
            "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, 'user', ?)",
            (username, password_hash, salt, datetime.now().isoformat())
        )
        db.commit()
        return jsonify({"message": "Registered", "username": username, "role": "user"}), 201

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        db = get_db()
        row = db.execute("SELECT id, password_hash, salt, role FROM users WHERE username = ?", (username,)).fetchone()

        if row is None or not verify_password(password, row["password_hash"], row["salt"]):
            log_access(g.audit_log_path, username, None, "/login", allowed=False, reason="bad credentials")
            return jsonify({"error": "Invalid username or password"}), 401

        session.clear()
        session["user_id"] = row["id"]
        log_access(g.audit_log_path, username, row["role"], "/login", allowed=True)
        return jsonify({"message": "Logged in", "role": row["role"]})

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"message": "Logged out"})

    @app.route("/profile")
    @require_role("user")
    def profile():
        return jsonify({"username": g.current_username, "role": g.current_role})

    @app.route("/reports")
    @require_role("manager")
    def reports():
        return jsonify({"message": "Confidential reports data", "accessed_by": g.current_username})

    @app.route("/admin/dashboard")
    @require_role("admin")
    def admin_dashboard():
        return jsonify({"message": "Admin dashboard", "accessed_by": g.current_username})

    @app.route("/admin/audit-log")
    @require_role("admin")
    def admin_audit_log():
        log_path = Path(g.audit_log_path)
        if not log_path.exists():
            return jsonify({"entries": []})
        lines = log_path.read_text().strip().splitlines()
        return jsonify({"entries": lines[-200:]})  # cap to last 200 entries

    @app.route("/admin/promote", methods=["POST"])
    @require_role("admin")
    def admin_promote():
        data = request.get_json(silent=True) or request.form
        target_username = data.get("username")
        new_role = data.get("role")

        if new_role not in ROLE_RANK:
            return jsonify({"error": f"Invalid role. Must be one of {list(ROLE_RANK)}"}), 400

        db = get_db()
        result = db.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, target_username))
        db.commit()
        if result.rowcount == 0:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"message": f"{target_username} promoted to {new_role}"})

    return app


# ---------------------------------------------------------------------------
# CLI (standalone server)
# ---------------------------------------------------------------------------

def seed_admin(db_path: str, username: str, password: str):
    """Convenience: create an initial admin account directly, bypassing the
    self-registration endpoint (which always forces role='user')."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        print(f"[*] User '{username}' already exists, skipping seed.")
        conn.close()
        return
    password_hash, salt = hash_password(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
        (username, password_hash, salt, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    print(f"[+] Seeded admin user '{username}'")


def main():
    parser = argparse.ArgumentParser(description="Access Control System (Project #16)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="Run the Flask server")
    p_serve.add_argument("--db", default="access_control.db", help="SQLite database file path")
    p_serve.add_argument("--audit-log", default=AUDIT_LOG_DEFAULT, help="Audit log file path")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=5060)

    p_seed = sub.add_parser("seed-admin", help="Create an initial admin account")
    p_seed.add_argument("--db", default="access_control.db")
    p_seed.add_argument("--username", required=True)
    p_seed.add_argument("--password", required=True)

    args = parser.parse_args()

    if args.command == "seed-admin":
        seed_admin(args.db, args.username, args.password)
    elif args.command == "serve":
        app = create_app(db_path=args.db, audit_log_path=args.audit_log)
        app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
