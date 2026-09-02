#!/usr/bin/env python3
"""
Self-test for access_control.py using Flask's real test client -- this
exercises the actual routing, session, and SQLite logic end-to-end, not a
mock or simulation. Uses a temp SQLite file (Flask's per-request g.db
pattern doesn't support ':memory:' across requests, so a real temp file
stands in for a throwaway database).

Run this any time access_control.py changes to confirm nothing broke.

Usage:
    python3 selftest.py
"""

import json
import os
import sys
import tempfile

from access_control import create_app, seed_admin


def _assert(condition: bool, message: str, failures: list):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {message}")
    if not condition:
        failures.append(message)


def register(client, username, password):
    return client.post("/register", json={"username": username, "password": password})


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def main():
    failures = []

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    os.remove(db_path)  # let init_db create it fresh
    log_fd, log_path = tempfile.mkstemp(suffix=".log")
    os.close(log_fd)
    os.remove(log_path)

    try:
        # Seed one admin directly (bypassing self-registration, which always
        # forces role='user' -- this IS the intended way to create the
        # first admin account)
        seed_admin(db_path, "root_admin", "SuperSecret!2026Strong")

        app = create_app(db_path=db_path, audit_log_path=log_path)
        client = app.test_client()

        print("=== Public access ===")
        resp = client.get("/public")
        _assert(resp.status_code == 200, "Public endpoint accessible with no auth", failures)

        print("\n=== Registration + password strength enforcement ===")
        resp = register(client, "weakuser", "123")
        _assert(resp.status_code == 400, "Weak password rejected at registration", failures)

        resp = register(client, "alice", "StrongPass!2026xyz")
        _assert(resp.status_code == 201, "Strong password accepted at registration", failures)
        _assert(resp.get_json().get("role") == "user", "Self-registered account gets 'user' role", failures)

        print("\n=== Privilege escalation attempt via request body ===")
        # Try to register while claiming role=admin in the request body --
        # the server must ignore this field entirely.
        resp = client.post("/register", json={
            "username": "sneaky", "password": "StrongPass!2026xyz", "role": "admin"
        })
        _assert(resp.status_code == 201, "Registration with extra 'role' field still succeeds", failures)
        _assert(resp.get_json().get("role") == "user",
                "Client-supplied 'role': 'admin' in registration is IGNORED (still 'user')", failures)

        print("\n=== Login ===")
        resp = login(client, "alice", "wrongpassword")
        _assert(resp.status_code == 401, "Login with wrong password rejected", failures)

        resp = login(client, "alice", "StrongPass!2026xyz")
        _assert(resp.status_code == 200, "Login with correct password succeeds", failures)
        _assert(resp.get_json().get("role") == "user", "Login response reports correct role", failures)

        print("\n=== RBAC enforcement (alice = 'user' role) ===")
        resp = client.get("/profile")
        _assert(resp.status_code == 200, "'user' role can access /profile", failures)

        resp = client.get("/reports")
        _assert(resp.status_code == 403, "'user' role CANNOT access /reports (needs manager+)", failures)

        resp = client.get("/admin/dashboard")
        _assert(resp.status_code == 403, "'user' role CANNOT access /admin/dashboard (needs admin)", failures)

        client.post("/logout")
        resp = client.get("/profile")
        _assert(resp.status_code == 401, "After logout, /profile requires auth again", failures)

        print("\n=== RBAC enforcement (root_admin = 'admin' role) ===")
        login(client, "root_admin", "SuperSecret!2026Strong")

        resp = client.get("/reports")
        _assert(resp.status_code == 200, "'admin' role CAN access /reports (manager-tier)", failures)

        resp = client.get("/admin/dashboard")
        _assert(resp.status_code == 200, "'admin' role CAN access /admin/dashboard", failures)

        print("\n=== Admin promoting another user (legitimate privilege change) ===")
        resp = client.post("/admin/promote", json={"username": "alice", "role": "manager"})
        _assert(resp.status_code == 200, "Admin can promote a user to manager", failures)

        client.post("/logout")
        login(client, "alice", "StrongPass!2026xyz")
        resp = client.get("/reports")
        _assert(resp.status_code == 200, "After promotion, alice (now manager) CAN access /reports", failures)

        resp = client.get("/admin/dashboard")
        _assert(resp.status_code == 403, "alice (manager, not admin) still CANNOT access /admin/dashboard", failures)

        print("\n=== Non-admin cannot promote (privilege escalation via promote endpoint) ===")
        resp = client.post("/admin/promote", json={"username": "alice", "role": "admin"})
        _assert(resp.status_code == 403, "'manager' role cannot call /admin/promote (admin-only)", failures)

        print("\n=== Audit log ===")
        client.post("/logout")
        login(client, "root_admin", "SuperSecret!2026Strong")
        resp = client.get("/admin/audit-log")
        _assert(resp.status_code == 200, "Admin can view the audit log", failures)
        entries = resp.get_json()["entries"]
        _assert(any("DENIED" in e for e in entries), "Audit log contains DENIED entries", failures)
        _assert(any("ALLOWED" in e for e in entries), "Audit log contains ALLOWED entries", failures)
        _assert(any("/reports" in e for e in entries), "Audit log records the specific endpoint accessed", failures)

        client.post("/logout")
        login(client, "alice", "StrongPass!2026xyz")
        resp = client.get("/admin/audit-log")
        _assert(resp.status_code == 403, "Non-admin (manager) cannot view the audit log", failures)

    finally:
        for p in (db_path, log_path):
            if os.path.exists(p):
                os.remove(p)

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
