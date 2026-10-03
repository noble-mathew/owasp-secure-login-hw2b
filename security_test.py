"""Reproducible security checks for the HW 2-B secure-login demo.

Start server.py first, then run: python security_test.py
"""

import json
from urllib import request, error

BASE = "http://127.0.0.1:8765"
LOGIN_URL = BASE + "/api/login"


def post_json(value):
    body = json.dumps(value).encode("utf-8")
    req = request.Request(
        LOGIN_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req) as response:
            return response.status, dict(response.headers), response.read().decode("utf-8")
    except error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8")


def get(path):
    try:
        with request.urlopen(BASE + path) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def check(label, payload, expected_status, expected_message):
    status, headers, body = post_json(payload)
    parsed = json.loads(body)
    assert status == expected_status, (label, status, body)
    assert parsed["message"] == expected_message, (label, parsed)
    assert "default-src 'self'" in headers.get("Content-Security-Policy", ""), label
    print(f"PASS: {label} -> HTTP {status}: {parsed['message']}")


if __name__ == "__main__":
    check(
        "valid login",
        {"email": "student@example.com", "password": "SecurePass123!"},
        200,
        "Login successful.",
    )
    check(
        "SQL-injection-style input",
        {"email": "' OR 1=1--@example.com", "password": "AnyPass123!"},
        400,
        "Enter a valid email address.",
    )
    check(
        "XSS-style input",
        {"email": "<script>alert(1)</script>@example.com", "password": "AnyPass123!"},
        401,
        "Invalid email or password.",
    )
    check(
        "non-object JSON",
        ["student@example.com", "SecurePass123!"],
        400,
        "JSON body must be an object.",
    )

    status, _ = get("/../server.py")
    assert status == 404, f"path traversal should be blocked, got HTTP {status}"
    print("PASS: path traversal attempt is blocked with HTTP 404")
    print("All security checks passed.")
