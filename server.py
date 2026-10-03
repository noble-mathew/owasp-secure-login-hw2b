from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import json
import sqlite3
import hashlib
import hmac
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE, "static")
DB = os.path.join(BASE, "users.db")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_BODY_BYTES = 10_000
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 256
ALLOWED_STATIC_PATHS = {"/", "/index.html", "/app.js", "/styles.css"}


def hash_password(password: str, salt: bytes | None = None):
    """Hash a password with scrypt and a unique random salt."""
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1
    )
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str):
    """Verify a password using a constant-time comparison."""
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    actual = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1
    )
    return hmac.compare_digest(actual, expected)


def init_db():
    """Create the demo database and seed one test account."""
    with sqlite3.connect(DB) as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(email TEXT PRIMARY KEY, salt TEXT NOT NULL, pw_hash TEXT NOT NULL)"
        )
        if not con.execute(
            "SELECT 1 FROM users WHERE email = ?", ("student@example.com",)
        ).fetchone():
            salt, pw_hash = hash_password("SecurePass123!")
            con.execute(
                "INSERT INTO users(email, salt, pw_hash) VALUES (?, ?, ?)",
                ("student@example.com", salt, pw_hash),
            )


class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        """Serve only the three files used by the demo from ./static."""
        clean = urlparse(path).path
        if clean == "/":
            clean = "/index.html"
        if clean not in ALLOWED_STATIC_PATHS:
            return os.path.join(STATIC_DIR, "__not_found__")
        return os.path.join(STATIC_DIR, clean.lstrip("/"))

    def end_headers(self):
        # Apply browser security headers to both static files and API responses.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        super().end_headers()

    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api/login":
            return self._json(404, {"ok": False, "message": "Not found"})

        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            return self._json(
                415, {"ok": False, "message": "Content-Type must be application/json."}
            )

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                return self._json(400, {"ok": False, "message": "Invalid request size."})
            data = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self._json(400, {"ok": False, "message": "Invalid JSON"})

        if not isinstance(data, dict):
            return self._json(400, {"ok": False, "message": "JSON body must be an object."})

        email = str(data.get("email", "")).strip()
        password = str(data.get("password", ""))

        # Server-side validation: never trust browser-side checks alone.
        if not email or not password:
            return self._json(
                400, {"ok": False, "message": "Email and password are required."}
            )
        if len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.fullmatch(email):
            return self._json(
                400, {"ok": False, "message": "Enter a valid email address."}
            )
        if len(password) < 8:
            return self._json(
                400,
                {"ok": False, "message": "Password must be at least 8 characters."},
            )
        if len(password) > MAX_PASSWORD_LENGTH:
            return self._json(
                400, {"ok": False, "message": "Password is too long."}
            )

        with sqlite3.connect(DB) as con:
            # Parameterized query blocks SQL injection because input is data, not SQL code.
            row = con.execute(
                "SELECT salt, pw_hash FROM users WHERE email = ?", (email,)
            ).fetchone()

        if row and verify_password(password, row[0], row[1]):
            return self._json(200, {"ok": True, "message": "Login successful."})
        return self._json(
            401, {"ok": False, "message": "Invalid email or password."}
        )


if __name__ == "__main__":
    init_db()
    print("Demo user: student@example.com / SecurePass123!")
    port = int(os.environ.get("PORT", "8765"))
    print(f"Open http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
