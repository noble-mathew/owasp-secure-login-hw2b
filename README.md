# HW 2-B Secure Login Form

This repository contains the secure-login portion of my HW 2-B OWASP assignment. It is a small local web application built with Python, SQLite, HTML, CSS, and JavaScript. The goal is to demonstrate simple defenses against SQL injection, cross-site scripting (XSS), weak password storage, and unsafe client-side-only validation.

## What the project demonstrates

- Email and password login form
- Client-side validation for basic usability
- Server-side validation because browser checks can be bypassed
- Parameterized SQLite query (`WHERE email = ?`) instead of string-built SQL
- Password storage with Python `hashlib.scrypt` and a unique random salt
- Constant-time password comparison with `hmac.compare_digest`
- Safe page updates with `textContent` rather than `innerHTML`
- Content Security Policy and additional browser security headers
- Static-file allowlisting so requests cannot traverse outside the `static` folder

## Run the project

Python 3.10 or newer is recommended. No third-party packages are required.

```bash
python server.py
```

Then open:

`http://127.0.0.1:8765`

Demo account:

- Email: `student@example.com`
- Password: `SecurePass123!`

The local `users.db` database is created automatically on first run and is excluded from Git.

## Run the security checks

With `server.py` still running, open a second terminal in the project folder and run:

```bash
python security_test.py
```

The test script checks:

1. A valid login succeeds.
2. A SQL-injection-style email is rejected and cannot change the parameterized SQL statement.
3. An XSS-style value does not execute as HTML/JavaScript.
4. Unexpected JSON input is handled without crashing the server.
5. A path-traversal-style request cannot read files outside the public static directory.

## Assignment test inputs

These inputs are intentionally used only against this local/authorized demo application:

- SQL injection style: `' OR 1=1--@example.com`
- XSS style: `<script>alert(1)</script>@example.com`

The SQL-injection-style value fails server-side email validation. Even without that validation, the SQLite lookup uses a parameterized query, so the supplied email remains data rather than becoming SQL syntax. The XSS-style value is not rendered with `innerHTML`; server messages are assigned with `textContent`, and the page also sends a restrictive Content Security Policy.

## Files

- `server.py` - local HTTP server, database setup, authentication, and security headers
- `static/index.html` - login page
- `static/app.js` - browser-side validation and login request
- `static/styles.css` - page styling
- `security_test.py` - reproducible security checks
- `evidence/security_test_results.txt` - recorded output from the local security test run
- `.gitignore` - excludes generated database/cache files

## Scope

This project is for coursework and authorized local testing. The security test inputs should not be used against systems without permission.
