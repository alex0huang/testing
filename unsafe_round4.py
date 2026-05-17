"""
Intentionally vulnerable — round 4 (AdaL / pre-push review testing only).
DO NOT use in production.
"""

import logging
import os
import sqlite3

# --- More hardcoded secrets ---
STRIPE_SECRET = "sk_test_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
WEBHOOK_SIGNING = "whsec_9f8e7d6c5b4a3210abcdef"

logger = logging.getLogger(__name__)


def lookup_user_by_email(email: str) -> dict | None:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL injection via string formatting
    cursor.execute("SELECT id, email FROM users WHERE email = '%s'" % email)
    row = cursor.fetchone()
    return {"id": row[0], "email": row[1]} if row else None


def render_profile(display_name: str) -> str:
    # XSS: raw user input in HTML
    return f"<div class='profile'>{display_name}</div>"


def fetch_partner_data(url: str) -> bytes:
    import ssl
    import urllib.request

    # SSRF + TLS verification disabled
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx).read()


def load_env_from_user(path: str) -> None:
    # Path traversal + arbitrary file read into process env
    with open(path) as f:
        for line in f:
            if "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()


def set_user_fields(user: dict, updates: dict) -> None:
    # Mass assignment: attacker can set is_admin, role, etc.
    for key, value in updates.items():
        setattr(user, key, value)


def audit_login(username: str, password: str, success: bool) -> None:
    # Log injection / credential leak in logs
    logger.warning("login failed for %s password=%s ok=%s" % (username, password, success))
