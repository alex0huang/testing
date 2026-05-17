"""Safe request handlers — env-based secrets, allowlists, escaping, verified TLS."""

import html
import logging
import os
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

import urllib.request

logger = logging.getLogger(__name__)

ALLOWED_FETCH_HOSTS = frozenset({"api.example.com", "cdn.example.com"})


def get_api_key() -> str:
    key = os.environ.get("API_KEY")
    if not key:
        raise RuntimeError("API_KEY is not set")
    return key


def lookup_user(email: str) -> dict | None:
    with sqlite3.connect("app.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
    if row is None:
        return None
    return {"id": row[0], "email": row[1]}


def render_profile(display_name: str) -> str:
    safe_name = html.escape(display_name.strip()[:128], quote=True)
    return f"<div class='profile'>{safe_name}</div>"


def fetch_allowed_json(url: str, timeout: float = 5.0) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        raise ValueError("URL not allowed")
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def read_config_file(filename: str, config_dir: Path) -> str:
    if os.path.isabs(filename) or ".." in Path(filename).parts:
        raise ValueError("invalid filename")
    base = config_dir.resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError("path traversal detected")
    return target.read_text(encoding="utf-8")


def issue_session_token() -> str:
    return secrets.token_urlsafe(32)


def audit_login_attempt(username: str, success: bool) -> None:
    logger.info("login %s user=%s", "ok" if success else "fail", username[:64])
