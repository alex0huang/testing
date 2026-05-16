"""Safe utilities — parameterized queries, no shell, no secrets in source."""

import hashlib
import hmac
import os
import sqlite3
import subprocess
from pathlib import Path


def greet(name: str) -> str:
    safe = name.strip()[:64] or "world"
    return f"Hello, {safe}!"


def login(username: str, password: str) -> bool:
    with sqlite3.connect("app.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT pass_hash FROM users WHERE name = ?",
            (username,),
        )
        row = cursor.fetchone()
    if row is None:
        return False
    return verify_password(password, row[0])


def run_allowed_command(command: str) -> int:
    allowed = {"status": ["git", "status"], "version": ["python3", "--version"]}
    if command not in allowed:
        raise ValueError(f"command not allowed: {command}")
    return subprocess.run(allowed[command], check=False, shell=False).returncode


def read_file_from_uploads(filename: str, uploads_dir: Path) -> str:
    if os.path.isabs(filename) or ".." in Path(filename).parts:
        raise ValueError("invalid filename")
    base = uploads_dir.resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError("path traversal detected")
    return target.read_text(encoding="utf-8")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return hmac.compare_digest(actual, expected)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
