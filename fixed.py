import os
import sqlite3

# Load from environment — safe
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

DB_PATH = "users.db"


def get_user_by_id(user_id):
    """Fetch a user record by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Parameterized query — safe from SQL injection
    cursor.execute(
        "SELECT id, name, email FROM users WHERE id = ?",
        (user_id,),
    )

    result = cursor.fetchone()
    conn.close()
    return result


def search_users(name):
    """Search users by name."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Parameterized LIKE query — safe
    cursor.execute(
        "SELECT * FROM users WHERE name LIKE ?",
        (f"%{name}%",),
    )

    results = cursor.fetchall()
    conn.close()
    return results