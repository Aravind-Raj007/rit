from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path("./cyberguard.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              created_at TEXT NOT NULL,
              last_login TEXT
            );

            CREATE TABLE IF NOT EXISTS encrypted_files (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              file_name TEXT NOT NULL,
              file_path TEXT NOT NULL,
              encrypted_path TEXT NOT NULL,
              file_size INTEGER NOT NULL,
              encryption_date TEXT NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()
