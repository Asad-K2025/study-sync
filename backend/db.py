from __future__ import annotations

import sqlite3
from typing import Any

from flask import current_app, g


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db() -> sqlite3.Connection:
    db: sqlite3.Connection | None = g.get("db")
    if db is None:
        db = connect_db()
        g.db = db
    return db


def close_db(_: Any | None = None) -> None:
    db: sqlite3.Connection | None = g.pop("db", None)
    if db is not None:
        db.close()

