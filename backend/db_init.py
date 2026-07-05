from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from argon2 import PasswordHasher
from argon2._password_hasher import Type
from flask import Flask


def _read_schema() -> str:
    return (Path(__file__).resolve().parent / "schema.sql").read_text(encoding="utf-8")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1] for r in rows}


def _slugify_username(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "", name.lower())
    return base or "user"


def _argon2_hash(password: str) -> str:
    """Hash a password using argon2id with OWASP recommended parameters."""
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=Type.ID,  # Argon2id
    )
    return ph.hash(password.encode("utf-8"))


def init_db(app: Flask) -> None:
    db_path = Path(app.config["DB_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(_read_schema())

        cols = _table_columns(conn, "users")
        if "username" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN username TEXT")
        if "password_hash" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        if "email" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "reset_token" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        if "reset_token_expires_at" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN reset_token_expires_at DATETIME")

        if "password_changed_at" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_changed_at DATETIME")

        # Create verification_codes table if it doesn't exist
        vc_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='verification_codes'"
        ).fetchone()
        if not vc_exists:
            conn.execute("""
                CREATE TABLE verification_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    code TEXT NOT NULL,
                    expires_at DATETIME NOT NULL,
                    used INTEGER DEFAULT 0,
                    ip_address TEXT NOT NULL DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_verification_codes_ip_created ON verification_codes(ip_address, created_at)")
        else:
            vc_cols = _table_columns(conn, "verification_codes")
            if "ip_address" not in vc_cols:
                conn.execute("ALTER TABLE verification_codes ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''")

        # Create login_failures table if it doesn't exist
        lf_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='login_failures'"
        ).fetchone()
        if not lf_exists:
            conn.execute("""
                CREATE TABLE login_failures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    failed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(username, ip_address)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_login_failures_failed_at ON login_failures(failed_at)")
        else:
            lf_cols = _table_columns(conn, "login_failures")
            if "ip_address" not in lf_cols:
                conn.execute("ALTER TABLE login_failures ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''")

        # Create password_history table if it doesn't exist
        ph_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='password_history'"
        ).fetchone()
        if not ph_exists:
            conn.execute("""
                CREATE TABLE password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")

        _seed_if_empty(conn)
        _backfill_auth_for_existing_users(conn)
        _ensure_demo_usernames(conn)
        _update_demo_passwords(conn)
        _migrate_bcrypt_to_argon2(conn)

        conn.commit()
    finally:
        conn.close()


def _seed_if_empty(conn: sqlite3.Connection) -> None:
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count:
        return

    default_password = "StudySync!1"
    users = [
        (1, "Alex Rivera", "alex", "studysync_support@163.com"),
        (2, "Jordan Chen", "jordan", None),
        (3, "Sarah Miller", "sarah", None),
        (4, "Marcus Lee", "marcus", None),
    ]
    for uid, name, username, email in users:
        if email:
            conn.execute(
                "INSERT INTO users (id, name, username, email, password_hash, avatar_color) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, name, username, email, _argon2_hash(default_password), "#4361ee"),
            )
        else:
            conn.execute(
                "INSERT INTO users (id, name, username, password_hash, avatar_color) VALUES (?, ?, ?, ?, ?)",
                (uid, name, username, _argon2_hash(default_password), "#4361ee"),
            )

    groups = [
        (1, "Design Sprint", "#4361ee"),
        (2, "Marketing Sync", "#f72585"),
        (3, "Launch Party", "#06d6a0"),
    ]
    for gid, name, color in groups:
        conn.execute("INSERT INTO groups (id, name, color) VALUES (?, ?, ?)", (gid, name, color))

    members = [
        (1, 1),
        (1, 2),
        (1, 3),
        (2, 1),
        (2, 4),
        (3, 1),
        (3, 2),
        (3, 3),
        (3, 4),
    ]
    for gid, uid in members:
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (gid, uid))

    msg_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    if msg_count == 0:
        msgs = [
            (
                1,
                2,
                "Hey team! I've uploaded the initial wireframes for the new dashboard. Can everyone take a look before our sync?",
            ),
            (
                1,
                1,
                "On it! The flow looks much tighter already. I particularly like how the bento grid arrangement handles the widget density.",
            ),
            (1, 3, "Astro is right, let's lock in that sync. Tuesday morning works best for the Dev team. @Jordan thoughts?"),
        ]
        for gid, uid, content in msgs:
            conn.execute(
                "INSERT INTO messages (group_id, user_id, content) VALUES (?, ?, ?)",
                (gid, uid, content),
            )

    mtg_count = conn.execute("SELECT COUNT(*) FROM meetings").fetchone()[0]
    if mtg_count == 0:
        cur = conn.execute(
            "INSERT INTO meetings (group_id, title, description, created_by) VALUES (1, ?, ?, 1)",
            ("Design Review & Sprints", "Weekly design sync"),
        )
        mid = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO meeting_time_slots (meeting_id, day, time) VALUES (?, 'Tuesday', '14:00')",
            (mid,),
        )
        slot1 = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO meeting_time_slots (meeting_id, day, time) VALUES (?, 'Wednesday', '10:30')",
            (mid,),
        )
        slot2 = cur.lastrowid

        conn.execute("INSERT INTO meeting_votes (slot_id, user_id, available) VALUES (?, 2, 1)", (slot1,))
        conn.execute("INSERT INTO meeting_votes (slot_id, user_id, available) VALUES (?, 3, 1)", (slot1,))
        conn.execute("INSERT INTO meeting_votes (slot_id, user_id, available) VALUES (?, 4, 1)", (slot1,))
        conn.execute("INSERT INTO meeting_votes (slot_id, user_id, available) VALUES (?, 2, 1)", (slot2,))
        conn.execute("INSERT INTO meeting_votes (slot_id, user_id, available) VALUES (?, 3, 1)", (slot2,))

        cur = conn.execute(
            "INSERT INTO meetings (group_id, title, description, created_by) VALUES (2, ?, ?, 1)",
            ("Market Expansion Strategy", "Q4 planning"),
        )
        mid2 = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO meeting_time_slots (meeting_id, day, time) VALUES (?, 'Wednesday', '10:30')",
            (mid2,),
        )
        slot3 = cur.lastrowid
        conn.execute("INSERT INTO meeting_votes (slot_id, user_id, available) VALUES (?, 2, 1)", (slot3,))


def _backfill_auth_for_existing_users(conn: sqlite3.Connection) -> None:
    default_password = "StudySync!1"
    users = conn.execute("SELECT id, name, username, password_hash, email FROM users").fetchall()
    for u in users:
        uid = int(u["id"])
        username = u["username"]
        password_hash = u["password_hash"]
        email = u["email"]

        if not username:
            base = _slugify_username(u["name"])
            candidate = base
            i = 1
            while conn.execute("SELECT 1 FROM users WHERE username = ? AND id != ?", (candidate, uid)).fetchone():
                i += 1
                candidate = f"{base}{i}"
            username = candidate
            conn.execute("UPDATE users SET username = ? WHERE id = ?", (username, uid))

        if not password_hash:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_argon2_hash(default_password), uid))

        if not email:
            safe_user = (username or "user").replace("@", "")
            candidate_email = f"{safe_user}@studysync.dev"
            while conn.execute("SELECT 1 FROM users WHERE email = ?", (candidate_email,)).fetchone():
                candidate_email = f"{safe_user}{i}@studysync.dev"
                i += 1
            conn.execute("UPDATE users SET email = ? WHERE id = ?", (candidate_email, uid))


def _ensure_demo_usernames(conn: sqlite3.Connection) -> None:
    demo = [
        (1, "Alex Rivera", "alex"),
        (2, "Jordan Chen", "jordan"),
        (3, "Sarah Miller", "sarah"),
        (4, "Marcus Lee", "marcus"),
    ]
    for uid, name, desired in demo:
        row = conn.execute("SELECT username FROM users WHERE id = ? AND name = ?", (uid, name)).fetchone()
        if not row:
            continue
        current = row["username"]
        if current == desired:
            continue
        collision = conn.execute("SELECT 1 FROM users WHERE username = ? AND id != ?", (desired, uid)).fetchone()
        if collision:
            continue
        conn.execute("UPDATE users SET username = ? WHERE id = ?", (desired, uid))


def _update_demo_passwords(conn: sqlite3.Connection) -> None:
    demo = [
        (1, "Alex Rivera"),
        (2, "Jordan Chen"),
        (3, "Sarah Miller"),
        (4, "Marcus Lee"),
    ]
    new_password = "StudySync!1"
    new_hash = _argon2_hash(new_password)
    for uid, name in demo:
        row = conn.execute("SELECT id FROM users WHERE id = ? AND name = ?", (uid, name)).fetchone()
        if row:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, uid))


def _migrate_bcrypt_to_argon2(conn: sqlite3.Connection) -> None:
    """Migrate any bcrypt-hashed passwords to argon2."""
    default_password = "StudySync!1"
    
    users = conn.execute("SELECT id, password_hash FROM users WHERE password_hash IS NOT NULL").fetchall()
    
    migrated = []
    for user in users:
        uid = user["id"]
        hashed = user["password_hash"]
        if not hashed:
            continue
        
        # Check if it's a bcrypt hash (starts with $2b$ or $2a$)
        if hashed.startswith(("$2b$", "$2a$")):
            try:
                import bcrypt
                if bcrypt.checkpw(default_password.encode(), hashed.encode()):
                    # Password matches with bcrypt, migrate to argon2
                    new_hash = _argon2_hash(default_password)
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, uid))
                    migrated.append(uid)
            except ImportError:
                # bcrypt not installed, cannot verify
                pass
            except Exception:
                # Password doesn't match bcrypt or other error, skip
                pass
    
    if migrated:
        print(f"Migrated {len(migrated)} user(s) from bcrypt to argon2")
