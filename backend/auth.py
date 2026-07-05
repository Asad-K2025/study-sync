from __future__ import annotations

import re
from functools import wraps
from typing import Any, Callable, TypeVar, cast

import secrets
import smtplib
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from hmac import compare_digest

from argon2 import PasswordHasher
from argon2._password_hasher import Type
from argon2.exceptions import VerifyMismatchError, InvalidHash
from flask import Blueprint, current_app, jsonify, request, session

from backend.db import get_db


bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")

PASSWORD_STRENGTH_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,}$")

F = TypeVar("F", bound=Callable[..., Any])

# --- Configuration constants ---
LOGIN_MAX_ATTEMPTS = 5          # max failed logins before lockout
LOGIN_LOCKOUT_SECONDS = 60     # lockout duration
LOGIN_RATE_LIMIT = 20          # max requests per minute per IP
LOGIN_RATE_WINDOW = 60         # rate limit window in seconds
FORGOT_PASSWORD_GLOBAL_LIMIT = 10  # max forgot_password requests per minute (global)
FORGOT_PASSWORD_GLOBAL_WINDOW = 60   # global rate limit window
PASSWORD_HISTORY_COUNT = 3     # number of old passwords to remember


def _get_argon2_config():
    """Get argon2 configuration from Flask config or environment variables."""
    config = current_app.config
    return {
        "time_cost": config.get("ARGON2_TIME_COST", 3),
        "memory_cost": config.get("ARGON2_MEMORY_COST", 65536),
        "parallelism": config.get("ARGON2_PARALLELISM", 4),
        "hash_len": config.get("ARGON2_HASH_LEN", 32),
        "salt_len": config.get("ARGON2_SALT_LEN", 16),
    }


def _get_password_hasher():
    """Create and cache an argon2 PasswordHasher instance."""
    if not hasattr(_get_password_hasher, "_cache"):
        config = _get_argon2_config()
        _get_password_hasher._cache = PasswordHasher(
            time_cost=config["time_cost"],
            memory_cost=config["memory_cost"],
            parallelism=config["parallelism"],
            hash_len=config["hash_len"],
            salt_len=config["salt_len"],
            type=Type.ID,  # Argon2id - recommended for password hashing
        )
    return _get_password_hasher._cache


def _hash_password(password: str) -> str:
    """Hash a password using argon2id with OWASP recommended parameters."""
    ph = _get_password_hasher()
    return ph.hash(password.encode("utf-8"))


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a hash using constant-time comparison.
    
    Uses argon2-cffi's verify() which internally uses constant-time comparison
    to prevent timing attacks.
    """
    ph = _get_password_hasher()
    try:
        ph.verify(hashed, password.encode("utf-8"))
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def _needs_rehash(hashed: str) -> bool:
    """Check if the password hash needs to be rehashed with updated parameters."""
    try:
        ph = _get_password_hasher()
        return ph.check_needs_rehash(hashed)
    except InvalidHash:
        return True


def _json_error(message: str, status: int):
    return jsonify({"error": message}), status


def _get_client_ip() -> str:
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _check_login_rate_limit(db, username: str, ip: str = None) -> bool:
    """Check if the IP has exceeded the login rate limit."""
    if ip is None:
        ip = _get_client_ip()
    cutoff = (datetime.now() - timedelta(seconds=LOGIN_RATE_WINDOW)).strftime("%Y-%m-%d %H:%M:%S")
    count = db.execute(
        "SELECT COUNT(*) as cnt FROM login_failures WHERE ip_address = ? AND failed_at > ?",
        (ip, cutoff),
    ).fetchone()
    return count["cnt"] < LOGIN_RATE_LIMIT


def _check_account_lockout(db, username: str) -> tuple[bool, int]:
    """Check if the account is locked due to too many failed attempts.
    Returns (is_locked, remaining_seconds).
    """
    cutoff = (datetime.now() - timedelta(seconds=LOGIN_LOCKOUT_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    recent = db.execute(
        "SELECT COUNT(*) as cnt FROM login_failures WHERE username = lower(?) AND failed_at > ?",
        (username, cutoff),
    ).fetchone()
    if recent["cnt"] >= LOGIN_MAX_ATTEMPTS:
        # Find the oldest failure in the window to calculate remaining time
        oldest = db.execute(
            "SELECT MIN(failed_at) as oldest FROM login_failures WHERE username = lower(?) AND failed_at > ?",
            (username, cutoff),
        ).fetchone()
        if oldest and oldest["oldest"]:
            failed_time = datetime.strptime(oldest["oldest"], "%Y-%m-%d %H:%M:%S")
            remaining = int(LOGIN_LOCKOUT_SECONDS - (datetime.now() - failed_time).total_seconds())
            remaining = max(remaining, 1)
            return True, remaining
        return True, LOGIN_LOCKOUT_SECONDS
    return False, 0


def _record_login_failure(db, username: str) -> None:
    """Record a failed login attempt."""
    ip = _get_client_ip()
    try:
        db.execute(
            "INSERT INTO login_failures (username, ip_address) VALUES (lower(?), ?)",
            (username, ip),
        )
        db.commit()
    except Exception:
        # Handle unique constraint violation (same username + IP)
        db.rollback()


def _cleanup_old_login_failures(db) -> None:
    """Remove failed login attempts older than the lockout window."""
    cutoff = (datetime.now() - timedelta(seconds=LOGIN_LOCKOUT_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("DELETE FROM login_failures WHERE failed_at < ?", (cutoff,))
    db.commit()


def _check_password_history(db, uid: int, new_password: str) -> bool:
    """Check if the new password matches any of the user's recent passwords.
    Returns True if the password is NEW (safe to use), False if it's a repeat.
    """
    rows = db.execute(
        "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?",
        (uid, PASSWORD_HISTORY_COUNT),
    ).fetchall()
    for row in rows:
        stored_hash = row["password_hash"]
        if isinstance(stored_hash, bytes):
            stored_hash = stored_hash.decode("utf-8")
        if _verify_password(new_password, stored_hash):
            return False
    return True


def _cleanup_login_failures(db) -> None:
    """Remove failed login attempts older than the lockout window."""
    cutoff = (datetime.now() - timedelta(seconds=LOGIN_LOCKOUT_SECONDS * 2)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("DELETE FROM login_failures WHERE failed_at < ?", (cutoff,))
    db.commit()


def _cleanup_expired_verification_codes(db) -> None:
    """Remove expired verification codes older than 1 hour."""
    cutoff = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("DELETE FROM verification_codes WHERE expires_at < ?", (cutoff,))
    db.commit()


def _check_ip_rate_limit(db, ip: str, limit: int, window: int) -> bool:
    """Check if an IP has exceeded the rate limit for verification_codes.
    Returns True if within limit, False if exceeded.
    """
    cutoff = (datetime.now() - timedelta(seconds=window)).strftime("%Y-%m-%d %H:%M:%S")
    count = db.execute(
        "SELECT COUNT(*) as cnt FROM verification_codes WHERE ip_address = ? AND created_at > ?",
        (ip, cutoff),
    ).fetchone()
    return count["cnt"] < limit


def _request_is_secure() -> bool:
    if request.is_secure:
        return True
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    return "https" in {part.strip().lower() for part in forwarded_proto.split(",") if part.strip()}


@bp.before_request
def enforce_auth_transport_security():
    if request.path.endswith("/me"):
        return None
    if request.method != "POST":
        return _json_error("Authentication endpoints only accept POST requests", 405)
    if current_app.config.get("FORCE_HTTPS", True) and not _request_is_secure():
        return _json_error("Authentication requires HTTPS (TLS 1.2+).", 403)
    sensitive_query_keys = {"password", "new_password", "current_password"}
    if any(key in request.args for key in sensitive_query_keys):
        return _json_error("Password data in URL parameters is prohibited", 400)
    return None


def login_required(fn: F) -> F:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        if not session.get("user_id"):
            return _json_error("Unauthorized", 401)
        uid = int(session["user_id"])
        db = get_db()
        row = db.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
        if not row or not row["password_hash"]:
            session.clear()
            return _json_error("Unauthorized", 401)
        stored_hash = session.get("password_hash")
        if stored_hash and stored_hash != row["password_hash"]:
            session.clear()
            return _json_error("Session invalidated — password was changed. Please log in again.", 401)
        session["password_hash"] = row["password_hash"]
        return fn(*args, **kwargs)

    return cast(F, wrapper)


def current_user_id() -> int | None:
    uid = session.get("user_id")
    return int(uid) if uid else None


def _user_public(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "username": row["username"],
        "email": row["email"],
        "avatar_color": row["avatar_color"],
        "allocate_url": row["allocate_url"],
        "created_at": row["created_at"],
    }


@bp.get("/me")
def me():
    uid = current_user_id()
    if not uid:
        return _json_error("Unauthorized", 401)
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        session.clear()
        return _json_error("Unauthorized", 401)
    return jsonify(_user_public(row))


@bp.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    name = str(payload.get("name", "")).strip() or username
    email = str(payload.get("email", "")).strip().lower()
    avatar_color = str(payload.get("avatar_color", "")).strip() or "#4361ee"

    if not USERNAME_RE.match(username):
        return _json_error("Invalid username", 400)
    if password.lower() == username.lower():
        return _json_error("Password cannot be the same as username", 400)
    if not PASSWORD_STRENGTH_RE.match(password):
        return _json_error("Password must be at least 8 characters and contain uppercase, lowercase, and special characters", 400)
    if not name:
        return _json_error("Invalid name", 400)
    if not email or "@" not in email:
        return _json_error("Valid email is required", 400)

    password_hash = _hash_password(password)

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)).fetchone():
        return _json_error("Username already exists", 409)
    if db.execute("SELECT 1 FROM users WHERE lower(email) = lower(?)", (email,)).fetchone():
        return _json_error("Email already registered", 409)

    cur = db.execute(
        "INSERT INTO users (name, username, email, password_hash, avatar_color) VALUES (?, ?, ?, ?, ?)",
        (name, username, email, password_hash, avatar_color),
    )
    db.commit()
    uid = cur.lastrowid
    session["user_id"] = uid
    session["password_hash"] = password_hash
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return jsonify(_user_public(row)), 201


@bp.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if not username or not password:
        return _json_error("Missing credentials", 400)

    db = get_db()

    # Check account lockout
    is_locked, remaining = _check_account_lockout(db, username)
    if is_locked:
        return _json_error(f"Account locked. Please wait {remaining} seconds before trying again.", 429)

    # Check IP rate limit
    if not _check_login_rate_limit(db, username):
        return _json_error("Too many login attempts. Please wait a moment and try again.", 429)

    # ORIGINAL
    row = db.execute("SELECT * FROM users WHERE lower(username) = lower(?) ORDER BY id ASC", (username,)).fetchone()

    # MODIFIED FOR SQL INJECTION
    # row = db.executescript(f'SELECT * FROM users WHERE lower(username) = lower("{username}") ORDER BY id ASC').fetchone() # code for SQL Injection

    if not row or not row["password_hash"]:
        return _json_error("Invalid username or password", 401)

    try:
        ok = _verify_password(password, str(row["password_hash"]))
    except Exception:
        ok = False

    if not ok:
        _record_login_failure(db, username)
        return _json_error("Invalid username or password", 401)

    # --- Session fixation protection: regenerate session ID on successful login ---
    session.clear()
    session["user_id"] = int(row["id"])
    session["password_hash"] = row["password_hash"]
    _cleanup_old_login_failures(db)
    
    # Check if password hash needs migration (bcrypt → argon2)
    if _needs_rehash(row["password_hash"]):
        try:
            new_hash = _hash_password(password)
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, int(row["id"])))
            db.commit()
            session["password_hash"] = new_hash
        except Exception:
            pass  # Continue even if migration fails
    
    return jsonify(_user_public(row))


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@bp.post("/change_password")
@login_required
def change_password():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    current_password = str(payload.get("current_password", "")).strip()
    new_password = str(payload.get("new_password", "")).strip()

    if not current_password or not new_password:
        return _json_error("Missing fields", 400)

    db = get_db()
    user_row = db.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
    if user_row and new_password.lower() == user_row["username"].lower():
        return _json_error("Password cannot be the same as username", 400)
    if not PASSWORD_STRENGTH_RE.match(new_password):
        return _json_error("Password must be at least 8 characters and contain uppercase, lowercase, and special characters", 400)

    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
    if not row or not row["password_hash"]:
        return _json_error("Unauthorized", 401)

    ok = False
    try:
        ok = _verify_password(current_password, str(row["password_hash"]))
    except Exception:
        ok = False

    if not ok:
        return _json_error("Invalid password", 401)

    # Check password history (prevent reusing last N passwords)
    if not _check_password_history(db, uid, new_password):
        return _json_error("Password has been used recently. Please choose a different password.", 400)

    password_hash = _hash_password(new_password)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?", (password_hash, now, uid))

    # Save current password to history before updating
    db.execute(
        "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
        (uid, str(row["password_hash"])),
    )

    db.commit()
    session["password_hash"] = password_hash
    return jsonify({"ok": True})


@bp.post("/forgot_password")
def forgot_password():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()

    if not email:
        return _json_error("Missing email", 400)

    db = get_db()

    # Periodic cleanup of old data
    _cleanup_login_failures(db)
    _cleanup_expired_verification_codes(db)

    # IP-based rate limiting for verification codes (prevent single IP from spamming)
    ip = _get_client_ip()
    if not _check_ip_rate_limit(db, ip, FORGOT_PASSWORD_GLOBAL_LIMIT, FORGOT_PASSWORD_GLOBAL_WINDOW):
        return jsonify({"error": "Please wait before requesting another code"}), 429

    last_row = db.execute(
        "SELECT created_at FROM verification_codes WHERE email = lower(?) ORDER BY id DESC LIMIT 1",
        (email,),
    ).fetchone()
    if last_row:
        created = datetime.strptime(last_row["created_at"], "%Y-%m-%d %H:%M:%S")
        elapsed = (datetime.now() - created).total_seconds()
        if elapsed < 60:
            return jsonify({"error": "Please wait 60 seconds before requesting another code"}), 429

    row = db.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (email,)).fetchone()
    if row:
        code = "".join(secrets.choice(string.digits) for _ in range(6))
        expires = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "INSERT INTO verification_codes (email, code, expires_at, ip_address) VALUES (?, ?, ?, ?)",
            (email, code, expires, ip),
        )
        db.commit()
        _send_reset_code_email(email, code)

    # Always return success to prevent email enumeration
    return jsonify({"ok": True})


@bp.post("/reset_password")
def reset_password():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    code = str(payload.get("code", "")).strip()
    new_password = str(payload.get("new_password", "")).strip()

    if not email or not code or not new_password:
        return _json_error("Missing fields", 400)
    if not PASSWORD_STRENGTH_RE.match(new_password):
        return _json_error("Password must be at least 8 characters and contain uppercase, lowercase, and special characters", 400)

    db = get_db()

    # Rate limiting: max 10 attempts per 5 minutes per email
    recent_attempts = db.execute(
        "SELECT COUNT(*) as cnt FROM verification_codes WHERE email = lower(?) AND expires_at > datetime('now') AND used = 0",
        (email,),
    ).fetchone()
    if recent_attempts and recent_attempts["cnt"] >= 10:
        return _json_error("Too many attempts. Please wait 5 minutes before trying again.", 429)

    row = db.execute(
        "SELECT id FROM verification_codes WHERE email = lower(?) AND code = ? AND expires_at > datetime('now') AND used = 0 ORDER BY id DESC LIMIT 1",
        (email, code),
    ).fetchone()
    if not row:
        return _json_error("Invalid or expired code", 400)

    user_row = db.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (email,)).fetchone()
    if not user_row:
        return _json_error("User not found", 404)

    uid = user_row["id"]

    # Check password history
    if not _check_password_history(db, uid, new_password):
        return _json_error("Password has been used recently. Please choose a different password.", 400)

    password_hash = _hash_password(new_password)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?", (password_hash, now, uid))
    db.execute("UPDATE verification_codes SET used = 1 WHERE id = ?", (row["id"],))

    # Save current password to history
    old_row = db.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
    if old_row and old_row["password_hash"]:
        db.execute(
            "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
            (uid, str(old_row["password_hash"])),
        )

    # Invalidate ALL old verification codes for this email (prevent reuse of intercepted codes)
    db.execute("UPDATE verification_codes SET used = 1 WHERE email = lower(?) AND used = 0", (email,))

    # Invalidate the user's reset_token (legacy field, keep in sync)
    db.execute("UPDATE users SET reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?", (uid,))

    db.commit()

    # Invalidate any active session for this user
    session.clear()

    return jsonify({"ok": True})


def _send_reset_code_email(to_email: str, code: str) -> None:
    config = current_app.config
    smtp_host = config.get("SMTP_HOST", "")
    smtp_port = int(config.get("SMTP_PORT", 587))
    smtp_user = config.get("SMTP_USERNAME", "")
    smtp_pass = config.get("SMTP_PASSWORD", "")
    from_name = config.get("SMTP_FROM_NAME", "StudySync")
    from_email = config.get("SMTP_FROM_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        print(f"[StudySync] SMTP not configured. Reset code for {to_email}: {code}")
        return

    msg = MIMEMultipart()
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = "StudySync - Password Reset Code"

    body = f"""
Your StudySync password reset code:

{code}

This code expires in 5 minutes. If you didn't request this, please ignore this email.
"""
    msg.attach(MIMEText(body, "plain"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_email, to_email, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_email, to_email, msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        print(f"[StudySync] SMTPAuthenticationError: {e}")
    except smtplib.SMTPException as e:
        print(f"[StudySync] SMTPException: {e}")
    except Exception as e:
        print(f"[StudySync] Failed to send email to {to_email}: {type(e).__name__}: {e}")
