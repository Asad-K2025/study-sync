from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    DB_PATH = os.environ.get("DB_PATH", str(project_root() / "studysync.db"))
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", str(project_root() / "uploads"))
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))
    FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "1") == "1"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True

    # SMTP configuration (set via environment variables)
    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "StudySync")
    SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", SMTP_USERNAME)

    # Argon2 password hashing configuration (OWASP recommended)
    ARGON2_TIME_COST = int(os.environ.get("ARGON2_TIME_COST", "3"))
    ARGON2_MEMORY_COST = int(os.environ.get("ARGON2_MEMORY_COST", "65536"))
    ARGON2_PARALLELISM = int(os.environ.get("ARGON2_PARALLELISM", "4"))
    ARGON2_HASH_LEN = int(os.environ.get("ARGON2_HASH_LEN", "32"))
    ARGON2_SALT_LEN = int(os.environ.get("ARGON2_SALT_LEN", "16"))
