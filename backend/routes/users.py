from __future__ import annotations

from flask import Blueprint, jsonify

from backend.auth import login_required
from backend.db import get_db


bp = Blueprint("users", __name__, url_prefix="/api/users")


@bp.get("")
@login_required
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, name, username, avatar_color, allocate_url, created_at FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])

