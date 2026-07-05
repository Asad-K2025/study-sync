from __future__ import annotations
import json
from flask import Blueprint, jsonify, request
from backend.auth import current_user_id, login_required
from backend.db import get_db

bp = Blueprint("e2ee", __name__, url_prefix="/api/e2ee")


def _json_error(msg: str, status: int):
    return jsonify({"error": msg}), status


def _require_group_member(db, group_id: int, user_id: int) -> bool:
    return db.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone() is not None


@bp.post("/public_key")
@login_required
def upload_public_key():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    jwk = payload.get("public_key")
    if not jwk:
        return _json_error("Missing public_key", 400)
    db = get_db()
    db.execute("UPDATE users SET public_key = ? WHERE id = ?", (json.dumps(jwk), uid))
    db.commit()
    return jsonify({"ok": True})


@bp.get("/public_keys")
@login_required
def get_public_keys():
    """Fetch public keys for a comma-separated list of user IDs."""
    user_ids_str = request.args.get("user_ids", "")
    user_ids = [int(x) for x in user_ids_str.split(",") if x.strip().isdigit()]
    if not user_ids:
        return _json_error("Missing user_ids", 400)
    db = get_db()
    result = {}
    for uid_target in user_ids:
        row = db.execute("SELECT public_key FROM users WHERE id = ?", (uid_target,)).fetchone()
        if row and row["public_key"]:
            result[str(uid_target)] = json.loads(row["public_key"])
    return jsonify(result)


@bp.post("/group_key")
@login_required
def store_group_key():
    """Store one member's encrypted copy of the group key."""
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    try:
        group_id = int(payload["group_id"])
        target_user_id = int(payload["user_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Missing group_id or user_id", 400)
    encrypted_key = payload.get("encrypted_key")
    if not encrypted_key:
        return _json_error("Missing encrypted_key", 400)

    db = get_db()
    if not _require_group_member(db, group_id, uid):
        return _json_error("Forbidden", 403)

    db.execute(
        """INSERT OR REPLACE INTO group_keys (group_id, user_id, encrypted_key, distributed_by)
           VALUES (?, ?, ?, ?)""",
        (group_id, target_user_id, json.dumps(encrypted_key), uid),
    )
    db.commit()
    return jsonify({"ok": True})


@bp.get("/group_key/<int:group_id>")
@login_required
def get_group_key(group_id: int):
    """Return this user's encrypted group key plus the distributor's public key."""
    uid = current_user_id()
    db = get_db()
    if not _require_group_member(db, group_id, uid):
        return _json_error("Forbidden", 403)

    row = db.execute(
        "SELECT encrypted_key, distributed_by FROM group_keys WHERE group_id = ? AND user_id = ?",
        (group_id, uid),
    ).fetchone()

    if not row:
        return jsonify({"found": False})

    dist_by = int(row["distributed_by"])
    dist_row = db.execute("SELECT public_key FROM users WHERE id = ?", (dist_by,)).fetchone()
    distributor_pub = json.loads(dist_row["public_key"]) if dist_row and dist_row["public_key"] else None

    return jsonify({
        "found": True,
        "encrypted_key": json.loads(row["encrypted_key"]),
        "distributed_by": dist_by,
        "distributor_public_key": distributor_pub,
    })