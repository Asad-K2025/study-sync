from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.auth import current_user_id, login_required
from backend.db import get_db


bp = Blueprint("groups", __name__, url_prefix="/api")


def _json_error(message: str, status: int):
    return jsonify({"error": message}), status


def _require_group_member(db, group_id: int, user_id: int) -> bool:
    row = db.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()
    return row is not None


@bp.get("/groups")
@login_required
def list_groups():
    uid = current_user_id()
    db = get_db()
    rows = db.execute(
        """
        SELECT g.*, COUNT(DISTINCT gm2.user_id) AS member_count
        FROM groups g
        JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = ?
        LEFT JOIN group_members gm2 ON gm2.group_id = g.id
        GROUP BY g.id
        ORDER BY g.id
        """,
        (uid,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.post("/groups")
@login_required
def create_group():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    color = str(payload.get("color", "")).strip() or "#4361ee"
    members = payload.get("members", [])
    description = str(payload.get("description", "")).strip()
    if not name:
        return _json_error("Please enter a group name", 400)
    if not isinstance(members, list):
        return _json_error("Invalid members list", 400)

    db = get_db()
    cur = db.execute("INSERT INTO groups (name, color, description) VALUES (?, ?, ?)", (name, color, description))
    gid = cur.lastrowid
    db.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (gid, uid))
    for mid in members:
        try:
            mid_int = int(mid)
        except Exception:
            continue
        if mid_int == uid:
            continue
        db.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
            (gid, mid_int),
        )
    db.commit()
    row = db.execute("SELECT * FROM groups WHERE id = ?", (gid,)).fetchone()
    return jsonify(dict(row)), 201


@bp.get("/group_members")
@login_required
def group_members():
    uid = current_user_id()
    gid_str = request.args.get("group_id", "").strip()
    if not gid_str.isdigit():
        return _json_error("Missing group_id", 400)
    gid = int(gid_str)

    db = get_db()
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    rows = db.execute(
        """
        SELECT u.id, u.name, u.username, u.avatar_color
        FROM users u
        JOIN group_members gm ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY u.id
        """,
        (gid,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.delete("/groups/<int:group_id>/leave")
@login_required
def leave_group(group_id: int):
    uid = current_user_id()
    db = get_db()
    
    # Check if user is a member of the group
    if not _require_group_member(db, group_id, uid):
        return _json_error("You are not a member of this group", 403)
    
    # Remove user from the group
    cur = db.execute(
        "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, uid)
    )
    
    if cur.rowcount == 0:
        return _json_error("Failed to leave group", 500)
    
    # If no more members, delete the group
    member_count = db.execute(
        "SELECT COUNT(*) as count FROM group_members WHERE group_id = ?",
        (group_id,)
    ).fetchone()["count"]
    
    if member_count == 0:
        # Clean up group-related data
        db.execute("DELETE FROM meetings WHERE group_id = ?", (group_id,))
        db.execute("DELETE FROM announcements WHERE group_id = ?", (group_id,))
        db.execute("DELETE FROM messages WHERE group_id = ?", (group_id,))
        db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    
    db.commit()
    return jsonify({"success": True, "deleted_group": member_count == 0})

