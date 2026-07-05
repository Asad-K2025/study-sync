from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.auth import current_user_id, login_required
from backend.db import get_db


bp = Blueprint("announcements", __name__, url_prefix="/api")


def _json_error(message: str, status: int):
    return jsonify({"error": message}), status


def _require_group_member(db, group_id: int, user_id: int) -> bool:
    row = db.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()
    return row is not None


def _get_announcement_row(db, announcement_id: int):
    return db.execute(
        """
        SELECT a.*, u.name AS author_name, u.username AS author_username, u.avatar_color AS author_color
        FROM announcements a
        JOIN users u ON u.id = a.user_id
        WHERE a.id = ?
        """,
        (announcement_id,),
    ).fetchone()


@bp.get("/announcements")
@login_required
def list_announcements():
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
        SELECT
          a.id, a.group_id, a.user_id, a.content, a.created_at, a.updated_at,
          u.name AS author_name, u.username AS author_username, u.avatar_color AS author_color,
          CASE WHEN ar.user_id IS NULL THEN 0 ELSE 1 END AS read_by_me
        FROM announcements a
        JOIN users u ON u.id = a.user_id
        LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
        WHERE a.group_id = ?
        ORDER BY a.created_at DESC, a.id DESC
        """,
        (uid, gid),
    ).fetchall()

    announcements: list[dict] = []
    unread_count = 0
    for r in rows:
        d = dict(r)
        is_mine = int(d["user_id"]) == int(uid)
        read_by_me = bool(d.get("read_by_me")) or is_mine
        if not read_by_me:
            unread_count += 1
        d["read_by_me"] = read_by_me
        d["can_edit"] = is_mine
        announcements.append(d)

    return jsonify({"unread_count": int(unread_count), "announcements": announcements})


@bp.post("/announcements")
@login_required
def create_announcement():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    try:
        gid = int(payload.get("group_id"))
    except Exception:
        return _json_error("Missing group_id", 400)
    content = str(payload.get("content", "")).strip()
    if not content:
        return _json_error("Empty announcement", 400)
    if len(content) > 4000:
        return _json_error("Announcement is too long", 400)

    db = get_db()
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    cur = db.execute(
        "INSERT INTO announcements (group_id, user_id, content) VALUES (?, ?, ?)",
        (gid, uid, content),
    )
    ann_id = int(cur.lastrowid)
    db.execute(
        "INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id) VALUES (?, ?)",
        (ann_id, uid),
    )
    db.commit()

    row = _get_announcement_row(db, ann_id)
    if not row:
        return _json_error("Not found", 404)
    d = dict(row)
    d["read_by_me"] = True
    d["can_edit"] = True
    return jsonify(d), 201


@bp.put("/announcements/<int:announcement_id>")
@login_required
def update_announcement(announcement_id: int):
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    content = str(payload.get("content", "")).strip()
    if not content:
        return _json_error("Empty announcement", 400)
    if len(content) > 4000:
        return _json_error("Announcement is too long", 400)

    db = get_db()
    row = db.execute("SELECT * FROM announcements WHERE id = ?", (announcement_id,)).fetchone()
    if not row:
        return _json_error("Not found", 404)
    gid = int(row["group_id"])
    owner_id = int(row["user_id"])
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)
    if owner_id != int(uid):
        return _json_error("Forbidden", 403)

    db.execute(
        "UPDATE announcements SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (content, announcement_id),
    )
    db.execute(
        "DELETE FROM announcement_reads WHERE announcement_id = ? AND user_id != ?",
        (announcement_id, uid),
    )
    db.execute(
        "INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id) VALUES (?, ?)",
        (announcement_id, uid),
    )
    db.commit()

    out = _get_announcement_row(db, announcement_id)
    if not out:
        return _json_error("Not found", 404)
    d = dict(out)
    d["read_by_me"] = True
    d["can_edit"] = True
    return jsonify(d)


@bp.delete("/announcements/<int:announcement_id>")
@login_required
def delete_announcement(announcement_id: int):
    uid = current_user_id()
    db = get_db()
    row = db.execute("SELECT * FROM announcements WHERE id = ?", (announcement_id,)).fetchone()
    if not row:
        return _json_error("Not found", 404)
    gid = int(row["group_id"])
    owner_id = int(row["user_id"])
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)
    if owner_id != int(uid):
        return _json_error("Forbidden", 403)

    db.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,))
    db.commit()
    return jsonify({"ok": True})


@bp.post("/announcements/<int:announcement_id>/read")
@login_required
def mark_read(announcement_id: int):
    uid = current_user_id()
    db = get_db()
    row = db.execute("SELECT id, group_id, user_id FROM announcements WHERE id = ?", (announcement_id,)).fetchone()
    if not row:
        return _json_error("Not found", 404)
    gid = int(row["group_id"])
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)
    db.execute(
        "INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id) VALUES (?, ?)",
        (announcement_id, uid),
    )
    db.commit()
    return jsonify({"ok": True})


@bp.post("/announcements/read_all")
@login_required
def mark_all_read():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    try:
        gid = int(payload.get("group_id"))
    except Exception:
        return _json_error("Missing group_id", 400)

    db = get_db()
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    db.execute(
        """
        INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id)
        SELECT a.id, ?
        FROM announcements a
        WHERE a.group_id = ?
        """,
        (uid, gid),
    )
    db.commit()
    return jsonify({"ok": True})

