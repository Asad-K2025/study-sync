from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.auth import current_user_id, login_required
from backend.db import get_db


bp = Blueprint("meetings", __name__, url_prefix="/api")


def _json_error(message: str, status: int):
    return jsonify({"error": message}), status


def _require_group_member(db, group_id: int, user_id: int) -> bool:
    row = db.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()
    return row is not None


@bp.get("/meetings")
@login_required
def list_meetings():
    uid = current_user_id()
    gid_str = request.args.get("group_id", "").strip()

    db = get_db()
    if gid_str:
        if not gid_str.isdigit():
            return _json_error("Invalid group_id", 400)
        gid = int(gid_str)
        if not _require_group_member(db, gid, uid):
            return _json_error("Forbidden", 403)
        meetings = db.execute(
            """
            SELECT m.*, g.name AS gname, g.color AS gcolor
            FROM meetings m
            JOIN groups g ON g.id = m.group_id
            WHERE m.group_id = ?
            ORDER BY m.id ASC
            """,
            (gid,),
        ).fetchall()
    else:
        meetings = db.execute(
            """
            SELECT m.*, g.name AS gname, g.color AS gcolor
            FROM meetings m
            JOIN groups g ON g.id = m.group_id
            JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = ?
            ORDER BY m.id ASC
            """,
            (uid,),
        ).fetchall()

    result = []
    for m in meetings:
        mtg = dict(m)
        member_count = db.execute(
            "SELECT COUNT(DISTINCT user_id) FROM group_members WHERE group_id = ?",
            (mtg["group_id"],),
        ).fetchone()[0]

        slots = db.execute(
            "SELECT * FROM meeting_time_slots WHERE meeting_id = ? ORDER BY id",
            (mtg["id"],),
        ).fetchall()
        slot_list = []
        for s in slots:
            vote_count = db.execute(
                """
                SELECT COUNT(DISTINCT mv.user_id)
                FROM meeting_votes mv
                JOIN group_members gm ON gm.user_id = mv.user_id AND gm.group_id = ?
                WHERE mv.slot_id = ? AND mv.available = 1
                """,
                (mtg["group_id"], s["id"]),
            ).fetchone()[0]
            my_vote_row = db.execute(
                "SELECT available FROM meeting_votes WHERE slot_id = ? AND user_id = ?",
                (s["id"], uid),
            ).fetchone()
            my_vote = None if my_vote_row is None else int(my_vote_row["available"])
            slot_list.append({**dict(s), "vote_count": vote_count, "my_vote": my_vote})

        mtg["member_count"] = int(member_count)
        mtg["slots"] = slot_list
        result.append(mtg)

    return jsonify(result)


@bp.post("/meetings")
@login_required
def create_meeting():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    try:
        gid = int(payload.get("group_id"))
    except Exception:
        return _json_error("Missing group_id", 400)
    if gid <= 0:
        return _json_error("Invalid group_id", 400)

    title = str(payload.get("title", "")).strip()
    description = str(payload.get("description", "")).strip()
    slots = payload.get("slots", [])
    if not title:
        return _json_error("Please enter a meeting title", 400)
    if not isinstance(slots, list) or not slots:
        return _json_error("Add at least one time slot", 400)

    db = get_db()
    if not db.execute("SELECT 1 FROM groups WHERE id = ?", (gid,)).fetchone():
        return _json_error("Not found", 404)
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    cur = db.execute(
        "INSERT INTO meetings (group_id, title, description, created_by) VALUES (?, ?, ?, ?)",
        (gid, title, description, uid),
    )
    mid = cur.lastrowid
    for s in slots:
        day = str(s.get("day", "")).strip()
        time = str(s.get("time", "")).strip()
        if not day or not time:
            continue
        db.execute(
            "INSERT INTO meeting_time_slots (meeting_id, day, time) VALUES (?, ?, ?)",
            (mid, day, time),
        )

    msg = f'📅 New meeting poll created: "{title}" — please vote on your availability!'
    db.execute(
        "INSERT INTO messages (group_id, user_id, content) VALUES (?, ?, ?)",
        (gid, uid, msg),
    )

    db.commit()
    return jsonify({"id": mid, "status": "created"}), 201


@bp.post("/vote")
@login_required
def vote():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    try:
        slot_id = int(payload.get("slot_id"))
    except Exception:
        return _json_error("Missing slot_id", 400)
    try:
        available = int(payload.get("available", 1))
    except Exception:
        available = 1
    available = 1 if available else 0

    db = get_db()
    row = db.execute(
        """
        SELECT s.id AS slot_id, m.group_id
        FROM meeting_time_slots s
        JOIN meetings m ON m.id = s.meeting_id
        WHERE s.id = ?
        """,
        (slot_id,),
    ).fetchone()
    if not row:
        return _json_error("Not found", 404)
    gid = int(row["group_id"])
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    db.execute(
        """
        INSERT INTO meeting_votes (slot_id, user_id, available)
        VALUES (?, ?, ?)
        ON CONFLICT(slot_id, user_id) DO UPDATE SET available = excluded.available
        """,
        (slot_id, uid, available),
    )
    db.commit()
    vote_count = db.execute(
        """
        SELECT COUNT(DISTINCT mv.user_id)
        FROM meeting_votes mv
        JOIN group_members gm ON gm.user_id = mv.user_id AND gm.group_id = ?
        WHERE mv.slot_id = ? AND mv.available = 1
        """,
        (gid, slot_id),
    ).fetchone()[0]
    return jsonify({"vote_count": int(vote_count), "my_vote": available})


@bp.post("/meetings/<int:meeting_id>/complete")
@login_required
def complete_meeting(meeting_id: int):
    uid = current_user_id()
    db = get_db()
    row = db.execute("SELECT id, group_id, status FROM meetings WHERE id = ?", (meeting_id,)).fetchone()
    if not row:
        return _json_error("Not found", 404)
    gid = int(row["group_id"])
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    db.execute("UPDATE meetings SET status = 'completed' WHERE id = ?", (meeting_id,))
    db.commit()
    return jsonify({"ok": True, "id": int(meeting_id), "status": "completed"})
