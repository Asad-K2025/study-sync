from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from backend.auth import current_user_id, login_required
from backend.db import get_db


bp = Blueprint("messages", __name__, url_prefix="/api/messages")


def _json_error(message: str, status: int):
    return jsonify({"error": message}), status


def _require_group_member(db, group_id: int, user_id: int) -> bool:
    row = db.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()
    return row is not None


def _attachments_by_message_id(db, message_ids: list[int]) -> dict[int, list[dict]]:
    if not message_ids:
        return {}
    qmarks = ",".join(["?"] * len(message_ids))
    rows = db.execute(
        f"""
        SELECT id, message_id, filename, mime, size
        FROM message_attachments
        WHERE message_id IN ({qmarks})
        ORDER BY id ASC
        """,
        tuple(message_ids),
    ).fetchall()
    out: dict[int, list[dict]] = {}
    for r in rows:
        mid = int(r["message_id"])
        out.setdefault(mid, []).append(dict(r))
    return out


@bp.get("")
@login_required
def list_messages():
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
        SELECT m.*, u.name AS uname, u.avatar_color AS ucolor
        FROM messages m
        JOIN users u ON u.id = m.user_id
        WHERE m.group_id = ?
        ORDER BY m.created_at ASC
        """,
        (gid,),
    ).fetchall()
    msgs = [dict(r) for r in rows]
    att_map = _attachments_by_message_id(get_db(), [int(m["id"]) for m in msgs])
    for m in msgs:
        m["attachments"] = att_map.get(int(m["id"]), [])
    return jsonify(msgs)


@bp.post("")
@login_required
def create_message():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    try:
        gid = int(payload.get("group_id"))
    except Exception:
        return _json_error("Missing group_id", 400)
    content = str(payload.get("content", "")).strip()
    if not content:
        return _json_error("Empty message", 400)

    db = get_db()
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    cur = db.execute(
        "INSERT INTO messages (group_id, user_id, content) VALUES (?, ?, ?)",
        (gid, uid, content),
    )
    db.commit()
    row = db.execute(
        """
        SELECT m.*, u.name AS uname, u.avatar_color AS ucolor
        FROM messages m
        JOIN users u ON u.id = m.user_id
        WHERE m.id = ?
        """,
        (cur.lastrowid,),
    ).fetchone()
    out = dict(row)
    out["attachments"] = []
    return jsonify(out), 201


@bp.post("/upload")
@login_required
def upload_message():
    uid = current_user_id()
    gid_str = str(request.form.get("group_id", "")).strip()
    if not gid_str.isdigit():
        return _json_error("Missing group_id", 400)
    gid = int(gid_str)
    content = str(request.form.get("content", "")).strip()
    files = request.files.getlist("files")
    files = [f for f in files if f and getattr(f, "filename", "")]
    if not content and not files:
        return _json_error("Empty message", 400)

    db = get_db()
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    upload_dir = Path(str(current_app.config.get("UPLOAD_DIR", ""))).expanduser()
    if not str(upload_dir):
        return _json_error("Upload directory is not configured", 500)
    upload_dir.mkdir(parents=True, exist_ok=True)

    cur = db.execute(
        "INSERT INTO messages (group_id, user_id, content) VALUES (?, ?, ?)",
        (gid, uid, content or ""),
    )
    mid = int(cur.lastrowid)

    att_rows: list[dict] = []
    for f in files:
        orig = secure_filename(str(f.filename))
        if not orig:
            orig = "file"
        storage_name = f"{uuid4().hex}_{orig}"[:190]
        path = upload_dir / storage_name
        f.save(path)
        size = path.stat().st_size
        mime = str(getattr(f, "mimetype", "") or "")
        a_cur = db.execute(
            """
            INSERT INTO message_attachments (message_id, group_id, user_id, filename, mime, size, storage_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (mid, gid, uid, orig, mime, int(size), storage_name),
        )
        att_rows.append(
            {"id": int(a_cur.lastrowid), "message_id": mid, "filename": orig, "mime": mime, "size": int(size)}
        )

    db.commit()
    row = db.execute(
        """
        SELECT m.*, u.name AS uname, u.avatar_color AS ucolor
        FROM messages m
        JOIN users u ON u.id = m.user_id
        WHERE m.id = ?
        """,
        (mid,),
    ).fetchone()
    out = dict(row)
    out["attachments"] = att_rows
    return jsonify(out), 201


@bp.get("/files/<int:attachment_id>")
@login_required
def get_attachment_file(attachment_id: int):
    uid = current_user_id()
    db = get_db()
    row = db.execute(
        """
        SELECT a.id, a.group_id, a.filename, a.mime, a.storage_name
        FROM message_attachments a
        WHERE a.id = ?
        """,
        (attachment_id,),
    ).fetchone()
    if not row:
        return _json_error("Not found", 404)
    gid = int(row["group_id"])
    if not _require_group_member(db, gid, uid):
        return _json_error("Forbidden", 403)

    upload_dir = Path(str(current_app.config.get("UPLOAD_DIR", ""))).expanduser()
    path = upload_dir / str(row["storage_name"])
    if not path.exists() or not path.is_file():
        return _json_error("Not found", 404)

    as_download = str(request.args.get("download", "")).strip() == "1"
    return send_file(
        path,
        mimetype=str(row["mime"] or None),
        as_attachment=as_download,
        download_name=str(row["filename"] or "file"),
        conditional=True,
        max_age=0,
    )
