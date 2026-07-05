from __future__ import annotations

import urllib.request

from flask import Blueprint, jsonify, request

from backend.auth import current_user_id, login_required
from backend.db import get_db
from backend.services.ical import parse_ical


bp = Blueprint("calendar", __name__, url_prefix="/api")


def _json_error(message: str, status: int):
    return jsonify({"error": message}), status


@bp.get("/calendar")
@login_required
def get_calendar():
    uid = current_user_id()
    db = get_db()
    events = db.execute(
        "SELECT * FROM calendar_events WHERE user_id = ? ORDER BY start_dt",
        (uid,),
    ).fetchall()
    user = db.execute("SELECT allocate_url FROM users WHERE id = ?", (uid,)).fetchone()
    return jsonify({"events": [dict(e) for e in events], "allocate_url": user["allocate_url"] if user else None})


@bp.post("/sync_allocate")
@login_required
def sync_allocate():
    uid = current_user_id()
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    ical_text = str(payload.get("ical_text", "")).strip()

    if not ical_text:
        if not url:
            return _json_error("Please provide an iCal URL or raw iCal text", 400)
        if url.startswith("webcal://"):
            url = "https://" + url[len("webcal://") :]
        if not (url.startswith("http://") or url.startswith("https://")):
            return _json_error("Invalid URL", 400)

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "StudySync/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                ical_text = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return _json_error(f"Failed to fetch calendar: {e}", 400)

    events = parse_ical(ical_text)

    db = get_db()
    if url:
        db.execute("UPDATE users SET allocate_url = ? WHERE id = ?", (url, uid))
    db.execute("DELETE FROM calendar_events WHERE user_id = ? AND source = 'allocate'", (uid,))
    for ev in events:
        db.execute(
            """
            INSERT INTO calendar_events (user_id, title, start_dt, end_dt, location, source)
            VALUES (?, ?, ?, ?, ?, 'allocate')
            """,
            (uid, ev["title"], ev["start_dt"], ev["end_dt"], ev.get("location", "")),
        )
    db.commit()

    return jsonify({"imported": len(events), "url": url or None})


@bp.post("/calendar/allocate/clear")
@login_required
def clear_allocate():
    uid = current_user_id()
    db = get_db()
    db.execute("UPDATE users SET allocate_url = NULL WHERE id = ?", (uid,))
    cur = db.execute("DELETE FROM calendar_events WHERE user_id = ? AND source = 'allocate'", (uid,))
    db.commit()
    return jsonify({"ok": True, "deleted": cur.rowcount})
