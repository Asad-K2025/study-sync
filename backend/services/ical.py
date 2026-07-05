from __future__ import annotations

from datetime import datetime, timedelta


def _unfold_lines(text: str) -> list[str]:
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    unfolded: list[str] = []
    for line in lines:
        if not line:
            continue
        if (line.startswith(" ") or line.startswith("\t")) and unfolded:
            unfolded[-1] += line.lstrip()
        else:
            unfolded.append(line.strip())
    return unfolded


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    v = value.strip().replace("Z", "")
    try:
        if "T" in v:
            return datetime.strptime(v, "%Y%m%dT%H%M%S")
        return datetime.strptime(v, "%Y%m%d")
    except Exception:
        return None


def _to_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _parse_rrule(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not value:
        return out
    for part in value.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.upper().strip()] = v.strip()
    return out


BYDAY_MAP = {"SU": 0, "MO": 1, "TU": 2, "WE": 3, "TH": 4, "FR": 5, "SA": 6}


def parse_ical(ical_text: str, max_expand: int = 200) -> list[dict[str, str]]:
    raw_events: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for line in _unfold_lines(ical_text):
        if line == "BEGIN:VEVENT":
            cur = {}
            continue
        if line == "END:VEVENT":
            if cur is not None and "DTSTART" in cur:
                raw_events.append(cur)
            cur = None
            continue
        if cur is None:
            continue
        if ":" not in line:
            continue
        key_full, value = line.split(":", 1)
        base_key = key_full.split(";", 1)[0].upper().strip()
        cur[base_key] = value.strip()

    out: list[dict[str, str]] = []

    for ev in raw_events:
        title = (ev.get("SUMMARY") or "Class").replace("\\,", ",").replace("\\n", " ").strip()
        location = (ev.get("LOCATION") or "").replace("\\,", ",").strip()
        start_dt = _parse_dt(ev.get("DTSTART", ""))
        end_dt = _parse_dt(ev.get("DTEND", "")) or start_dt
        if not start_dt:
            continue
        duration = (end_dt - start_dt) if end_dt else timedelta(hours=1)
        rrule = _parse_rrule(ev.get("RRULE", ""))

        if not rrule or rrule.get("FREQ") != "WEEKLY":
            out.append(
                {"title": title, "start_dt": _to_iso(start_dt), "end_dt": _to_iso(end_dt or start_dt), "location": location}
            )
            continue

        interval = int(rrule.get("INTERVAL", "1") or "1")
        count = int(rrule.get("COUNT", "0") or "0") or None
        until_dt = _parse_dt(rrule.get("UNTIL", "")) if rrule.get("UNTIL") else None
        if until_dt is None:
            until_dt = start_dt + timedelta(weeks=26)

        byday = rrule.get("BYDAY", "")
        bydays = [d.strip().upper() for d in byday.split(",") if d.strip()] if byday else []

        emitted = 0

        def emit_series(base_date: datetime) -> None:
            nonlocal emitted
            cursor = base_date
            while cursor <= until_dt and (count is None or emitted < count) and emitted < max_expand:
                s = cursor
                e = cursor + duration
                out.append({"title": title, "start_dt": _to_iso(s), "end_dt": _to_iso(e), "location": location})
                cursor = cursor + timedelta(days=7 * interval)
                emitted += 1

        if bydays:
            base_week_start = start_dt - timedelta(days=start_dt.weekday())
            for code in bydays:
                if code not in BYDAY_MAP:
                    continue
                target_wd = BYDAY_MAP[code]
                candidate = base_week_start + timedelta(days=target_wd)
                candidate = candidate.replace(hour=start_dt.hour, minute=start_dt.minute, second=start_dt.second)
                if candidate < start_dt:
                    candidate = candidate + timedelta(days=7 * interval)
                emit_series(candidate)
        else:
            emit_series(start_dt)

    out.sort(key=lambda e: e.get("start_dt") or "")
    return out
