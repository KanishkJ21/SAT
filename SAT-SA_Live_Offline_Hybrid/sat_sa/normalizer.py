import hashlib
from datetime import datetime, timezone

ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "event_time", "date"],
    "host": ["host", "hostname", "computer", "asset_code", "entity_code", "machine"],
    "source": ["source", "log_source", "channel", "provider"],
    "event_code": ["event_code", "eventid", "event_id", "alert_id", "code"],
    "level": ["level", "severity", "priority", "status"],
    "category": ["category", "alert_category", "type", "investigation_type"],
    "username": ["username", "user", "account", "investigator"],
    "message": [
        "message", "description", "event_message", "investigation_summary",
        "root_cause", "details"
    ],
}

def _value(row, names):
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        if name in lowered:
            v = lowered[name]
            if v is not None and str(v).strip() != "":
                return str(v)
    return ""

def parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            import pandas as pd
            dt = pd.to_datetime(text, utc=True).to_pydatetime()
        except Exception:
            return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def normalize(row, source_hint="CSV/JSON"):
    timestamp = parse_timestamp(_value(row, ALIASES["timestamp"]))
    host = _value(row, ALIASES["host"]) or "Unknown"
    source = _value(row, ALIASES["source"]) or source_hint
    event_code = _value(row, ALIASES["event_code"]) or "N/A"
    level = _value(row, ALIASES["level"]) or "INFO"
    category = _value(row, ALIASES["category"]) or "General"
    username = _value(row, ALIASES["username"])
    message = _value(row, ALIASES["message"]) or "No message supplied"
    raw = dict(row)
    seed = "|".join([timestamp.isoformat(), host, source, event_code, username, message])
    uid = hashlib.sha256(seed.encode("utf-8", "ignore")).hexdigest()
    return {
        "event_uid": uid,
        "timestamp": timestamp.isoformat(),
        "host": host,
        "source": source,
        "event_code": event_code,
        "level": level.upper(),
        "category": category,
        "username": username,
        "message": message,
        "raw": raw,
    }
