import json
import sqlite3
from sat_sa.config import DB_PATH

def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = connect()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_uid TEXT UNIQUE,
        timestamp TEXT NOT NULL,
        host TEXT,
        source TEXT,
        event_code TEXT,
        level TEXT,
        category TEXT,
        username TEXT,
        message TEXT,
        raw_json TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT UNIQUE,
        created_at TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        rationale TEXT,
        evidence_ids TEXT,
        status TEXT DEFAULT 'Open'
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT
    );
    ''')
    con.commit()
    con.close()

def insert_event(event):
    con = connect()
    cur = con.execute(
        '''INSERT OR IGNORE INTO events
        (event_uid,timestamp,host,source,event_code,level,category,username,message,raw_json)
        VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (
            event["event_uid"], event["timestamp"], event["host"], event["source"],
            event["event_code"], event["level"], event["category"],
            event["username"], event["message"], json.dumps(event.get("raw", {}), default=str)
        )
    )
    con.commit()
    rowid = cur.lastrowid if cur.rowcount else None
    con.close()
    return rowid

def recent_events(limit=200):
    con = connect()
    rows = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]

def events_by_ids(ids):
    if not ids:
        return []
    con = connect()
    q = ",".join("?" for _ in ids)
    rows = con.execute(f"SELECT * FROM events WHERE id IN ({q}) ORDER BY id", ids).fetchall()
    con.close()
    return [dict(r) for r in rows]

def count_events():
    con = connect()
    n = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    con.close()
    return n

def insert_finding(finding):
    con = connect()
    con.execute(
        '''INSERT OR IGNORE INTO findings
        (fingerprint,created_at,finding_type,severity,title,rationale,evidence_ids,status)
        VALUES (?,?,?,?,?,?,?,?)''',
        (
            finding["fingerprint"], finding["created_at"], finding["finding_type"],
            finding["severity"], finding["title"], finding["rationale"],
            json.dumps(finding["evidence_ids"]), "Open"
        )
    )
    con.commit()
    con.close()

def get_findings():
    con = connect()
    rows = con.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
    con.close()
    return [dict(r) for r in rows]

def set_finding_status(finding_id, status):
    con = connect()
    con.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
    con.commit()
    con.close()

def audit(action, details=""):
    con = connect()
    con.execute(
        "INSERT INTO audit_log(timestamp,action,details) VALUES(?,?,?)",
        (__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), action, details)
    )
    con.commit()
    con.close()

def clear_data():
    con = connect()
    con.executescript("DELETE FROM events; DELETE FROM findings; DELETE FROM audit_log;")
    con.commit()
    con.close()
