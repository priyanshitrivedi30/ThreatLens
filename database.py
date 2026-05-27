"""
ThreatLens — SQLite persistence layer
Replaces full-file JSONL parsing on every request with indexed queries.
"""

import sqlite3
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

DB_PATH  = Path(__file__).parent / "logs" / "threatlens.db"
LOG_FILE = Path(__file__).parent / "logs" / "sessions.jsonl"

_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """Return a thread-local connection (create + init if needed)."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return _local.conn


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Create tables and indexes on first run."""
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            event      TEXT    NOT NULL,
            src_ip     TEXT,
            src_port   INTEGER,
            username   TEXT,
            password   TEXT,
            method     TEXT,
            client_ver TEXT,
            country    TEXT,
            city       TEXT,
            asn        TEXT,
            latitude   REAL,
            longitude  REAL,
            logged_at  TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_event    ON events(event);
        CREATE INDEX IF NOT EXISTS idx_src_ip   ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_logged_at ON events(logged_at);

        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT    NOT NULL,
            attempts   INTEGER NOT NULL,
            country    TEXT,
            fired_at   TEXT    NOT NULL,
            notified   INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS ingest_cursor (
            id       INTEGER PRIMARY KEY CHECK (id = 1),
            position INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO ingest_cursor (id, position) VALUES (1, 0);
        """)


def _cursor_pos() -> int:
    with db() as conn:
        row = conn.execute("SELECT position FROM ingest_cursor WHERE id=1").fetchone()
        return row["position"] if row else 0


def _set_cursor(pos: int):
    with db() as conn:
        conn.execute("UPDATE ingest_cursor SET position=? WHERE id=1", (pos,))


def ingest_new_lines():
    """
    Read only NEW lines from sessions.jsonl (tracked by byte offset),
    insert into SQLite, and advance the cursor.  Called by the background
    watcher — O(new lines), never re-parses old data.
    """
    if not LOG_FILE.exists():
        return 0

    pos = _cursor_pos()
    inserted = 0

    with open(LOG_FILE, "rb") as f:
        f.seek(pos)
        new_lines = f.read()
        new_pos   = f.tell()

    if not new_lines:
        return 0

    rows = []
    for raw in new_lines.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
        except Exception:
            continue

        rows.append((
            e.get("event"),
            e.get("src_ip"),
            e.get("src_port"),
            e.get("username"),
            e.get("password"),
            e.get("method"),
            e.get("client_version"),
            e.get("country"),
            e.get("city"),
            e.get("asn"),
            e.get("latitude"),
            e.get("longitude"),
            e.get("logged_at", datetime.now(timezone.utc).isoformat()),
        ))

    if rows:
        with db() as conn:
            conn.executemany("""
                INSERT INTO events
                    (event, src_ip, src_port, username, password,
                     method, client_ver, country, city, asn,
                     latitude, longitude, logged_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, rows)
            inserted = len(rows)
        _set_cursor(new_pos)

    return inserted


# ── Query helpers used by main.py ─────────────────────────────────────────────

def get_stats(threshold: int = 5) -> dict:
    """Fast aggregated stats from indexed SQLite — no full file scan."""
    with db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE event='auth_attempt'"
        ).fetchone()[0]

        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM events WHERE event='auth_attempt'"
        ).fetchone()[0]

        ip_rows = conn.execute("""
            SELECT src_ip, COUNT(*) as attempts,
                   MAX(country) as country, MAX(city) as city,
                   MAX(latitude) as latitude, MAX(longitude) as longitude
            FROM events
            WHERE event='auth_attempt' AND src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY attempts DESC
        """).fetchall()

        user_rows = conn.execute("""
            SELECT username, COUNT(*) as cnt
            FROM events
            WHERE event='auth_attempt' AND username IS NOT NULL
            GROUP BY username
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

        timeline_rows = conn.execute("""
            SELECT CAST(substr(logged_at, 12, 2) AS INTEGER) as hr,
                   COUNT(*) as cnt
            FROM events
            WHERE event='auth_attempt'
            GROUP BY hr
        """).fetchall()

    timeline = [0] * 24
    for r in timeline_rows:
        if 0 <= r["hr"] <= 23:
            timeline[r["hr"]] = r["cnt"]

    ips = []
    for r in ip_rows:
        att = r["attempts"]
        status = "CRITICAL" if att >= 20 else "FLAGGED" if att >= threshold else "NORMAL"
        ips.append({
            "ip":        r["src_ip"],
            "attempts":  att,
            "country":   r["country"] or "??",
            "city":      r["city"]    or "",
            "latitude":  r["latitude"],
            "longitude": r["longitude"],
            "status":    status,
        })

    return {
        "ips":           ips,
        "usernames":     [{"name": r["username"], "count": r["cnt"]} for r in user_rows],
        "timeline":      timeline,
        "total_events":  total,
        "unique_ips":    unique_ips,
        "flagged_count": sum(1 for i in ips if i["status"] != "NORMAL"),
        "threshold":     threshold,
        "source":        "ThreatLens SQLite DB",
        "scanned_at":    datetime.now().isoformat(),
    }


def get_unfired_alerts(threshold: int = 20) -> list[dict]:
    """IPs that crossed CRITICAL threshold and haven't been alerted yet."""
    with db() as conn:
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) as attempts,
                   MAX(country) as country
            FROM events
            WHERE event='auth_attempt'
            GROUP BY src_ip
            HAVING attempts >= ?
              AND src_ip NOT IN (SELECT ip FROM alerts)
            ORDER BY attempts DESC
        """, (threshold,)).fetchall()
    return [dict(r) for r in rows]


def mark_alerted(ip: str, attempts: int, country: str | None):
    with db() as conn:
        conn.execute(
            "INSERT INTO alerts (ip, attempts, country, fired_at, notified) VALUES (?,?,?,?,1)",
            (ip, attempts, country, datetime.now(timezone.utc).isoformat()),
        )
