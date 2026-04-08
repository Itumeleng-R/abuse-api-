"""
database.py — SQLite setup and all query functions.
The database is a single file at data/reports.db — no server needed.
"""

import sqlite3
import os
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "reports.db")


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # lets us access columns by name
    return conn


def init_db() -> None:
    """Create tables if they don't exist yet."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ip_reports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address    TEXT    NOT NULL,
            category      INTEGER NOT NULL,
            comment       TEXT,
            reporter_ip   TEXT    DEFAULT '127.0.0.1',
            reported_at   TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_ip ON ip_reports(ip_address);
        CREATE INDEX IF NOT EXISTS idx_reported_at ON ip_reports(reported_at);

        CREATE TABLE IF NOT EXISTS ip_metadata (
            ip_address    TEXT PRIMARY KEY,
            country_code  TEXT DEFAULT 'ZZ',
            isp           TEXT DEFAULT 'Unknown ISP',
            usage_type    TEXT DEFAULT 'Unknown',
            domain        TEXT DEFAULT 'unknown',
            is_tor        INTEGER DEFAULT 0,
            is_whitelisted INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


def insert_report(
    ip: str,
    category: int,
    comment: str,
    reporter_ip: str = "127.0.0.1",
) -> int:
    """Insert one abuse report. Returns the new row id."""
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO ip_reports (ip_address, category, comment, reporter_ip, reported_at)
           VALUES (?, ?, ?, ?, ?)""",
        (ip, category, comment, reporter_ip, datetime.utcnow().isoformat())
    )
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_reports(ip: str, max_age_days: int = 90) -> list:
    """Return all reports for an IP within the time window."""
    cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat()
    conn   = get_connection()
    rows   = conn.execute(
        """SELECT * FROM ip_reports
           WHERE ip_address = ? AND reported_at >= ?
           ORDER BY reported_at DESC""",
        (ip, cutoff)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_metadata(ip: str) -> Optional[dict]:
    conn = get_connection()
    row  = conn.execute(
        "SELECT * FROM ip_metadata WHERE ip_address = ?", (ip,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_metadata(ip: str, **kwargs) -> None:
    """Insert or update metadata for an IP (country, ISP, etc.)."""
    conn = get_connection()
    existing = conn.execute(
        "SELECT ip_address FROM ip_metadata WHERE ip_address = ?", (ip,)
    ).fetchone()

    if existing:
        fields = ", ".join(f"{k} = ?" for k in kwargs)
        conn.execute(
            f"UPDATE ip_metadata SET {fields} WHERE ip_address = ?",
            (*kwargs.values(), ip)
        )
    else:
        cols = "ip_address, " + ", ".join(kwargs.keys())
        placeholders = ", ".join("?" for _ in range(len(kwargs) + 1))
        conn.execute(
            f"INSERT INTO ip_metadata ({cols}) VALUES ({placeholders})",
            (ip, *kwargs.values())
        )
    conn.commit()
    conn.close()


def compute_confidence(reports: list) -> int:
    """
    Calculate an abuse confidence score (0-100) from report history.
    More reports + more distinct reporters = higher score.
    """
    if not reports:
        return 0

    total    = len(reports)
    distinct = len(set(r["reporter_ip"] for r in reports))

    # Base score from report volume (caps at 60)
    volume_score = min(total * 3, 60)

    # Diversity bonus — multiple independent reporters is strong signal
    diversity_bonus = min(distinct * 5, 40)

    return min(volume_score + diversity_bonus, 100)