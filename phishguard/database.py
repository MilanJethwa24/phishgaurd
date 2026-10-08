"""SQLite helper: creates database/phishguard.db and stores scans (parameterized queries only)."""
import os
import sqlite3
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "phishguard.db")


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL,
                input_text TEXT NOT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ml_score REAL NOT NULL,
                keyword_score REAL NOT NULL,
                url_score REAL NOT NULL,
                warnings TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )


def save_scan(input_type, input_text, result):
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO scans (input_type, input_text, classification, risk_score,
               ml_score, keyword_score, url_score, warnings, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                input_type,
                input_text,
                result["classification"],
                result["risk_score"],
                result["ml_score"],
                result["keyword_score"],
                result["url_score"],
                json.dumps(result["warnings"]),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        return cur.lastrowid


def _row_to_dict(row):
    d = dict(row)
    try:
        d["warnings"] = json.loads(d["warnings"])
    except (ValueError, TypeError):
        d["warnings"] = []
    return d


def get_scan(scan_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_dict(row) if row else None


def get_history(limit=200):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_stats():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        counts = {}
        for label in ("High Risk", "Suspicious", "Low Risk"):
            counts[label] = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE classification = ?", (label,)
            ).fetchone()[0]
        emails = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE input_type = ?", ("email",)
        ).fetchone()[0]
        urls = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE input_type = ?", ("url",)
        ).fetchone()[0]
        avg = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
    return {
        "total": total,
        "high": counts["High Risk"],
        "suspicious": counts["Suspicious"],
        "low": counts["Low Risk"],
        "emails": emails,
        "urls": urls,
        "avg_risk": round(avg, 1),
    }
