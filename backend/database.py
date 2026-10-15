import json
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("PHISH_DB_PATH", "./data/phish_scan_history.db"))


def get_db_path():
    return DB_PATH


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                submitted_summary TEXT NOT NULL,
                sender TEXT,
                url TEXT,
                raw_result TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan(record):
    submitted = record.get("submitted", {})
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans (created_at, analysis_type, risk_score, risk_level, submitted_summary, sender, url, raw_result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["created_at"],
                record["analysis_type"],
                int(record["risk_score"]),
                record["risk_level"],
                json.dumps(submitted, ensure_ascii=False),
                submitted.get("sender_email") or submitted.get("url"),
                submitted.get("url") or None,
                json.dumps(record, ensure_ascii=False),
            ),
        )
        conn.commit()


def get_all_scans():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def delete_scan(scan_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()


def get_dashboard_metrics():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) AS total FROM scans").fetchone()["total"]
        high_risk = conn.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_score >= 60").fetchone()["total"]
        medium_risk = conn.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_score BETWEEN 30 AND 59").fetchone()["total"]
        low_risk = conn.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_score BETWEEN 0 AND 29").fetchone()["total"]
        recent = conn.execute(
            "SELECT id, created_at, analysis_type, risk_score, risk_level FROM scans ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
        distribution = conn.execute(
            "SELECT risk_level, COUNT(*) AS total FROM scans GROUP BY risk_level ORDER BY total DESC"
        ).fetchall()
        indicators = conn.execute("SELECT raw_result FROM scans").fetchall()
    return {
        "total": total,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "recent_scans": [dict(row) for row in recent],
        "risk_distribution": [dict(row) for row in distribution],
        "indicator_summary": _summarize_indicators(indicators),
    }


def _summarize_indicators(raw_results):
    summaries = {}
    for row in raw_results:
        data = json.loads(row["raw_result"])
        for indicator in data.get("indicators", []):
            name = indicator.get("name", "Unknown")
            summaries[name] = summaries.get(name, 0) + 1
    return sorted(summaries.items(), key=lambda item: (-item[1], item[0]))[:8]
