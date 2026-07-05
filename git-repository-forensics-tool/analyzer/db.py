from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable


DB_PATH = Path("database/findings.db")


def init_db(db_path: Path = DB_PATH) -> None:
    """Create SQLite findings table if it does not exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                repo_name TEXT,
                scan_date TEXT,
                commit_hash TEXT,
                author_name TEXT,
                author_email TEXT,
                commit_date TEXT,
                file_path TEXT,
                finding_type TEXT,
                evidence TEXT,
                risk_score INTEGER,
                severity TEXT,
                recommendation TEXT
            )
            """
        )
        conn.commit()


def save_findings(
    case_id: str,
    repo_name: str,
    scan_date: str,
    findings: Iterable[dict],
    db_path: Path = DB_PATH,
) -> None:
    """Save findings to SQLite."""
    init_db(db_path)
    rows = []
    for f in findings:
        rows.append(
            (
                case_id,
                repo_name,
                scan_date,
                f.get("commit_hash", ""),
                f.get("author_name", ""),
                f.get("author_email", ""),
                f.get("commit_date", ""),
                f.get("file_path", ""),
                f.get("finding_type", ""),
                f.get("evidence", ""),
                int(f.get("risk_score", 0)),
                f.get("severity", ""),
                f.get("recommendation", ""),
            )
        )

    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO findings (
                case_id, repo_name, scan_date, commit_hash, author_name,
                author_email, commit_date, file_path, finding_type, evidence,
                risk_score, severity, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
