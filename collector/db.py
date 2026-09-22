"""Small transactional SQLite store; report history and alert state survive restarts."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Database:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY,
                    fingerprint TEXT NOT NULL UNIQUE,
                    device_id TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    report TEXT NOT NULL,
                    evaluation TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS reports_device_time
                    ON reports(device_id, collected_at DESC, id DESC);
                CREATE TABLE IF NOT EXISTS alerts (
                    device_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    sent_at REAL NOT NULL
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, fingerprint, report, evaluation, received_at):
        with self.connect() as db:
            cursor = db.execute(
                "INSERT OR IGNORE INTO reports "
                "(fingerprint,device_id,collected_at,received_at,report,evaluation) VALUES (?,?,?,?,?,?)",
                (
                    fingerprint,
                    report["device_id"],
                    report["collected_at"],
                    received_at,
                    json.dumps(report),
                    json.dumps(evaluation),
                ),
            )
            inserted = cursor.rowcount == 1
            row = db.execute(
                "SELECT id FROM reports WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            latest = db.execute(
                "SELECT id FROM reports WHERE device_id=? ORDER BY collected_at DESC,id DESC LIMIT 1",
                (report["device_id"],),
            ).fetchone()[0]
            return row[0], inserted, row[0] == latest

    @staticmethod
    def decode(row):
        return {
            "report_id": row["id"],
            "received_at": row["received_at"],
            "report": json.loads(row["report"]),
            "evaluation": json.loads(row["evaluation"]),
        }

    def latest(self):
        with self.connect() as db:
            rows = db.execute("""
                SELECT * FROM (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY device_id ORDER BY collected_at DESC,id DESC
                    ) AS rank FROM reports
                ) WHERE rank=1 ORDER BY device_id
            """).fetchall()
            return [self.decode(row) for row in rows]

    def history(self, device_id, limit=50):
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM reports WHERE device_id=? ORDER BY collected_at DESC,id DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
            return [self.decode(row) for row in rows]
