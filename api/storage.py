"""Transactional application metadata; analytical artifacts stay on disk."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS imports (
                    import_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    manifest TEXT NOT NULL,
                    directory TEXT NOT NULL,
                    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    run_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    bundle_path TEXT NOT NULL,
                    PRIMARY KEY (run_id, incident_id)
                );
                CREATE TABLE IF NOT EXISTS reports (
                    cache_key TEXT PRIMARY KEY,
                    report TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_filters (
                    run_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS filter_lookup
                    ON incident_filters(run_id,kind,value,incident_id);
            """)
            columns = {r[1] for r in db.execute("PRAGMA table_info(imports)")}
            for name in ["processed_bytes", "total_bytes"]:
                if name not in columns:
                    db.execute(f"ALTER TABLE imports ADD COLUMN {name} INTEGER DEFAULT 0")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA temp_store=FILE")
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()
