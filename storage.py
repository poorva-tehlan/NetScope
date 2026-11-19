"""Small local packet database; no raw packet payloads are saved."""
import sqlite3
from pathlib import Path
DB = Path(__file__).resolve().parent / "data" / "packets.sqlite3"
SCHEMA = """CREATE TABLE IF NOT EXISTS packets (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 timestamp TEXT NOT NULL, source TEXT, destination TEXT,
 protocol TEXT, source_port INTEGER, destination_port INTEGER,
 length INTEGER, summary TEXT, hostname TEXT, service TEXT, evidence TEXT
)"""
def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB), timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute(SCHEMA)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(packets)")}
    for col in ("hostname", "service", "evidence"):
        if col not in cols:
            conn.execute(f"ALTER TABLE packets ADD COLUMN {col} TEXT")
    conn.commit()
    return conn
