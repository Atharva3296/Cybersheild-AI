import sqlite3
from pathlib import Path
from datetime import datetime
import hashlib

DB_PATH = Path(__file__).parent / "cybershield.db"

def connect():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    with connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT NOT NULL,
                source TEXT,
                risk_level TEXT,
                anomaly_score REAL,
                reason TEXT
            )
        """)
        # Demo-only account. Change this password before any real deployment.
        con.execute(
            "INSERT OR IGNORE INTO users(username, password_hash) VALUES (?, ?)",
            ("admin", hash_password("ChangeMe123!"))
        )

def verify_login(username: str, password: str) -> bool:
    with connect() as con:
        row = con.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    return bool(row and row[0] == hash_password(password))

def save_alerts(results):
    now = datetime.now().isoformat(timespec="seconds")
    rows = []
    for _, r in results.iterrows():
        if r["classification"] == "Suspicious":
            rows.append((
                now, str(r.get("source", "sample")),
                str(r["risk_level"]), float(r["anomaly_score"]),
                str(r["reason"])
            ))
    if rows:
        with connect() as con:
            con.executemany("""
                INSERT INTO alerts(detected_at, source, risk_level, anomaly_score, reason)
                VALUES (?, ?, ?, ?, ?)
            """, rows)

def get_alerts(limit=200):
    with connect() as con:
        return con.execute("""
            SELECT detected_at, source, risk_level, anomaly_score, reason
            FROM alerts ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
