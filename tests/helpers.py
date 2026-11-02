"""Shared test helpers (temporary database, quick ingestion)."""
import contextlib
import tempfile
from pathlib import Path

from core import database as db
from detection.rule_loader import sync_rules
from ingestion.parser import parse_file

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
ADMIN = {"user_id": 1, "username": "admin", "role": "admin"}
ANALYST = {"user_id": 2, "username": "ana", "role": "analyst"}
VIEWER = {"user_id": 3, "username": "vic", "role": "viewer"}


@contextlib.contextmanager
def temp_db(with_rules=True):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.db"
        db.init_db(path)
        with db.get_conn(path) as conn:
            for u in (ADMIN, ANALYST, VIEWER):
                conn.execute("INSERT INTO users (user_id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                             (u["user_id"], u["username"], "x", u["role"], db.now_iso()))
            if with_rules:
                sync_rules(conn)
            yield conn


def ingest(conn, filename, data=None, source="auto"):
    data = (SAMPLES / filename).read_bytes() if data is None else data
    res = parse_file(data, filename, source)
    db.insert_events(conn, res.events)
    return res
