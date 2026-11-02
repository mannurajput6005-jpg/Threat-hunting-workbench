"""Investigation (case) management. All writes check permissions and are audited."""
from __future__ import annotations

from core import database as db
from core.authentication import authorize
from detection.severity import SEVERITIES

STATUSES = ["New", "In Progress", "Under Review", "Resolved", "Closed"]
VERDICTS = ["Undetermined", "False Positive", "True Positive (Confirmed Incident)"]


def create_case(conn, actor: dict, title: str, description: str = "", severity: str = "medium") -> int:
    authorize(actor, "case_write")
    title = (title or "").strip()
    if not title:
        raise ValueError("Title is required.")
    if severity not in SEVERITIES:
        raise ValueError("Invalid severity.")
    now = db.now_iso()
    cur = conn.execute(
        "INSERT INTO investigations (title, description, severity, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)",
        (title[:200], description[:5000], severity, actor["user_id"], now, now))
    db.audit(conn, actor, "case_create", "investigation", cur.lastrowid, title[:200])
    return cur.lastrowid


def _touch(conn, case_id: int) -> None:
    conn.execute("UPDATE investigations SET updated_at=? WHERE investigation_id=?", (db.now_iso(), case_id))


def _system_note(conn, actor: dict, case_id: int, text: str) -> None:
    conn.execute("INSERT INTO investigation_notes (investigation_id, user_id, note, is_system, created_at) VALUES (?,?,?,1,?)",
                 (case_id, actor["user_id"], text, db.now_iso()))


def update_case(conn, actor: dict, case_id: int, *, status=None, severity=None, verdict=None,
                conclusion=None) -> None:
    authorize(actor, "case_write")
    case = get_case(conn, case_id)
    if not case:
        raise ValueError("Case not found.")
    checks = {"status": (status, STATUSES), "severity": (severity, SEVERITIES), "verdict": (verdict, VERDICTS)}
    for name, (val, allowed) in checks.items():
        if val is not None and val not in allowed:
            raise ValueError(f"Invalid {name}.")
        if val is not None and val != case[name]:
            conn.execute(f"UPDATE investigations SET {name}=? WHERE investigation_id=?", (val, case_id))  # name from fixed dict
            _system_note(conn, actor, case_id, f"{name.capitalize()} changed: {case[name]} -> {val}")
            db.audit(conn, actor, f"case_{name}", "investigation", case_id, f"{case[name]} -> {val}")
    if conclusion is not None and conclusion != (case["conclusion"] or ""):
        conn.execute("UPDATE investigations SET conclusion=? WHERE investigation_id=?", (conclusion[:5000], case_id))
        _system_note(conn, actor, case_id, "Conclusion updated")
        db.audit(conn, actor, "case_conclusion", "investigation", case_id)
    _touch(conn, case_id)


def add_note(conn, actor: dict, case_id: int, note: str) -> None:
    authorize(actor, "case_write")
    note = (note or "").strip()
    if not note:
        raise ValueError("Note is empty.")
    if not get_case(conn, case_id):
        raise ValueError("Case not found.")
    conn.execute("INSERT INTO investigation_notes (investigation_id, user_id, note, created_at) VALUES (?,?,?,?)",
                 (case_id, actor["user_id"], note[:5000], db.now_iso()))
    _touch(conn, case_id)
    db.audit(conn, actor, "case_note", "investigation", case_id)


def list_cases(conn, actor: dict, status: str | None = None) -> list[dict]:
    authorize(actor, "read")
    sql = ("SELECT i.*, u.username AS created_by_name, "
           "(SELECT COUNT(*) FROM investigation_alerts WHERE investigation_id=i.investigation_id) AS alerts, "
           "(SELECT COUNT(*) FROM investigation_events WHERE investigation_id=i.investigation_id) AS events "
           "FROM investigations i LEFT JOIN users u ON u.user_id=i.created_by")
    if status:
        return db.rows(conn, sql + " WHERE i.status=? ORDER BY i.updated_at DESC", (status,))
    return db.rows(conn, sql + " ORDER BY i.updated_at DESC")


def get_case(conn, case_id: int) -> dict | None:
    return db.one(conn, "SELECT * FROM investigations WHERE investigation_id=?", (case_id,))


def get_notes(conn, case_id: int) -> list[dict]:
    return db.rows(conn, "SELECT n.*, u.username FROM investigation_notes n LEFT JOIN users u ON u.user_id=n.user_id "
                         "WHERE n.investigation_id=? ORDER BY n.created_at, n.note_id", (case_id,))
