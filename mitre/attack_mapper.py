"""MITRE ATT&CK reference lookups. Data lives in techniques.json (local, offline)."""
from __future__ import annotations

import json
from functools import lru_cache

from core import database as db
from core.config import MITRE_PATH


@lru_cache(maxsize=1)
def load_techniques() -> dict[str, dict]:
    return json.loads(MITRE_PATH.read_text(encoding="utf-8"))["techniques"]


def describe(technique_id: str) -> dict:
    t = load_techniques().get(technique_id)
    if t:
        return {"id": technique_id, **t}
    return {"id": technique_id, "name": "(not in local reference file)", "tactics": [], "description": "",
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"}


def techniques_for_rule_ids(mitre_field: str | None) -> list[dict]:
    if not mitre_field:
        return []
    return [describe(t.strip()) for t in mitre_field.split(",") if t.strip()]


def coverage(conn) -> list[dict]:
    """One row per (technique, rule): which rules relate to it and how many alerts fired."""
    out = []
    for r in db.rows(conn, "SELECT rule_id, rule_name, mitre_technique_id, enabled FROM detection_rules "
                           "WHERE mitre_technique_id IS NOT NULL"):
        n_alerts = db.scalar(conn, "SELECT COUNT(*) FROM alerts WHERE rule_id=?", (r["rule_id"],))
        for t in techniques_for_rule_ids(r["mitre_technique_id"]):
            out.append({"technique_id": t["id"], "technique": t["name"], "tactics": ", ".join(t["tactics"]),
                        "rule_id": r["rule_id"], "rule_name": r["rule_name"],
                        "rule_enabled": bool(r["enabled"]), "alerts": n_alerts})
    return out
