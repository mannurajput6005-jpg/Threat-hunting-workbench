"""Load YAML rules from disk, validate them and sync them into the database."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from core import database as db
from core.config import RULES_DIR
from core.logging_config import get_logger
from detection.rule_evaluator import CompiledRule, RuleError, compile_rule
from detection.severity import SEVERITIES

log = get_logger(__name__)

# Built-in rule used by the IOC matcher so IOC alerts live in the same alerts table.
IOC_RULE = {
    "id": "IOC-001", "name": "Indicator of Compromise match", "severity": "high", "type": "ioc_match",
    "description": "An observed IP, domain, URL or file hash exactly matches the local IOC watchlist.",
    "mitre": [], "enabled": True,
    "caution": "Check indicator confidence, freshness and context before treating as malicious.",
}


def load_rule_files(rules_dir: Path | None = None) -> tuple[list[dict], list[str]]:
    """Return (valid rule dicts, error messages). One bad rule never blocks the others."""
    rules, errors = [], []
    seen: set[str] = set()
    for path in sorted(Path(rules_dir or RULES_DIR).glob("*.y*ml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: invalid YAML ({exc})")
            continue
        for raw in doc.get("rules", []):
            try:
                if raw.get("severity", "").lower() not in SEVERITIES:
                    raise RuleError(f"severity must be one of {SEVERITIES}")
                compile_rule(raw)
                if raw["id"] in seen:
                    raise RuleError("duplicate rule id")
                seen.add(raw["id"])
                raw["source_file"] = path.name
                rules.append(raw)
            except (RuleError, AttributeError, KeyError) as exc:
                errors.append(f"{path.name}: rule {raw.get('id', '?') if isinstance(raw, dict) else '?'}: {exc}")
    return rules, errors


def sync_rules(conn, rules_dir: Path | None = None) -> tuple[int, list[str]]:
    """Upsert file rules into detection_rules. Keeps an analyst's enable/disable choice."""
    rules, errors = load_rule_files(rules_dir)
    for r in [*rules, IOC_RULE]:
        existing = db.one(conn, "SELECT enabled FROM detection_rules WHERE rule_id=?", (r["id"],))
        enabled = existing["enabled"] if existing else int(r.get("enabled", True))
        conn.execute(
            "INSERT INTO detection_rules (rule_id, rule_name, description, rule_logic, severity, mitre_technique_id, enabled, source_file)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET rule_name=excluded.rule_name,"
            " description=excluded.description, rule_logic=excluded.rule_logic, severity=excluded.severity,"
            " mitre_technique_id=excluded.mitre_technique_id, source_file=excluded.source_file",
            (r["id"], r["name"], r.get("description", ""), json.dumps(r), r["severity"].lower(),
             ",".join(r.get("mitre", [])) or None, enabled, r.get("source_file", "builtin")))
    return len(rules), errors


def load_enabled_rules(conn) -> list[CompiledRule]:
    out = []
    for row in db.rows(conn, "SELECT rule_logic FROM detection_rules WHERE enabled=1"):
        logic = json.loads(row["rule_logic"])
        if logic.get("type") == "ioc_match":
            continue
        try:
            out.append(compile_rule(logic))
        except RuleError as exc:
            log.warning("Skipping invalid stored rule %s: %s", logic.get("id"), exc)
    return out
