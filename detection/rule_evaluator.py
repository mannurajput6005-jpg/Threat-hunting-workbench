"""Pure rule evaluation (no database access) - easy to unit test."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from core.database import EVENT_COLUMNS

OPERATORS = {"equals", "not_equals", "in", "not_in", "contains", "contains_any", "startswith",
             "endswith", "regex", "exists", "not_exists", "gt", "gte", "lt", "lte"}
VALID_FIELDS = set(EVENT_COLUMNS)
MAX_REGEX_LEN = 500
MAX_EVAL_LEN = 8192


class RuleError(ValueError):
    pass


def _s(v: Any) -> str:
    return "" if v is None else str(v).lower()[:MAX_EVAL_LEN]


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


@dataclass
class Condition:
    field: str
    op: str
    value: Any
    test: Callable[[Any], bool] = field(repr=False, default=lambda v: False)

    def describe(self) -> dict:
        return {"field": self.field, "op": self.op, "expected": self.value}


def compile_condition(raw: dict) -> Condition:
    if not isinstance(raw, dict) or "field" not in raw or "op" not in raw:
        raise RuleError(f"condition needs 'field' and 'op': {raw!r}")
    f, op, val = raw["field"], raw["op"], raw.get("value")
    if f not in VALID_FIELDS:
        raise RuleError(f"unknown field '{f}'")
    if op not in OPERATORS:
        raise RuleError(f"unknown operator '{op}'")
    if op not in ("exists", "not_exists") and val is None:
        raise RuleError(f"operator '{op}' needs a value")
    if op in ("in", "not_in", "contains_any") and not isinstance(val, list):
        raise RuleError(f"operator '{op}' needs a list value")

    if op == "equals":
        t = lambda v: v is not None and _s(v) == _s(val)
    elif op == "not_equals":
        t = lambda v: v is not None and _s(v) != _s(val)
    elif op == "in":
        s = {_s(x) for x in val}
        t = lambda v: v is not None and _s(v) in s
    elif op == "not_in":
        s = {_s(x) for x in val}
        t = lambda v: v is not None and _s(v) not in s
    elif op == "contains":
        t = lambda v: v is not None and _s(val) in _s(v)
    elif op == "contains_any":
        s = [_s(x) for x in val]
        t = lambda v: v is not None and any(x in _s(v) for x in s)
    elif op == "startswith":
        t = lambda v: v is not None and _s(v).startswith(_s(val))
    elif op == "endswith":
        t = lambda v: v is not None and _s(v).endswith(_s(val))
    elif op == "regex":
        if len(str(val)) > MAX_REGEX_LEN:
            raise RuleError("regex too long")
        try:
            rx = re.compile(str(val), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"invalid regex: {exc}") from exc
        t = lambda v: v is not None and rx.search(str(v)[:MAX_EVAL_LEN]) is not None
    elif op == "exists":
        t = lambda v: v is not None and str(v) != ""
    elif op == "not_exists":
        t = lambda v: v is None or str(v) == ""
    else:  # numeric comparisons
        n = _num(val)
        if n is None:
            raise RuleError(f"operator '{op}' needs a numeric value")
        cmp = {"gt": lambda a: a > n, "gte": lambda a: a >= n, "lt": lambda a: a < n, "lte": lambda a: a <= n}[op]
        t = lambda v: (_num(v) is not None) and cmp(_num(v))
    return Condition(f, op, val, t)


@dataclass
class CompiledRule:
    rule_id: str
    name: str
    description: str
    severity: str
    type: str  # 'match' | 'threshold'
    all_of: list[Condition]
    any_of: list[Condition]
    threshold: dict | None
    mitre: list[str]
    raw: dict

    def evaluate(self, event: dict) -> list[dict] | None:
        """Return the matched-evidence list if the event satisfies the rule's conditions, else None."""
        evidence = []
        for c in self.all_of:
            if not c.test(event.get(c.field)):
                return None
            evidence.append({**c.describe(), "actual": event.get(c.field)})
        if self.any_of:
            hit = next((c for c in self.any_of if c.test(event.get(c.field))), None)
            if hit is None:
                return None
            evidence.append({**hit.describe(), "actual": event.get(hit.field)})
        return evidence


def compile_rule(rule: dict) -> CompiledRule:
    for key in ("id", "name", "severity", "type"):
        if not rule.get(key):
            raise RuleError(f"rule missing '{key}'")
    if rule["type"] not in ("match", "threshold"):
        raise RuleError(f"rule {rule['id']}: type must be 'match' or 'threshold'")
    all_of = [compile_condition(c) for c in rule.get("match", [])]
    any_of = [compile_condition(c) for c in rule.get("match_any", [])]
    if not all_of and not any_of:
        raise RuleError(f"rule {rule['id']}: needs 'match' and/or 'match_any' conditions")
    th = rule.get("threshold")
    if rule["type"] == "threshold":
        if not isinstance(th, dict) or not th.get("count") or not th.get("window_seconds"):
            raise RuleError(f"rule {rule['id']}: threshold needs 'count' and 'window_seconds'")
        bad = [g for g in th.get("group_by", []) + ([th["distinct_field"]] if th.get("distinct_field") else [])
               if g not in VALID_FIELDS]
        if bad:
            raise RuleError(f"rule {rule['id']}: unknown threshold field(s) {bad}")
    mitre = rule.get("mitre") or []
    return CompiledRule(rule["id"], rule["name"], rule.get("description", ""), rule["severity"].lower(),
                        rule["type"], all_of, any_of, th, list(mitre), rule)


def _ts(e: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) if e.get("timestamp") else None
    except ValueError:
        return None


def evaluate_threshold(events: list[dict], th: dict) -> list[dict]:
    """Find (non-overlapping) windows where an event count - or distinct-value count - reaches the threshold.

    ``events`` must already satisfy the rule's match conditions. Events lacking a timestamp or a
    group-by value are skipped (we never guess them).
    Returns [{"group": {...}, "events": [event,...], "measure": int}].
    """
    group_by = th.get("group_by", [])
    distinct = th.get("distinct_field")
    count, window = int(th["count"]), int(th["window_seconds"])
    groups: dict[tuple, list[tuple[datetime, dict]]] = {}
    for e in events:
        t = _ts(e)
        key = tuple(e.get(g) for g in group_by)
        if t is None or any(k is None for k in key):
            continue
        groups.setdefault(key, []).append((t, e))
    findings = []
    for key, items in groups.items():
        items.sort(key=lambda x: (x[0], x[1]["event_id"]))
        n, i = len(items), 0
        while i < n:
            j = i
            while j + 1 < n and (items[j + 1][0] - items[i][0]).total_seconds() <= window:
                j += 1
            win = [e for _, e in items[i:j + 1]]
            measure = len({e.get(distinct) for e in win if e.get(distinct) is not None}) if distinct else len(win)
            if measure >= count:
                findings.append({"group": dict(zip(group_by, key)), "events": win, "measure": measure})
                i = j + 1
            else:
                i += 1
    return findings
