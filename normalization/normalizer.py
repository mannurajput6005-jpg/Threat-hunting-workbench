"""Common event schema + helpers shared by all parsers.

Rules: unavailable fields stay ``None`` (nothing is invented); every event keeps the
original raw record (JSON) so a finding can always be traced back to its source.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import re
from datetime import datetime, timezone
from typing import Any

from dateutil import parser as dateparser
from pydantic import BaseModel, field_validator

NULL_TOKENS = {"", "-", "(empty)", "n/a", "na", "null", "none", "nan", "(null)", "unknown"}
OUTCOME_FAIL = {"failure", "failed", "fail", "denied", "blocked", "error", "false", "audit failure"}
OUTCOME_OK = {"success", "succeeded", "ok", "allowed", "true", "audit success", "permitted"}
MAX_FIELD_LEN = 8192


def clean(value: Any) -> str | None:
    """Return a stripped string, or None for empty / placeholder values."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    s = str(value).strip()
    if s.lower() in NULL_TOKENS:
        return None
    return s[:MAX_FIELD_LEN]


def to_int(value: Any) -> int | None:
    try:
        s = clean(value)
        return int(float(s)) if s is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def valid_ip(value: Any) -> str | None:
    s = clean(value)
    if s is None:
        return None
    s = s.removeprefix("::ffff:")
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return ntpath.basename(path.replace("/", "\\")) or None


def normalize_outcome(value: Any) -> str | None:
    s = clean(value)
    if s is None:
        return None
    low = s.lower()
    if low in OUTCOME_FAIL:
        return "failure"
    if low in OUTCOME_OK:
        return "success"
    return low


def parse_timestamp(value: Any) -> str | None:
    """Convert many timestamp styles to ISO-8601 UTC ('2024-01-01T12:00:00.000Z').

    Epoch seconds/milliseconds and ISO strings are handled directly. Timestamps with no
    time-zone are ASSUMED to be UTC (documented limitation). Unparseable -> None.
    """
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d{9,13}(\.\d+)?", str(value).strip()):
            num = float(value)
            if num > 1e11:  # milliseconds
                num /= 1000.0
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
        else:
            s = clean(value)
            if s is None:
                return None
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                dt = dateparser.parse(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        if not (1990 <= dt.year <= 2100):
            return None
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError, OSError, dateparser.ParserError):
        return None


class NormalizedEvent(BaseModel):
    timestamp: str | None = None
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    process_name: str | None = None
    process_path: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    event_category: str | None = None
    event_action: str | None = None
    outcome: str | None = None
    event_code: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None
    protocol: str | None = None
    severity: str | None = None
    source_type: str
    source_file: str | None = None
    record_ref: str | None = None

    @field_validator("source_port", "destination_port")
    @classmethod
    def _port(cls, v):
        return v if v is None or 0 <= v <= 65535 else None

    @field_validator("hostname", "domain")
    @classmethod
    def _lower(cls, v):
        return v.lower() if v else v


def build_event(fields: dict[str, Any], raw: dict, *, source_type: str, source_file: str,
                record_ref: str) -> dict:
    """Clean + validate mapped fields and return a dict ready for ``database.insert_events``."""
    f = dict(fields)
    f["timestamp"] = parse_timestamp(f.get("timestamp"))
    f["source_ip"] = valid_ip(f.get("source_ip"))
    f["destination_ip"] = valid_ip(f.get("destination_ip"))
    f["source_port"] = to_int(f.get("source_port"))
    f["destination_port"] = to_int(f.get("destination_port"))
    f["outcome"] = normalize_outcome(f.get("outcome"))
    for key in ("hostname", "username", "process_name", "process_path", "parent_process", "command_line",
                "event_category", "event_action", "event_code", "domain", "url", "file_hash",
                "protocol", "severity"):
        f[key] = clean(f.get(key))
    if f.get("event_code") and f["event_code"].endswith(".0"):
        f["event_code"] = f["event_code"][:-2]
    if f.get("process_path") and not f.get("process_name"):
        f["process_name"] = basename(f["process_path"])
    if f.get("process_name") and ("\\" in f["process_name"] or "/" in f["process_name"]):
        f["process_path"] = f.get("process_path") or f["process_name"]
        f["process_name"] = basename(f["process_name"])
    if f.get("parent_process") and ("\\" in f["parent_process"] or "/" in f["parent_process"]):
        f["parent_process"] = basename(f["parent_process"])
    if f.get("severity"):
        f["severity"] = f["severity"].lower()
    ev = NormalizedEvent(source_type=source_type, source_file=source_file, record_ref=record_ref,
                         **{k: v for k, v in f.items() if k in NormalizedEvent.model_fields}).model_dump()
    raw_json = json.dumps(raw, default=str, sort_keys=True, ensure_ascii=False)
    ev["raw_event"] = raw_json
    # Hash excludes file name / line number so re-importing the same file is detected as duplicate.
    ev["event_hash"] = hashlib.sha256(f"{source_type}|{raw_json}".encode("utf-8")).hexdigest()
    return ev


# --------------------------------------------------------------------------- field access helpers
def flatten(obj: Any, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict[str, Any]:
    """Flatten nested dicts into dotted keys. Lists of scalars are kept as lists."""
    out = {} if out is None else out
    if isinstance(obj, dict) and depth < 6:
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list) and any(isinstance(i, (dict, list)) for i in obj) and depth < 6:
        for i, v in enumerate(obj[:50]):
            flatten(v, f"{prefix}.{i}", out, depth + 1)
    else:
        out[prefix] = obj
    return out


class FieldView:
    """Case-insensitive lookup over a raw record. Tries full dotted keys, then leaf names."""

    def __init__(self, raw: dict):
        self.flat = flatten(raw)
        self.full = {k.lower(): v for k, v in self.flat.items()}
        self.leaf: dict[str, Any] = {}
        for k, v in self.flat.items():
            self.leaf.setdefault(k.rsplit(".", 1)[-1].lower(), v)

    def get(self, *names: str) -> Any:
        for table in (self.full, self.leaf):
            for n in names:
                v = table.get(n.lower())
                if clean(v) is not None:
                    return v
        return None

    def has(self, *names: str) -> bool:
        return any(n.lower() in self.leaf or n.lower() in self.full for n in names)


def strip_domain(user: str | None) -> str | None:
    """'CORP\\jdoe' -> 'jdoe' (the full value stays in raw_event)."""
    if not user:
        return user
    return user.split("\\")[-1] or user
