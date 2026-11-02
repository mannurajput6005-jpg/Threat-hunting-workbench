"""Ingestion entry point: validate -> decode -> read -> detect source -> map -> normalize."""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field

from core.config import ALLOWED_EXTENSIONS, MAX_RECORDS_PER_FILE, MAX_UPLOAD_MB
from ingestion.csv_parser import map_generic, read_csv
from ingestion.json_parser import read_json
from ingestion.suricata_parser import map_suricata
from ingestion.sysmon_parser import map_sysmon, map_windows, read_windows_xml
from ingestion.zeek_parser import is_zeek_tsv, map_zeek, read_zeek_tsv
from normalization.normalizer import FieldView, build_event, clean

SOURCE_TYPES = ["auto", "sysmon", "windows_event", "zeek", "suricata", "csv", "json"]
MAX_ERRORS_KEPT = 200

SYSMON_KEYS = ("image", "parentimage", "utctime", "processguid", "queryname", "targetfilename",
               "destinationip", "hashes")
WINDOWS_KEYS = ("targetusername", "subjectusername", "logontype", "ipaddress", "newprocessname",
                "workstationname", "servicename", "imagepath")


class IngestionError(Exception):
    """File-level problem (bad extension, too large, undecodable...)."""


@dataclass
class ParseResult:
    filename: str
    events: list[dict] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (record_ref, message)
    total_records: int = 0
    error_count: int = 0
    source_types: Counter = field(default_factory=Counter)
    truncated: bool = False


def decode_bytes(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestionError("File is not valid UTF-8 or UTF-16 text.") from exc


def detect_record_type(raw: dict, container: str) -> str:
    """Decide the source type of one record from its field names."""
    v = FieldView(raw)
    if v.has("uid") and v.has("id.orig_h", "orig_h"):
        return "zeek"
    if v.has("event_type") and v.has("src_ip", "flow_id"):
        return "suricata"
    provider = (clean(v.get("Provider", "Channel", "SourceName")) or "").lower()
    if "sysmon" in provider:
        return "sysmon"
    if v.has("EventID", "event_id") and v.has(*SYSMON_KEYS):
        return "sysmon"
    if v.has("EventID", "event_id") and (v.has(*WINDOWS_KEYS) or "security" in provider):
        return "windows_event"
    return container  # 'csv' or 'json' (generic)


MAPPERS = {"sysmon": map_sysmon, "windows_event": map_windows, "zeek": map_zeek,
           "suricata": map_suricata, "csv": map_generic, "json": map_generic}


def parse_file(data: bytes, filename: str, source_type: str = "auto") -> ParseResult:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise IngestionError(f"Unsupported file type '{ext or filename}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    if not data:
        raise IngestionError("File is empty.")
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise IngestionError(f"File exceeds the {MAX_UPLOAD_MB} MB limit.")
    if source_type not in SOURCE_TYPES:
        raise IngestionError("Unknown source type.")
    text = decode_bytes(data)
    safe_name = os.path.basename(filename)[:255]

    if ext == ".xml":
        container, reader = "windows_event", read_windows_xml(text, MAX_RECORDS_PER_FILE)
    elif is_zeek_tsv(text):
        container, reader = "zeek", read_zeek_tsv(text)
    elif ext in (".csv", ".tsv"):
        container, reader = "csv", read_csv(text, "\t" if ext == ".tsv" else None)
    else:  # .json .jsonl .ndjson .log (JSON lines)
        container, reader = "json", read_json(text)

    result = ParseResult(filename=safe_name)
    for ref, raw, err in reader:
        if result.total_records >= MAX_RECORDS_PER_FILE:
            result.truncated = True
            break
        result.total_records += 1
        if err or raw is None:
            _record_error(result, ref, err or "unreadable record")
            continue
        try:
            stype = source_type if source_type != "auto" else detect_record_type(raw, container)
            if container == "zeek" and source_type == "auto":
                stype = "zeek"
            fields = MAPPERS[stype](raw)
            ev = build_event(fields, raw, source_type=stype, source_file=safe_name, record_ref=ref)
            result.events.append(ev)
            result.source_types[stype] += 1
        except Exception as exc:  # one bad record must not abort the whole file
            _record_error(result, ref, f"{type(exc).__name__}: {str(exc)[:150]}")
    return result


def _record_error(result: ParseResult, ref: str, msg: str) -> None:
    result.error_count += 1
    if len(result.errors) < MAX_ERRORS_KEPT:
        result.errors.append((ref, msg))
