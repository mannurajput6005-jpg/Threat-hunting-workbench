"""CSV / TSV reader and the generic field mapper used for custom CSV and JSON datasets."""
from __future__ import annotations

import csv
import io
from typing import Iterator

from normalization.normalizer import FieldView, clean, strip_domain

csv.field_size_limit(5_000_000)

GENERIC_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "@timestamp", "eventtime", "event_time", "datetime", "date",
                  "utctime", "ts", "timecreated", "systemtime", "created_at"),
    "hostname": ("hostname", "host.name", "host", "computer", "computername", "machine", "device",
                 "device_name", "workstation"),
    "username": ("username", "user.name", "user", "account", "accountname", "targetusername",
                 "subjectusername", "user_name"),
    "source_ip": ("source_ip", "src_ip", "srcip", "source.ip", "src", "client_ip", "sourceaddress",
                  "ipaddress", "id.orig_h", "sourceip"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "destination.ip", "dest", "dstip",
                       "destinationaddress", "id.resp_h", "destinationip"),
    "source_port": ("source_port", "src_port", "srcport", "source.port", "id.orig_p", "sourceport"),
    "destination_port": ("destination_port", "dest_port", "dst_port", "dstport", "destination.port",
                         "id.resp_p", "destinationport"),
    "process_path": ("process_path", "process.executable", "image", "newprocessname", "process_image"),
    "process_name": ("process_name", "process.name", "process", "processname"),
    "parent_process": ("parent_process", "parent_image", "parentimage", "process.parent.name",
                       "parentprocessname", "parent"),
    "command_line": ("command_line", "commandline", "cmdline", "process.command_line", "process.args"),
    "event_category": ("event_category", "category", "event.category"),
    "event_action": ("event_action", "action", "event.action", "event_type"),
    "outcome": ("outcome", "status", "result", "event.outcome"),
    "event_code": ("event_code", "event_id", "eventid", "event.code"),
    "domain": ("domain", "dns.question.name", "query", "queryname", "hostname_requested", "url.domain"),
    "url": ("url", "url.full", "uri"),
    "file_hash": ("file_hash", "sha256", "sha1", "md5", "hash", "hashes", "file.hash.sha256"),
    "protocol": ("protocol", "proto", "network.protocol"),
    "severity": ("severity", "level", "priority"),
}


def map_generic(raw: dict) -> dict:
    v = FieldView(raw)
    fields = {target: v.get(*aliases) for target, aliases in GENERIC_ALIASES.items()}
    fields["username"] = strip_domain(clean(fields["username"]))
    return fields


def read_csv(text: str, delimiter: str | None = None) -> Iterator[tuple[str, dict | None, str | None]]:
    """Yield (record_ref, record, error). Header row is required."""
    if delimiter is None:
        sample = text[:4096].splitlines()[0] if text else ""
        delimiter = "\t" if sample.count("\t") > sample.count(",") else (
            ";" if sample.count(";") > sample.count(",") else ",")
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
        yield ("header", None, "CSV needs a header row with unique column names")
        return
    for i, row in enumerate(reader, start=2):  # header is line 1
        if None in row:
            yield (f"line {i}", None, "row has more fields than the header")
            continue
        if not any((v or "").strip() for v in row.values()):
            continue  # blank row
        yield (f"line {i}", {k: v for k, v in row.items()}, None)
