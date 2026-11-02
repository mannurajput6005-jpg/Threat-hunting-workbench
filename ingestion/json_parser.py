"""JSON (array / object / JSON Lines) reader."""
from __future__ import annotations

import json
from typing import Iterator

WRAPPER_KEYS = ("events", "records", "logs", "data", "items", "hits")


def read_json(text: str) -> Iterator[tuple[str, dict | None, str | None]]:
    stripped = text.lstrip()
    if not stripped:
        return
    if stripped[0] == "[":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            yield ("document", None, f"invalid JSON: {exc.msg} (line {exc.lineno})")
            return
        yield from _iter_items(data)
        return
    # JSON Lines first; fall back to a single (possibly pretty-printed) object
    first_line = stripped.splitlines()[0]
    try:
        json.loads(first_line)
        jsonl = True
    except json.JSONDecodeError:
        jsonl = False
    if not jsonl:
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            yield ("document", None, f"invalid JSON: {exc.msg} (line {exc.lineno})")
            return
        yield from _iter_items(data)
        return
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            yield (f"line {i}", None, f"invalid JSON: {exc.msg}")
            continue
        if isinstance(obj, dict):
            yield (f"line {i}", obj, None)
        else:
            yield (f"line {i}", None, "record is not a JSON object")


def _iter_items(data) -> Iterator[tuple[str, dict | None, str | None]]:
    if isinstance(data, dict):
        for key in WRAPPER_KEYS:
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    for i, item in enumerate(data, start=1):
        if isinstance(item, dict):
            yield (f"item {i}", item, None)
        else:
            yield (f"item {i}", None, "record is not a JSON object")
