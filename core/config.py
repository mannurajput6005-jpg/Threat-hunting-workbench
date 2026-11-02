"""Central configuration. Values come from environment variables (optionally a .env file)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader (no extra dependency). Real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


DB_PATH = Path(os.environ.get("THW_DB_PATH", BASE_DIR / "data" / "workbench.db"))
RULES_DIR = Path(os.environ.get("THW_RULES_DIR", BASE_DIR / "rules"))
SAMPLES_DIR = BASE_DIR / "data" / "samples"
WATCHLIST_PATH = BASE_DIR / "data" / "threat_intelligence" / "ioc_watchlist.csv"
MITRE_PATH = BASE_DIR / "mitre" / "techniques.json"
LOG_LEVEL = os.environ.get("THW_LOG_LEVEL", "INFO").upper()

# Ingestion limits (uploaded files are untrusted input)
MAX_UPLOAD_MB = _int("THW_MAX_UPLOAD_MB", 50)
MAX_RECORDS_PER_FILE = _int("THW_MAX_RECORDS_PER_FILE", 200_000)
ALLOWED_EXTENSIONS = {".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".log", ".xml"}

# Authentication
SESSION_TIMEOUT_MINUTES = _int("THW_SESSION_TIMEOUT_MINUTES", 30)
MAX_FAILED_LOGINS = _int("THW_MAX_FAILED_LOGINS", 5)
LOCKOUT_MINUTES = _int("THW_LOCKOUT_MINUTES", 5)
MIN_PASSWORD_LENGTH = 10

# Optional external enrichment (OFF by default - the app works fully offline)
ENABLE_EXTERNAL_ENRICHMENT = _bool("THW_ENABLE_EXTERNAL_ENRICHMENT", False)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Analysis defaults
CORRELATION_WINDOW_SECONDS = _int("THW_CORRELATION_WINDOW_SECONDS", 900)
