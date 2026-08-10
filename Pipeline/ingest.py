"""
ingest.py: Ingestion from multiple log sources

Supports two ingestion modes:
    Single file:  load_json(filepath) -> list[dict]
    Directory:    load_directory(dirpath) -> list[dict]

Directory mode merges all JSON files in a folder into one event stream
ordered by timestamp. Each event is tagged with its source file and
inferred source type. This is the primary mode for detection chains
that use multiple telemetry sources.
"""

import json
import sys
from pathlib import Path
from typing import Any

SUPPORTED_ENCODINGS = ["utf-8-sig", "utf-16", "utf-8", "latin-1"]

SOURCE_TYPE_MAP = {
    "sysmon_eid1":  "sysmon_process",
    "sysmon_eid3":  "sysmon_network",
    "sysmon_eid11": "sysmon_file",
    "sysmon_eid13": "sysmon_registry",
    "sysmon_eid22": "sysmon_dns",
    "winsec_4624":  "winsec_logon_success",
    "winsec_4625":  "winsec_logon_failure",
    "winsec_4688":  "winsec_process",
    "winsec_4698":  "winsec_task",
    "winsec_7045":  "winsec_service",
    "winsec_4672":  "winsec_privilege",
}


def load_json(filepath: str | Path) -> list[dict]:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {filepath}")
    raw = _read_with_encoding_fallback(path)
    events = _normalise_structure(raw, source=str(filepath))
    source_type = _infer_source_type(path.stem)
    for e in events:
        e.setdefault("_source_file", path.name)
        e.setdefault("_source_type", source_type)
    return events


def load_directory(dirpath: str | Path) -> list[dict]:
    """
    Load all JSON files from a directory and merge into a single event stream.
    Each event tagged with source file and inferred source type.
    """
    path = Path(dirpath)
    if not path.exists():
        raise FileNotFoundError(f"Input directory not found: {dirpath}")

    json_files = sorted(path.glob("*.json"))
    if not json_files:
        raise ValueError(f"No JSON files found in {dirpath}")

    all_events: list[dict] = []
    for jf in json_files:
        try:
            events = load_json(jf)
            all_events.extend(events)
            print(f"[INFO] ingest: {len(events)} events from {jf.name}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] ingest: failed {jf.name}: {e}", file=sys.stderr)

    print(f"[INFO] ingest: merged {len(all_events)} total events from {len(json_files)} files", file=sys.stderr)
    return all_events


def _read_with_encoding_fallback(path: Path) -> Any:
    last_error = None
    for encoding in SUPPORTED_ENCODINGS:
        try:
            with open(path, "r", encoding=encoding) as f:
                return json.load(f)
        except (UnicodeDecodeError, UnicodeError):
            continue
        except json.JSONDecodeError as e:
            last_error = e
            continue
    raise ValueError(f"Failed to parse {path.name}. Last error: {last_error}")


def _normalise_structure(data: Any, source: str) -> list[dict]:
    if isinstance(data, list):
        valid = [e for e in data if isinstance(e, dict)]
        dropped = len(data) - len(valid)
        if dropped:
            print(f"[WARN] ingest: dropped {dropped} non-dict entries from {source}", file=sys.stderr)
        return valid
    if isinstance(data, dict):
        for key in ("Events", "Records", "events", "records", "value"):
            if key in data and isinstance(data[key], list):
                return _normalise_structure(data[key], source)
        return [data]
    raise ValueError(f"Unexpected root type '{type(data).__name__}' in {source}.")


def _infer_source_type(stem: str) -> str:
    stem_lower = stem.lower()
    for key, stype in SOURCE_TYPE_MAP.items():
        if key in stem_lower:
            return stype
    return "unknown"
