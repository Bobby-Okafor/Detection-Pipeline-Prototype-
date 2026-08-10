"""
schema_validator.py: Schema contract enforcement

Validates normalised events against field contracts per event type.
Supports both Sysmon flat-format and Windows Security message-format events.
"""

import sys
from typing import Optional

SCHEMA_CONTRACTS: dict[int, dict] = {
    # Sysmon EID 1: process creation
    1: {
        "required":  ["event_id", "time", "process_name"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["parent_process", "command_line", "user", "host", "process_guid", "logon_id"],
    },
    # Sysmon EID 3: network connection
    3: {
        "required":  ["event_id", "time", "process_name", "dst_ip"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["dst_port", "src_ip", "user", "host", "process_guid", "protocol"],
    },
    # Sysmon EID 13: registry value set
    13: {
        "required":  ["event_id", "time", "process_name", "registry_key"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["user", "host", "process_guid", "registry_value"],
    },
    # Sysmon EID 22: DNS query
    22: {
        "required":  ["event_id", "time", "process_name"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["query_name", "user", "host", "process_guid"],
    },
    # Windows Security 4688: process creation
    4688: {
        "required":  ["event_id", "time", "process_name"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["parent_process", "command_line", "user", "host", "logon_id"],
    },
    # Windows Security 4624: successful logon
    4624: {
        "required":  ["event_id", "time", "user"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["src_ip", "host", "logon_type", "logon_id", "domain"],
    },
    # Windows Security 4625: failed logon
    4625: {
        "required":  ["event_id", "time", "user"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["src_ip", "host", "failure_reason"],
    },
    # Windows Security 4698: scheduled task creation
    4698: {
        "required":  ["event_id", "time"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["task_name", "user", "host", "logon_id"],
    },
    # Windows Security 7045: service installation
    7045: {
        "required":  ["event_id", "time", "service_name"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["service_file", "host"],
    },
    # Windows Security 4672: special privileges
    4672: {
        "required":  ["event_id", "time", "user"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["logon_id", "host", "privileges"],
    },
}


def validate_events(
    events: list[dict],
    strict: bool = False,
) -> tuple[list[dict], list[dict]]:
    valid   = []
    rejected = []

    for event in events:
        violations, warnings = _check_event(event)

        if violations:
            event["schema_violations"] = violations
            event["schema_warnings"]   = warnings
            rejected.append(event)
            print(
                f"[SCHEMA REJECT] event_id={event.get('event_id')} "
                f"time={event.get('time')} violations={violations}",
                file=sys.stderr,
            )
        else:
            if warnings:
                event["schema_warnings"] = warnings
                print(
                    f"[SCHEMA WARN] event_id={event.get('event_id')} "
                    f"time={event.get('time')} warnings={warnings}",
                    file=sys.stderr,
                )
            if strict and warnings:
                event["schema_violations"] = warnings
                rejected.append(event)
            else:
                valid.append(event)

    total = len(events)
    print(
        f"[SCHEMA] total={total} valid={len(valid)} rejected={len(rejected)} "
        f"pass_rate={round(len(valid)/total*100, 1) if total else 0}%",
        file=sys.stderr,
    )
    return valid, rejected


def validate_schema_drift(
    events: list[dict],
    baseline_fields: Optional[dict[int, set]] = None,
) -> dict[int, set]:
    drift_report: dict[int, set] = {}

    for event in events:
        eid = event.get("event_id")
        if eid not in SCHEMA_CONTRACTS:
            continue
        contract = SCHEMA_CONTRACTS[eid]
        expected = set(baseline_fields.get(eid, [])) if baseline_fields else set(
            contract["required"] + contract.get("warn_only", [])
        )
        present  = {k for k, v in event.items() if v is not None and not k.startswith("_")}
        missing  = expected - present
        if missing:
            if eid not in drift_report:
                drift_report[eid] = set()
            drift_report[eid].update(missing)

    for eid, fields in drift_report.items():
        print(f"[SCHEMA DRIFT] event_id={eid} missing={sorted(fields)}", file=sys.stderr)

    return drift_report


def _check_event(event: dict) -> tuple[list[str], list[str]]:
    eid = event.get("event_id")
    violations: list[str] = []
    warnings:   list[str] = []

    if eid not in SCHEMA_CONTRACTS:
        return violations, warnings

    contract = SCHEMA_CONTRACTS[eid]

    for f in contract["required"]:
        if event.get(f) is None:
            violations.append(f"missing_required:{f}")

    for f, t in contract.get("typed", {}).items():
        val = event.get(f)
        if val is not None and not isinstance(val, t):
            violations.append(f"type_mismatch:{f} expected={t.__name__} got={type(val).__name__}")

    for f in contract.get("warn_only", []):
        if event.get(f) is None:
            warnings.append(f"missing_optional:{f}")

    return violations, warnings
