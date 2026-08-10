"""
normalize.py: Telemetry normalization layer

Handles two fundamentally different Windows telemetry formats:

1. Windows Security Event Log (4624, 4625, 4688, 4698, 7045)
   Events arrive with a Message field containing labelled text blocks.
   User context lives in "Creator Subject:" or "Subject:" sections.
   Process fields live in "Process Information:" section.

2. Sysmon Operational Log (EID 1, 3, 11, 13, 22)
   Events arrive as flat key-value pairs directly on the event object
   OR as structured Message text with "Key: Value" pairs.
   ProcessGuid is available for cross-event correlation.

Key design decisions:
   - Creator Subject user extraction uses regex scoping to avoid
     picking up "-" placeholder values from Target Subject blocks
   - ProcessGuid is preserved as a first-class correlation field
   - LogonId is normalised across both formats for session correlation
   - All timestamps normalised to UTC ISO 8601
   - Schema warnings do not fail validation; events with missing optional
     fields still pass through to the detection engine
"""

import re
import sys
from datetime import datetime, timezone
from typing import Optional

WINDOWS_EPOCH_OFFSET = 11_644_473_600


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def normalize_events(events: list[dict]) -> list[dict]:
    normalised = []

    for raw in events:
        source_type = raw.get("_source_type", "unknown")
        event_id = _extract_event_id(raw)

        try:
            if source_type == "sysmon_process" or event_id == 1:
                record = _normalise_sysmon_eid1(raw)
            elif source_type == "sysmon_network" or event_id == 3:
                record = _normalise_sysmon_eid3(raw)
            elif source_type == "sysmon_registry" or event_id == 13:
                record = _normalise_sysmon_eid13(raw)
            elif source_type == "sysmon_dns" or event_id == 22:
                record = _normalise_sysmon_eid22(raw)
            elif source_type == "winsec_process" or event_id == 4688:
                record = _normalise_winsec_4688(raw)
            elif source_type in ("winsec_logon_success", "winsec_logon_failure") or event_id in (4624, 4625):
                record = _normalise_winsec_logon(raw, event_id)
            elif source_type == "winsec_task" or event_id == 4698:
                record = _normalise_winsec_4698(raw)
            elif source_type == "winsec_service" or event_id == 7045:
                record = _normalise_winsec_7045(raw)
            elif source_type == "winsec_privilege" or event_id == 4672:
                record = _normalise_winsec_4672(raw)
            else:
                record = _normalise_unknown(raw, event_id)
        except Exception as e:
            print(f"[ERROR] normalize: exception on event_id={event_id}: {e}", file=sys.stderr)
            record = {"event_id": event_id, "time": None, "parse_error": str(e), "_raw": raw}

        # Preserve source metadata
        record["_source_file"] = raw.get("_source_file", "unknown")
        record["_source_type"] = raw.get("_source_type", "unknown")
        normalised.append(record)

    normalised.sort(key=lambda x: to_epoch(x.get("time")))
    return normalised


# ---------------------------------------------------------------------------
# Sysmon normalizers: flat key/value format
# ---------------------------------------------------------------------------

def _normalise_sysmon_eid1(raw: dict) -> dict:
    """Sysmon EID 1: process creation. Fields are available as flat key/value pairs."""
    msg = raw.get("Message", "")
    kv = _parse_sysmon_message(msg) if msg else {}

    # Direct field access first (some exporters flatten to top level)
    process_name  = raw.get("Image") or kv.get("Image")
    parent_process = raw.get("ParentImage") or kv.get("ParentImage")
    command_line  = raw.get("CommandLine") or kv.get("CommandLine")
    user          = raw.get("User") or kv.get("User")
    process_guid  = raw.get("ProcessGuid") or kv.get("ProcessGuid")
    parent_guid   = raw.get("ParentProcessGuid") or kv.get("ParentProcessGuid")
    logon_id      = raw.get("LogonId") or kv.get("LogonId")
    logon_guid    = raw.get("LogonGuid") or kv.get("LogonGuid")
    integrity     = raw.get("IntegrityLevel") or kv.get("IntegrityLevel")
    hashes        = raw.get("Hashes") or kv.get("Hashes")

    record = {
        "event_id":       1,
        "data_source":    "Sysmon EID 1 Process Create",
        "time":           _safe_extract_time(raw, kv),
        "host":           _extract_host(raw, kv),
        "process_name":   _clean(process_name),
        "parent_process": _clean(parent_process),
        "command_line":   command_line,
        "user":           _clean_user(user),
        "process_guid":   _clean_guid(process_guid),
        "parent_guid":    _clean_guid(parent_guid),
        "logon_id":       _normalise_logon_id(logon_id),
        "logon_guid":     _clean_guid(logon_guid),
        "integrity_level": integrity,
        "hashes":         hashes,
    }

    record["_parse_complete"] = all([record["process_name"], record["time"]])
    return record


def _normalise_sysmon_eid3(raw: dict) -> dict:
    """Sysmon EID 3: network connection."""
    msg = raw.get("Message", "")
    kv = _parse_sysmon_message(msg) if msg else {}

    process_name = raw.get("Image") or kv.get("Image")
    user         = raw.get("User") or kv.get("User")
    process_guid = raw.get("ProcessGuid") or kv.get("ProcessGuid")
    dst_ip       = raw.get("DestinationIp") or kv.get("DestinationIp")
    dst_port     = raw.get("DestinationPort") or kv.get("DestinationPort")
    src_ip       = raw.get("SourceIp") or kv.get("SourceIp")
    src_port     = raw.get("SourcePort") or kv.get("SourcePort")
    dst_hostname = raw.get("DestinationHostname") or kv.get("DestinationHostname")
    protocol     = raw.get("Protocol") or kv.get("Protocol")
    initiated    = raw.get("Initiated") or kv.get("Initiated")

    record = {
        "event_id":        3,
        "data_source":     "Sysmon EID 3 Network Connection",
        "time":            _safe_extract_time(raw, kv),
        "host":            _extract_host(raw, kv),
        "process_name":    _clean(process_name),
        "process_guid":    _clean_guid(process_guid),
        "user":            _clean_user(user),
        "dst_ip":          _clean(dst_ip),
        "dst_port":        dst_port,
        "dst_hostname":    _clean(dst_hostname),
        "src_ip":          _clean(src_ip),
        "src_port":        src_port,
        "protocol":        protocol,
        "initiated":       initiated,
    }

    record["_parse_complete"] = all([record["process_name"], record["time"], record["dst_ip"]])
    return record


def _normalise_sysmon_eid13(raw: dict) -> dict:
    """Sysmon EID 13: registry value set."""
    msg = raw.get("Message", "")
    kv = _parse_sysmon_message(msg) if msg else {}

    process_name = raw.get("Image") or kv.get("Image")
    process_guid = raw.get("ProcessGuid") or kv.get("ProcessGuid")
    target_obj   = raw.get("TargetObject") or kv.get("TargetObject")
    details      = raw.get("Details") or kv.get("Details")
    event_type   = raw.get("EventType") or kv.get("EventType")
    user         = raw.get("User") or kv.get("User")

    record = {
        "event_id":      13,
        "data_source":   "Sysmon EID 13 Registry Value Set",
        "time":          _safe_extract_time(raw, kv),
        "host":          _extract_host(raw, kv),
        "process_name":  _clean(process_name),
        "process_guid":  _clean_guid(process_guid),
        "user":          _clean_user(user),
        "registry_key":  _clean(target_obj),
        "registry_value": details,
        "event_type":    event_type,
    }

    record["_parse_complete"] = all([record["process_name"], record["time"], record["registry_key"]])
    return record


def _normalise_sysmon_eid22(raw: dict) -> dict:
    """Sysmon EID 22: DNS query."""
    msg = raw.get("Message", "")
    kv = _parse_sysmon_message(msg) if msg else {}

    record = {
        "event_id":     22,
        "data_source":  "Sysmon EID 22 DNS Query",
        "time":         _safe_extract_time(raw, kv),
        "host":         _extract_host(raw, kv),
        "process_name": _clean(raw.get("Image") or kv.get("Image")),
        "process_guid": _clean_guid(raw.get("ProcessGuid") or kv.get("ProcessGuid")),
        "user":         _clean_user(raw.get("User") or kv.get("User")),
        "query_name":   _clean(raw.get("QueryName") or kv.get("QueryName")),
        "query_status": raw.get("QueryStatus") or kv.get("QueryStatus"),
        "query_results": raw.get("QueryResults") or kv.get("QueryResults"),
    }

    record["_parse_complete"] = all([record["process_name"], record["time"]])
    return record


# ---------------------------------------------------------------------------
# Windows Security normalizers: message text format
# ---------------------------------------------------------------------------

def _normalise_winsec_4688(raw: dict) -> dict:
    """Windows Security EID 4688: process creation."""
    message = raw.get("Message", "")

    process_name   = _extract_last_field(message, "New Process Name:")
    parent_process = _extract_last_field(message, "Creator Process Name:")
    command_line   = _extract_last_field(message, "Process Command Line:")
    elevation      = _extract_last_field(message, "Token Elevation Type:")
    user           = _extract_creator_subject_user(message)
    logon_id       = _extract_creator_logon_id(message)

    record = {
        "event_id":       4688,
        "data_source":    "Windows Security 4688 Process Create",
        "time":           _safe_extract_time(raw, {}),
        "host":           _extract_host(raw, {}),
        "process_name":   _clean(process_name),
        "parent_process": _clean(parent_process),
        "command_line":   command_line,
        "user":           _clean_user(user),
        "logon_id":       _normalise_logon_id(logon_id),
        "elevation_type": elevation,
    }

    record["_parse_complete"] = all([record["process_name"], record["time"]])
    return record


def _normalise_winsec_logon(raw: dict, event_id: int) -> dict:
    """Windows Security EID 4624/4625: logon events."""
    message = raw.get("Message", "")

    # For logon events extract from New Logon section for 4624
    # and Account For Which Logon Failed for 4625
    user       = _extract_logon_user(message, event_id)
    domain     = _extract_field_value(message, "Account Domain:")
    logon_type = _extract_field_value(message, "Logon Type:")
    logon_id   = _extract_new_logon_id(message) if event_id == 4624 else None
    src_ip     = _extract_field_value(message, "Source Network Address:")
    src_port   = _extract_field_value(message, "Source Port:")
    workstation = _extract_field_value(message, "Workstation Name:")
    auth_pkg   = _extract_field_value(message, "Authentication Package:")
    fail_reason = _extract_field_value(message, "Failure Reason:") if event_id == 4625 else None

    record = {
        "event_id":       event_id,
        "data_source":    f"Windows Security {event_id}",
        "time":           _safe_extract_time(raw, {}),
        "host":           _extract_host(raw, {}),
        "user":           _clean_user(user),
        "domain":         _clean(domain),
        "logon_type":     logon_type,
        "logon_id":       _normalise_logon_id(logon_id),
        "src_ip":         _clean(src_ip),
        "src_port":       src_port,
        "workstation":    _clean(workstation),
        "auth_package":   auth_pkg,
        "failure_reason": fail_reason,
        "outcome":        "success" if event_id == 4624 else "failure",
    }

    record["_parse_complete"] = all([record["user"], record["time"]])
    return record


def _normalise_winsec_4698(raw: dict) -> dict:
    """Windows Security EID 4698: scheduled task creation."""
    message = raw.get("Message", "")

    user      = _extract_creator_subject_user(message)
    logon_id  = _extract_creator_logon_id(message)
    task_name = _extract_field_value(message, "Task Name:")
    task_content = _extract_field_value(message, "Task Content:")

    record = {
        "event_id":     4698,
        "data_source":  "Windows Security 4698 Scheduled Task Created",
        "time":         _safe_extract_time(raw, {}),
        "host":         _extract_host(raw, {}),
        "user":         _clean_user(user),
        "logon_id":     _normalise_logon_id(logon_id),
        "task_name":    _clean(task_name),
        "task_content": task_content,
    }

    record["_parse_complete"] = all([record["time"], record["task_name"]])
    return record


def _normalise_winsec_7045(raw: dict) -> dict:
    """Windows Security EID 7045: new service installation."""
    message = raw.get("Message", "")

    record = {
        "event_id":      7045,
        "data_source":   "Windows Security 7045 Service Install",
        "time":          _safe_extract_time(raw, {}),
        "host":          _extract_host(raw, {}),
        "service_name":  _clean(_extract_field_value(message, "Service Name:")),
        "service_file":  _clean(_extract_field_value(message, "Service File Name:")),
        "service_type":  _extract_field_value(message, "Service Type:"),
        "start_type":    _extract_field_value(message, "Service Start Type:"),
        "account":       _extract_field_value(message, "Service Account:"),
    }

    record["_parse_complete"] = all([record["time"], record["service_name"]])
    return record


def _normalise_winsec_4672(raw: dict) -> dict:
    """Windows Security EID 4672: special privileges assigned."""
    message = raw.get("Message", "")

    record = {
        "event_id":   4672,
        "data_source": "Windows Security 4672 Special Privileges",
        "time":       _safe_extract_time(raw, {}),
        "host":       _extract_host(raw, {}),
        "user":       _clean_user(_extract_creator_subject_user(message)),
        "logon_id":   _normalise_logon_id(_extract_creator_logon_id(message)),
        "privileges": _extract_field_value(message, "Privileges:"),
    }

    record["_parse_complete"] = all([record["time"], record["user"]])
    return record


def _normalise_unknown(raw: dict, event_id) -> dict:
    return {
        "event_id":   event_id,
        "time":       _safe_extract_time(raw, {}),
        "host":       _extract_host(raw, {}),
        "parse_note": f"No handler for event_id {event_id}",
        "_raw":       raw,
    }


# ---------------------------------------------------------------------------
# Sysmon message parser
# ---------------------------------------------------------------------------

def _parse_sysmon_message(message: str) -> dict:
    """
    Parse Sysmon flat key-value message format.
    Each line is "Key: Value" with no nested sections.
    """
    result = {}
    for line in message.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key and value and key not in result:
                result[key] = value
    return result


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _extract_event_id(raw: dict) -> Optional[int]:
    val = raw.get("Id") or raw.get("EventID") or raw.get("event_id")
    try:
        return int(val) if val is not None else None
    except (ValueError, TypeError):
        return None


def _extract_creator_subject_user(message: str) -> Optional[str]:
    """Extract user from Creator Subject block, avoiding Target Subject placeholders."""
    match = re.search(
        r"(?:Creator Subject|Subject):.*?Account Name:\s*\t*([^\r\n]+)",
        message,
        re.DOTALL | re.IGNORECASE,
    )
    if match:
        val = match.group(1).strip()
        if val and val != "-" and not val.endswith("$"):
            return val
    return None


def _extract_creator_logon_id(message: str) -> Optional[str]:
    """Extract LogonId from Creator Subject block."""
    match = re.search(
        r"(?:Creator Subject|Subject):.*?Logon ID:\s*\t*(0x[0-9A-Fa-f]+)",
        message,
        re.DOTALL | re.IGNORECASE,
    )
    return match.group(1) if match else None


def _extract_logon_user(message: str, event_id: int) -> Optional[str]:
    """Extract user from New Logon section (4624) or failed account section (4625)."""
    if event_id == 4624:
        match = re.search(
            r"New Logon:.*?Account Name:\s*\t*([^\r\n]+)",
            message,
            re.DOTALL | re.IGNORECASE,
        )
    else:
        match = re.search(
            r"Account For Which Logon Failed:.*?Account Name:\s*\t*([^\r\n]+)",
            message,
            re.DOTALL | re.IGNORECASE,
        )
    if match:
        val = match.group(1).strip()
        return val if val and val != "-" else None
    return _extract_field_value(message, "Account Name:")


def _extract_new_logon_id(message: str) -> Optional[str]:
    """Extract LogonId from New Logon section of 4624."""
    match = re.search(
        r"New Logon:.*?Logon ID:\s*\t*(0x[0-9A-Fa-f]+)",
        message,
        re.DOTALL | re.IGNORECASE,
    )
    return match.group(1) if match else None


def _extract_last_field(message: str, label: str) -> Optional[str]:
    """Extract field value using last occurrence (Process Information section comes last)."""
    pattern = re.compile(
        rf"{re.escape(label)}\s*\t*([^\r\n]+)",
        re.IGNORECASE,
    )
    matches = pattern.findall(message)
    if not matches:
        return None
    val = matches[-1].strip()
    return val if val and val != "-" else None


def _extract_field_value(message: str, label: str) -> Optional[str]:
    """Extract first occurrence of a labelled field value."""
    match = re.search(
        rf"{re.escape(label)}\s*\t*([^\r\n]+)",
        message,
        re.IGNORECASE,
    )
    if match:
        val = match.group(1).strip()
        return val if val and val != "-" else None
    return None


def _safe_extract_time(event: dict, kv: dict) -> Optional[str]:
    raw_time = (
        event.get("TimeCreated", {}).get("SystemTime")
        if isinstance(event.get("TimeCreated"), dict)
        else event.get("TimeCreated")
           or event.get("SystemTime")
           or kv.get("UtcTime")
           or event.get("UtcTime")
           or event.get("timestamp")
           or event.get("time")
    )
    result = _convert_time(raw_time)
    if result is None and raw_time is not None:
        print(f"[WARN] normalize: unparseable timestamp: {repr(raw_time)}", file=sys.stderr)
    return result


def _convert_time(raw_time) -> Optional[str]:
    if raw_time is None:
        return None

    # ISO 8601 format
    if isinstance(raw_time, str) and re.match(r"\d{4}-\d{2}-\d{2}T", raw_time):
        try:
            dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

    # Sysmon space-separated format
    if isinstance(raw_time, str):
        try:
            dt = datetime.strptime(raw_time, "%Y-%m-%d %H:%M:%S.%f")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass

        try:
            dt = datetime.strptime(raw_time, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass

    # Epoch / Windows FILETIME handling
    try:
        val = int(re.search(r"\d+", str(raw_time)).group())
    except (AttributeError, ValueError, TypeError):
        return None

    if val > 1_000_000_000_000_000:
        epoch_sec = (val / 10_000_000) - WINDOWS_EPOCH_OFFSET
    elif val > 1_000_000_000_000:
        epoch_sec = val / 1_000
    else:
        epoch_sec = float(val)

    try:
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None

def _extract_host(event: dict, kv: dict) -> Optional[str]:
    return (
        event.get("Computer")
        or kv.get("Computer")
        or event.get("hostname")
        or event.get("host")
        or event.get("MachineName")
    )


def _normalise_logon_id(logon_id: Optional[str]) -> Optional[str]:
    """Normalize logon ID to lowercase hexadecimal for consistent matching across sources."""
    if not logon_id:
        return None
    val = str(logon_id).strip().lower()
    return val if val != "0x0" else None


def _clean(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    placeholders = {"-", "n/a", "null", "none", ""}
    stripped = value.strip()
    if stripped.lower() in placeholders:
        return None
    return stripped

def _clean_guid(value: Optional[str]) -> Optional[str]:
    val = _clean(value)

    if not val:
        return None

    zero_guids = {
        "{00000000-0000-0000-0000-000000000000}",
        "00000000-0000-0000-0000-000000000000",
    }

    if val.lower() in zero_guids:
        return None

    return val

def _clean_user(value: Optional[str]) -> Optional[str]:
    """Clean user field, also filtering machine accounts and system accounts."""
    val = _clean(value)
    if not val:
        return None
    system_accounts = {
        "nt authority\\system",
        "nt authority\\local service",
        "nt authority\\network service",
        "font driver host\\umfd-0",
        "font driver host\\umfd-1",
        "window manager\\dwm-1",
    }
    if val.lower() in system_accounts:
        return None
    if val.endswith("$"):
        return None
    return val


# ---------------------------------------------------------------------------
# Time utility
# ---------------------------------------------------------------------------

def to_epoch(ts: Optional[str]) -> float:
    if not ts:
        return 0.0
    try:
        return datetime.fromisoformat(ts).timestamp()
    except (ValueError, TypeError):
        return 0.0
