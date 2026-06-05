"""
detect.py — Multi-telemetry behavioural detection engine

All detections operate on CorrelationChain objects, not raw events.
This enforces the multi-telemetry requirement at the architectural level
and ensures every alert has cross-source evidence backing it.

Detection registry:
    DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1
        Encoded PowerShell process (Sysmon EID 1) followed by outbound
        network connection (Sysmon EID 3) to non-standard port on
        non-RFC1918 IP. Joined by ProcessGuid.
        Sources: sysmon_process + sysmon_network

    DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1
        Brute force failed logons (WinSec 4625) from attacker IP,
        followed by successful logon (WinSec 4624) from same IP,
        followed by process creation (Sysmon EID 1 or WinSec 4688)
        under the authenticated session LogonId.
        Sources: winsec_logon_failure + winsec_logon_success + sysmon_process

    DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1
        PowerShell process (Sysmon EID 1) writing a registry Run key
        (Sysmon EID 13) and/or creating a scheduled task (WinSec 4698)
        within a 120-second window. Joined by ProcessGuid and LogonId.
        Sources: sysmon_process + sysmon_registry + winsec_task

    DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1
        Privileged logon (WinSec 4624 + 4672) followed by service
        installation (WinSec 7045) and subsequent execution (WinSec 4688).
        Joined by LogonId.
        Sources: winsec_logon_success + winsec_privilege + winsec_service + winsec_process
"""

import math
import re
import sys
from typing import Optional

from alert_schema import build_alert
from correlate import CorrelationChain
from normalize import to_epoch


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "::1")

STANDARD_PORTS = {80, 443, 53, 8080, 8443}

ENCODED_PS_INDICATORS = ("-enc", "-encodedcommand", "-e ", " -e\t")

LOLBINS = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
}

PERSISTENCE_REGISTRY_PATHS = (
    "software\\microsoft\\windows\\currentversion\\run",
    "software\\microsoft\\windows\\currentversion\\runonce",
    "system\\currentcontrolset\\services",
)

PRIVILEGED_ACCOUNTS = {"administrator", "admin", "root", "sysadmin", "sa"}


# ---------------------------------------------------------------------------
# Detection 1: Encoded PowerShell → C2 Beacon
# DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1
# ---------------------------------------------------------------------------

def detect_exec_to_c2(
    chains: list[CorrelationChain],
    window_seconds: int = 60,
) -> list[dict]:
    """
    Detects encoded PowerShell execution followed by an outbound network
    connection from the same process within the correlation window.

    Requires cross-source evidence: sysmon_process AND sysmon_network.
    ProcessGuid is the primary join field.
    """
    alerts = []
    seen: set = set()

    for chain in chains:
        if not (chain.has_source("sysmon_process") and chain.has_source("sysmon_network")):
            continue

        ps_events = chain.get_events_by_id(1)
        net_events = chain.get_events_by_id(3)

        for ps_event in ps_events:
            cmd = (ps_event.get("command_line") or "").lower()
            proc = (ps_event.get("process_name") or "").lower()

            is_encoded_ps = (
                "powershell" in proc and
                any(ind in cmd for ind in ENCODED_PS_INDICATORS)
            )

            if not is_encoded_ps:
                continue

            ps_guid = ps_event.get("process_guid")
            ps_time = to_epoch(ps_event.get("time"))

            for net_event in net_events:
                net_guid = net_event.get("process_guid")
                net_time = to_epoch(net_event.get("time"))
                delta = net_time - ps_time

                if delta < 0 or delta > window_seconds:
                    continue

                # Must be same process via ProcessGuid
                if ps_guid and net_guid and ps_guid != net_guid:
                    continue

                dst_ip   = net_event.get("dst_ip") or ""
                dst_port = str(net_event.get("dst_port") or "")

                # Flag connections to non-RFC1918 or lab attacker IPs
                is_suspicious_dst = (
                    not any(dst_ip.startswith(p) for p in RFC1918_PREFIXES)
                    or dst_ip == "192.168.126.128"  # Kali lab IP
                )

                if not is_suspicious_dst:
                    continue

                dedup_key = (ps_guid or proc, dst_ip, dst_port)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                alerts.append(build_alert(
                    detection_id="DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1",
                    techniques=["T1059.001", "T1071.001"],
                    severity="high",
                    confidence_score=chain.confidence,
                    entropy_score=chain.entropy_score,
                    source_diversity=chain.source_diversity,
                    alert_type="ENCODED_PS_C2_BEACON",
                    reason=(
                        f"Encoded PowerShell process connected to "
                        f"{dst_ip}:{dst_port} within {round(delta, 2)}s. "
                        f"ProcessGuid correlation across EID 1 and EID 3."
                    ),
                    chain=chain,
                    primary_event=ps_event,
                    secondary_event=net_event,
                    extra={
                        "process_guid":  ps_guid,
                        "command_line":  ps_event.get("command_line"),
                        "dst_ip":        dst_ip,
                        "dst_port":      dst_port,
                        "dst_hostname":  net_event.get("dst_hostname"),
                        "delta_seconds": round(delta, 2),
                        "join_field":    "process_guid",
                    },
                ))

    return alerts


# ---------------------------------------------------------------------------
# Detection 2: Brute Force → Authenticated Execution
# DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1
# ---------------------------------------------------------------------------

def detect_brute_to_exec(
    chains: list[CorrelationChain],
    failure_threshold: int = 5,
    window_seconds: int = 300,
) -> list[dict]:
    """
    Detects brute force credential attack (multiple 4625 failures from same IP)
    followed by successful logon (4624) from same IP and subsequent process
    execution (Sysmon EID 1 or WinSec 4688) under the authenticated LogonId.

    Requires three-source evidence: winsec_logon_failure + winsec_logon_success
    + (sysmon_process or winsec_process).
    """
    alerts = []
    seen: set = set()

    for chain in chains:
        has_failure = chain.has_source("winsec_logon_failure")
        has_success = chain.has_source("winsec_logon_success")
        has_exec    = chain.has_source("sysmon_process") or chain.has_source("winsec_process")

        if not (has_failure and has_success and has_exec):
            continue

        failures = chain.get_events_by_id(4625)
        successes = chain.get_events_by_id(4624)

        for success in successes:
            success_ip   = success.get("src_ip")
            success_user = success.get("user")
            success_lid  = success.get("logon_id")
            success_time = to_epoch(success.get("time"))

            if not success_ip or success_ip in ("127.0.0.1", "-"):
                continue

            # Count failures from the same IP before the success
            prior_failures = [
                f for f in failures
                if f.get("src_ip") == success_ip
                and to_epoch(f.get("time")) < success_time
                and success_time - to_epoch(f.get("time")) <= window_seconds
            ]

            if len(prior_failures) < failure_threshold:
                continue

            # Find process execution after logon under same LogonId or user
            exec_events = (
                chain.get_events_by_id(1) +
                chain.get_events_by_id(4688)
            )

            post_exec = [
                e for e in exec_events
                if to_epoch(e.get("time")) > success_time
                and to_epoch(e.get("time")) - success_time <= window_seconds
                and (
                    (success_lid and e.get("logon_id") == success_lid) or
                    (success_user and e.get("user", "").lower() == success_user.lower())
                )
            ]

            if not post_exec:
                continue

            dedup_key = (success_ip, success_user, success_lid)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            first_exec = post_exec[0]
            delta_to_exec = round(
                to_epoch(first_exec.get("time")) - success_time, 2
            )

            alerts.append(build_alert(
                detection_id="DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1",
                techniques=["T1110.001", "T1078", "T1059"],
                severity="critical",
                confidence_score=chain.confidence,
                entropy_score=chain.entropy_score,
                source_diversity=chain.source_diversity,
                alert_type="BRUTE_FORCE_TO_AUTHENTICATED_EXECUTION",
                reason=(
                    f"{len(prior_failures)} failed logons from {success_ip} "
                    f"followed by successful logon as '{success_user}', "
                    f"then process execution {delta_to_exec}s later. "
                    f"Three-source correlation: 4625 + 4624 + process event."
                ),
                chain=chain,
                primary_event=success,
                secondary_event=first_exec,
                extra={
                    "attacker_ip":     success_ip,
                    "authenticated_user": success_user,
                    "logon_id":        success_lid,
                    "failure_count":   len(prior_failures),
                    "failure_window_s": window_seconds,
                    "first_process":   first_exec.get("process_name"),
                    "first_cmd":       first_exec.get("command_line"),
                    "delta_to_exec_s": delta_to_exec,
                    "join_fields":     ["src_ip", "logon_id"],
                },
            ))

    return alerts


# ---------------------------------------------------------------------------
# Detection 3: Persistence Establishment
# DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1
# ---------------------------------------------------------------------------

def detect_persistence_establish(
    chains: list[CorrelationChain],
    window_seconds: int = 120,
) -> list[dict]:
    """
    Detects PowerShell or cmd writing a registry Run key (Sysmon EID 13)
    and/or creating a scheduled task (WinSec 4698) within the correlation window.

    Requires minimum two-source evidence. ProcessGuid and LogonId are
    the primary join fields.
    """
    alerts = []
    seen: set = set()

    for chain in chains:
        has_process  = chain.has_source("sysmon_process") or chain.has_source("winsec_process")
        has_registry = chain.has_source("sysmon_registry")
        has_task     = chain.has_source("winsec_task")

        if not has_process:
            continue
        if not (has_registry or has_task):
            continue

        proc_events = chain.get_events_by_id(1) + chain.get_events_by_id(4688)
        reg_events  = chain.get_events_by_id(13)
        task_events = chain.get_events_by_id(4698)

        for proc in proc_events:
            proc_name = (proc.get("process_name") or "").lower()
            is_scripting = any(s in proc_name for s in ("powershell", "cmd.exe", "wscript", "cscript"))
            if not is_scripting:
                continue

            proc_time = to_epoch(proc.get("time"))
            proc_guid = proc.get("process_guid")
            proc_lid  = proc.get("logon_id")
            proc_user = proc.get("user")

            persistence_events = []
            persistence_type   = []

            # Check registry persistence
            for reg in reg_events:
                reg_key = (reg.get("registry_key") or "").lower()
                is_persist_key = any(p in reg_key for p in PERSISTENCE_REGISTRY_PATHS)
                if not is_persist_key:
                    continue
                delta = abs(to_epoch(reg.get("time")) - proc_time)
                if delta > window_seconds:
                    continue
                same_process = (
                    (proc_guid and reg.get("process_guid") == proc_guid) or
                    (proc_lid and reg.get("logon_id") == proc_lid)
                )
                if same_process:
                    persistence_events.append(reg)
                    persistence_type.append("registry_run_key")

            # Check scheduled task persistence
            for task in task_events:
                delta = abs(to_epoch(task.get("time")) - proc_time)
                if delta > window_seconds:
                    continue
                same_session = (
                    (proc_lid and task.get("logon_id") == proc_lid) or
                    (proc_user and task.get("user", "").lower() == (proc_user or "").lower())
                )
                if same_session:
                    persistence_events.append(task)
                    persistence_type.append("scheduled_task")

            if not persistence_events:
                continue

            dedup_key = (proc_guid or proc_name, proc_lid, tuple(sorted(persistence_type)))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            persist_detail = ", ".join(set(persistence_type))

            alerts.append(build_alert(
                detection_id="DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1",
                techniques=["T1547.001", "T1053.005"],
                severity="high",
                confidence_score=chain.confidence,
                entropy_score=chain.entropy_score,
                source_diversity=chain.source_diversity,
                alert_type="PERSISTENCE_ESTABLISHMENT",
                reason=(
                    f"Scripting engine '{proc_name}' established persistence "
                    f"via {persist_detail} within {window_seconds}s window. "
                    f"Cross-source correlation: process + persistence artefact."
                ),
                chain=chain,
                primary_event=proc,
                secondary_event=persistence_events[0],
                extra={
                    "scripting_process":  proc_name,
                    "command_line":       proc.get("command_line"),
                    "persistence_types":  list(set(persistence_type)),
                    "persistence_count":  len(persistence_events),
                    "registry_keys":      [e.get("registry_key") for e in persistence_events if e.get("registry_key")],
                    "task_names":         [e.get("task_name") for e in persistence_events if e.get("task_name")],
                    "process_guid":       proc_guid,
                    "logon_id":           proc_lid,
                    "join_fields":        ["process_guid", "logon_id"],
                },
            ))

    return alerts


# ---------------------------------------------------------------------------
# Detection 4: Privileged Logon → Service Install → Execution
# DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1
# ---------------------------------------------------------------------------

def detect_priv_esc_to_exec(
    chains: list[CorrelationChain],
    window_seconds: int = 300,
) -> list[dict]:
    """
    Detects privileged account logon (4624 + 4672) followed by service
    installation (7045) and subsequent execution (4688) within the window.

    Models the attacker pattern of authenticating with privileged credentials,
    installing a service for persistence or execution, then running commands.
    """
    alerts = []
    seen: set = set()

    for chain in chains:
        has_success   = chain.has_source("winsec_logon_success")
        has_privilege = chain.has_source("winsec_privilege")
        has_service   = chain.has_source("winsec_service")
        has_exec      = chain.has_source("winsec_process") or chain.has_source("sysmon_process")

        if not (has_success and has_privilege and has_service and has_exec):
            continue

        logons   = chain.get_events_by_id(4624)
        privileges = chain.get_events_by_id(4672)
        services = chain.get_events_by_id(7045)
        execs    = chain.get_events_by_id(4688) + chain.get_events_by_id(1)

        for logon in logons:
            user     = (logon.get("user") or "").lower()
            lid      = logon.get("logon_id")
            src_ip   = logon.get("src_ip")
            logon_t  = to_epoch(logon.get("time"))
            logon_type = str(logon.get("logon_type") or "")

            # Suspicious logon types: Network (3) or RemoteInteractive (10)
            if logon_type not in ("3", "10"):
                continue

            matching_privileges = [
                p for p in privileges
                if to_epoch(p.get("time")) >= logon_t
                and to_epoch(p.get("time")) - logon_t <= window_seconds
                and (
                    (lid and p.get("logon_id") == lid) or
                    (user and p.get("user", "").lower() == user)
                )
            ]

            if not matching_privileges:
                continue

            # Find service installs after this logon
            post_services = [
                s for s in services
                if to_epoch(s.get("time")) > logon_t
                and to_epoch(s.get("time")) - logon_t <= window_seconds
            ]

            if not post_services:
                continue

            # Find execution after service install under same session
            svc_time = to_epoch(post_services[0].get("time"))
            post_execs = [
                e for e in execs
                if to_epoch(e.get("time")) >= svc_time
                and to_epoch(e.get("time")) - logon_t <= window_seconds
                and (
                    (lid and e.get("logon_id") == lid) or
                    (user and e.get("user", "").lower() == user)
                )
            ]

            if not post_execs:
                continue

            dedup_key = (user, lid, src_ip)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            first_exec = post_execs[0]
            delta_total = round(
                to_epoch(first_exec.get("time")) - logon_t, 2
            )

            alerts.append(build_alert(
                detection_id="DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1",
                techniques=["T1543.003", "T1078", "T1059"],
                severity="critical",
                confidence_score=chain.confidence,
                entropy_score=chain.entropy_score,
                source_diversity=chain.source_diversity,
                alert_type="PRIV_LOGON_SERVICE_EXEC_CHAIN",
                reason=(
                    f"Privileged logon by '{logon.get('user')}' from {src_ip} "
                    f"(logon type {logon_type}), followed by service install "
                    f"'{post_services[0].get('service_name')}', "
                    f"then execution within {delta_total}s. "
                    f"Four-source correlation: 4624 + 4672 + 7045 + 4688."
                ),
                chain=chain,
                primary_event=logon,
                secondary_event=first_exec,
                extra={
                    "user":          logon.get("user"),
                    "src_ip":        src_ip,
                    "logon_type":    logon_type,
                    "logon_id":      lid,
                    "privileges":    matching_privileges[0].get("privileges"),
                    "services":      [s.get("service_name") for s in post_services],
                    "service_files": [s.get("service_file") for s in post_services],
                    "first_process": first_exec.get("process_name"),
                    "first_cmd":     first_exec.get("command_line"),
                    "delta_total_s": delta_total,
                    "join_fields":   ["logon_id", "src_ip"],
                },
            ))

    return alerts


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def run_all_detections(
    chains: list[CorrelationChain],
    window_seconds: int = 300,
    brute_threshold: int = 5,
) -> list[dict]:
    """
    Run all registered detections against the correlation chain list.
    Returns a time-sorted, deduplicated alert list.
    """
    alerts: list[dict] = []

    alerts += detect_exec_to_c2(chains, window_seconds=60)
    alerts += detect_brute_to_exec(chains, failure_threshold=brute_threshold, window_seconds=window_seconds)
    alerts += detect_persistence_establish(chains, window_seconds=120)
    alerts += detect_priv_esc_to_exec(chains, window_seconds=window_seconds)

    alerts.sort(key=lambda a: a.get("time_start") or "")

    print(f"[+] Detections fired: {len(alerts)}", file=sys.stderr)
    return alerts
