"""
correlate.py: Correlation across telemetry sources

This module is the core of the detection capability that uses multiple telemetry sources.
It takes a normalised, time-sorted event stream from mixed sources
(Sysmon EID 1, 3, 13, Windows Security 4624, 4625, 4688, 4698, 7045)
and builds CorrelationChain objects by joining events on shared context fields.

Join field priority (highest to lowest specificity):
    1. process_guid  : Sysmon stamps this on EID 1 and EID 3 for the same process
    2. logon_id      : Windows stamps this on 4624 and Sysmon EID 1 for the same session
    3. src_ip        : joins attacker-originated 4625 failures with 4624 success
    4. user + host   : fallback session join within a time window
    5. host + time   : scoped fallback for service installation events with no session ID

Each CorrelationChain carries:
    - All contributing events grouped by source type
    - The join fields that linked them
    - The time span from first to last event
    - A source diversity score (how many telemetry sources contributed)
    - An entropy score for confidence calibration

Detection functions in detect.py receive CorrelationChain objects,
not raw event lists. This enforces the requirement for multiple telemetry sources
at the architectural level.
"""

import math
from dataclasses import dataclass, field
from typing import Optional
from normalize import to_epoch


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CorrelationChain:
    """
    A group of related events from one or more telemetry sources,
    linked by shared context fields within a time window.
    """
    chain_id:        str
    events:          list[dict] = field(default_factory=list)
    join_fields:     dict       = field(default_factory=dict)
    source_types:    set        = field(default_factory=set)
    time_start:      Optional[str] = None
    time_end:        Optional[str] = None
    delta_seconds:   float = 0.0
    source_diversity: int  = 0
    entropy_score:   float = 0.0
    confidence:      float = 0.0

    def add_event(self, event: dict) -> None:
        self.events.append(event)
        source = event.get("_source_type", "unknown")
        self.source_types.add(source)

        t = event.get("time")
        if t:
            if not self.time_start or t < self.time_start:
                self.time_start = t
            if not self.time_end or t > self.time_end:
                self.time_end = t

    def finalise(self) -> None:
        """Calculate derived metrics after all events are added."""
        self.source_diversity = len(self.source_types)
        if self.time_start and self.time_end:
            self.delta_seconds = round(
                to_epoch(self.time_end) - to_epoch(self.time_start), 3
            )
        self.entropy_score  = _calculate_entropy(self)
        self.confidence     = _calculate_confidence(self)

    def get_events_by_type(self, source_type: str) -> list[dict]:
        return [e for e in self.events if e.get("_source_type") == source_type]

    def get_events_by_id(self, event_id: int) -> list[dict]:
        return [e for e in self.events if e.get("event_id") == event_id]

    def has_source(self, source_type: str) -> bool:
        return source_type in self.source_types

    def field_populated_ratio(self) -> float:
        """Ratio of populated fields across all events; measures telemetry completeness."""
        if not self.events:
            return 0.0
        total = sum(
            sum(1 for v in e.values() if v is not None and not str(v).startswith("_"))
            for e in self.events
        )
        possible = sum(
            sum(1 for k in e.keys() if not k.startswith("_"))
            for e in self.events
        )
        return round(total / possible, 3) if possible else 0.0


# ---------------------------------------------------------------------------
# Entropy and confidence scoring
# ---------------------------------------------------------------------------

def _calculate_entropy(chain: CorrelationChain) -> float:
    """
    Shannon entropy over source type distribution.

    High entropy = events spread across many diverse telemetry sources
    Low entropy  = events concentrated in one source type

    A detection that fires on 3 different telemetry sources has higher
    entropy (and thus higher signal quality) than one firing on 1 source.

    Returns value between 0.0 and 1.0 (normalised).
    """
    if not chain.events:
        return 0.0

    source_counts: dict[str, int] = {}
    for e in chain.events:
        st = e.get("_source_type", "unknown")
        source_counts[st] = source_counts.get(st, 0) + 1

    total = len(chain.events)
    raw_entropy = 0.0
    for count in source_counts.values():
        p = count / total
        if p > 0:
            raw_entropy -= p * math.log2(p)

    max_entropy = math.log2(len(source_counts)) if len(source_counts) > 1 else 1.0
    return round(raw_entropy / max_entropy, 3) if max_entropy > 0 else 0.0


def _calculate_confidence(chain: CorrelationChain) -> float:
    """
    Composite confidence score combining:
        - Source diversity (0-1): how many distinct telemetry sources
        - Entropy score (0-1): distribution across sources
        - Field completeness (0-1): ratio of populated fields
        - Join field strength (0-1): quality of the correlation join

    Weights reflect operational importance:
        Source diversity contributes most; detections with evidence from multiple sources
        are inherently more reliable than single-source ones.

    Returns value between 0.0 and 1.0.
    """
    # Source diversity score (normalised against maximum expected 4 sources)
    diversity_score = min(chain.source_diversity / 4.0, 1.0)

    # Entropy score already normalised
    entropy_score = chain.entropy_score

    # Field completeness
    completeness_score = chain.field_populated_ratio()

    # Join field strength
    join_strength = _join_field_strength(chain.join_fields)

    # Weighted composite
    confidence = (
        diversity_score   * 0.35 +
        entropy_score     * 0.25 +
        completeness_score * 0.20 +
        join_strength     * 0.20
    )

    return round(min(confidence, 1.0), 3)


def _join_field_strength(join_fields: dict) -> float:
    """
    Score the quality of correlation join fields.
    ProcessGuid and LogonId are highly specific joins.
    IP joins provide medium specificity.
    User+host+time fallbacks are lower specificity.
    """
    if not join_fields:
        return 0.1

    score = 0.0
    weights = {
        "process_guid": 1.0,
        "logon_id":     0.85,
        "logon_guid":   0.85,
        "src_ip":       0.60,
        "user_host":    0.40,
        "host_time":    0.35,
        "user_time":    0.30,
    }

    for field_name in join_fields:
        score = max(score, weights.get(field_name, 0.2))

    return score


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def build_correlation_chains(
    events: list[dict],
    window_seconds: int = 300,
) -> list[CorrelationChain]:
    """
    Build correlation chains from a normalised, time-sorted event stream.

    Strategy:
        1. Index all events by their joinable fields
        2. For each anchor event, find related events within the window
        3. Group related events into chains
        4. Finalise each chain with entropy and confidence scores

    Returns a list of CorrelationChain objects ready for detection logic.
    """
    if not events:
        return []

    # Build indexes for fast lookup
    guid_index:     dict[str, list[dict]] = {}
    logon_id_index: dict[str, list[dict]] = {}
    ip_index:       dict[str, list[dict]] = {}
    user_host_index: dict[str, list[dict]] = {}
    host_service_index: dict[str, list[dict]] = {}

    for event in events:
        pg = event.get("process_guid")
        if pg:
            guid_index.setdefault(pg, []).append(event)

        lid = event.get("logon_id")
        if lid:
            logon_id_index.setdefault(lid, []).append(event)

        src = event.get("src_ip")
        if src and src not in ("127.0.0.1", "::1", "-"):
            ip_index.setdefault(src, []).append(event)

        dst = event.get("dst_ip")
        if dst and dst not in ("127.0.0.1", "::1", "-"):
            ip_index.setdefault(dst, []).append(event)

        user = event.get("user")
        host = event.get("host")
        if user and host:
            key = f"{user.lower()}@{host.lower()}"
            user_host_index.setdefault(key, []).append(event)

        if host and event.get("_source_type") == "winsec_service":
            host_service_index.setdefault(host.lower(), []).append(event)

    chains: list[CorrelationChain] = []
    seen_event_groups: set = set()

    chain_counter = 0

    for anchor in events:
        anchor_time = to_epoch(anchor.get("time"))
        if anchor_time == 0.0:
            continue

        related: list[dict] = [anchor]
        join_fields: dict = {}

        # Join by ProcessGuid, the most specific join
        pg = anchor.get("process_guid")
        if pg and pg in guid_index:
            for e in guid_index[pg]:
                if e is not anchor and _in_window(e, anchor_time, window_seconds):
                    related.append(e)
                    join_fields["process_guid"] = pg

        # Join by LogonId for session correlation
        lid = anchor.get("logon_id")
        if lid and lid in logon_id_index:
            for e in logon_id_index[lid]:
                if e is not anchor and e not in related and _in_window(e, anchor_time, window_seconds):
                    related.append(e)
                    join_fields["logon_id"] = lid

        # Join by source IP for attacker IP correlation
        src = anchor.get("src_ip")
        if src and src in ip_index and src not in ("127.0.0.1", "::1"):
            for e in ip_index[src]:
                if e is not anchor and e not in related and _in_window(e, anchor_time, window_seconds):
                    related.append(e)
                    join_fields["src_ip"] = src

        # Join by destination IP when the anchor is the connecting process
        dst = anchor.get("dst_ip")
        if dst and dst in ip_index and dst not in ("127.0.0.1", "::1"):
            for e in ip_index[dst]:
                if e is not anchor and e not in related and _in_window(e, anchor_time, window_seconds):
                    related.append(e)
                    join_fields.setdefault("dst_ip", dst)

        # Join by user+host for fallback session correlation
        user = anchor.get("user")
        host = anchor.get("host")
        if user and host:
            key = f"{user.lower()}@{host.lower()}"
            if key in user_host_index:
                for e in user_host_index[key]:
                    if e is not anchor and e not in related and _in_window(e, anchor_time, window_seconds):
                        related.append(e)
                        join_fields["user_host"] = key

        # Windows 7045 service installation events often lack LogonId/user context.
        # Add them only as host/time corroboration so detections can still
        # require stronger joins on the surrounding logon and execution events.
        host = anchor.get("host")
        if host:
            for e in host_service_index.get(host.lower(), []):
                if e is not anchor and e not in related and _in_window(e, anchor_time, window_seconds):
                    related.append(e)
                    join_fields.setdefault("host_time", host.lower())

        # Only create chains with multiple events or an explicit requirement for multiple sources
        if len(related) < 2:
            continue

        # Deduplication: skip if this exact set of events was already chained
        event_key = frozenset(id(e) for e in related)
        if event_key in seen_event_groups:
            continue
        seen_event_groups.add(event_key)

        chain_counter += 1
        chain = CorrelationChain(
            chain_id=f"CHAIN-{chain_counter:04d}",
            join_fields=join_fields,
        )
        for e in sorted(related, key=lambda x: to_epoch(x.get("time"))):
            chain.add_event(e)
        chain.finalise()
        chains.append(chain)

    return chains


def _in_window(event: dict, anchor_time: float, window_seconds: int) -> bool:
    t = to_epoch(event.get("time"))
    if t == 0.0:
        return False
    return abs(t - anchor_time) <= window_seconds
