"""
alert_schema.py: Structured alert output model

Every alert carries:
    - Detection ID and version
    - MITRE technique mapping
    - Confidence score (composite 0-1)
    - Entropy score (source diversity 0-1)
    - Source diversity count
    - Evidence blocks for each contributing source
    - Chain metadata for replay traceability
    - Noise reduction classification

Confidence score interpretation:
    >= 0.80  High confidence: evidence from multiple sources, high entropy, complete fields
    >= 0.60  Medium confidence: partial corroboration across sources, some field gaps
    >= 0.40  Low confidence: limited corroboration, investigate further
    <  0.40  Informational: single source or very incomplete chain
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .correlate import CorrelationChain

PIPELINE_VERSION = "2.0.0"


def build_alert(
    detection_id:     str,
    techniques:       list[str],
    severity:         str,
    confidence_score: float,
    entropy_score:    float,
    source_diversity: int,
    alert_type:       str,
    reason:           str,
    chain:            "CorrelationChain",
    primary_event:    dict,
    secondary_event:  Optional[dict],
    extra:            Optional[dict] = None,
) -> dict:
    now_utc = datetime.now(timezone.utc).isoformat()

    confidence_label = _confidence_label(confidence_score)
    noise_classification = _noise_classification(confidence_score, source_diversity)

    alert = {
        # Identity
        "alert_id":          str(uuid.uuid4()),
        "detection_id":      detection_id,
        "pipeline_version":  PIPELINE_VERSION,

        # Classification
        "alert_type":        alert_type,
        "severity":          _validate_severity(severity),
        "mitre_techniques":  techniques,

        # Scoring: entropy and confidence for noise reduction
        "confidence_score":     round(confidence_score, 3),
        "confidence_label":     confidence_label,
        "entropy_score":        round(entropy_score, 3),
        "source_diversity":     source_diversity,
        "noise_classification": noise_classification,

        # Description
        "reason": reason,

        # Timeline
        "time_start":    chain.time_start,
        "time_end":      chain.time_end,
        "delta_seconds": chain.delta_seconds,
        "generated_at":  now_utc,

        # Correlation context
        "chain_id":    chain.chain_id,
        "join_fields": chain.join_fields,

        # Host and identity
        "host": primary_event.get("host"),
        "user": primary_event.get("user"),

        # Data sources that contributed
        "data_sources": sorted(chain.source_types),

        # Evidence grouped by contributing source type
        "evidence": _build_evidence_blocks(chain, primary_event, secondary_event),
    }

    if extra:
        alert["detail"] = extra

    return alert


def _confidence_label(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.60:
        return "medium"
    if score >= 0.40:
        return "low"
    return "informational"


def _noise_classification(confidence: float, source_diversity: int) -> str:
    """
    Classify alert noise risk for triage prioritisation.
    Multi-source high-confidence alerts are production-grade signal.
    Single-source low-confidence alerts require investigation before escalation.
    """
    if confidence >= 0.80 and source_diversity >= 3:
        return "SIGNAL — high confidence multi-source, prioritise"
    if confidence >= 0.60 and source_diversity >= 2:
        return "LIKELY_SIGNAL — cross-source corroboration, investigate"
    if confidence >= 0.40:
        return "INVESTIGATE — partial evidence, verify before escalating"
    return "LOW_FIDELITY — single source or incomplete chain, tune or suppress"


def _build_evidence_blocks(
    chain:            "CorrelationChain",
    primary_event:    dict,
    secondary_event:  Optional[dict],
) -> dict:
    """
    Build structured evidence blocks grouping contributing events by source type.
    Each block contains the key fields from events of that source type.
    """
    evidence: dict = {
        "primary":   _event_summary(primary_event),
        "secondary": _event_summary(secondary_event) if secondary_event else None,
        "chain_summary": {
            "total_events":    len(chain.events),
            "source_types":    sorted(chain.source_types),
            "time_span_s":     chain.delta_seconds,
            "join_fields":     list(chain.join_fields.keys()),
        },
        "by_source": {},
    }

    # Group evidence by source type for analyst review
    for source_type in sorted(chain.source_types):
        events = chain.get_events_by_type(source_type)
        evidence["by_source"][source_type] = [
            _event_summary(e) for e in events
        ]

    return evidence


def _event_summary(event: Optional[dict]) -> Optional[dict]:
    if not event:
        return None
    return {
        "event_id":      event.get("event_id"),
        "data_source":   event.get("data_source"),
        "time":          event.get("time"),
        "host":          event.get("host"),
        "user":          event.get("user"),
        "process_name":  event.get("process_name"),
        "command_line":  event.get("command_line"),
        "process_guid":  event.get("process_guid"),
        "logon_id":      event.get("logon_id"),
        "src_ip":        event.get("src_ip"),
        "dst_ip":        event.get("dst_ip"),
        "dst_port":      event.get("dst_port"),
        "registry_key":  event.get("registry_key"),
        "task_name":     event.get("task_name"),
        "service_name":  event.get("service_name"),
    }


def _validate_severity(severity: str) -> str:
    valid = {"critical", "high", "medium", "low", "informational"}
    s = severity.lower()
    if s not in valid:
        raise ValueError(f"Invalid severity '{severity}'.")
    return s
