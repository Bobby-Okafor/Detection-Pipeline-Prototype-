"""
run_pipeline.py: Detection pipeline CLI entry point

Full pipeline flow:
    ingest → normalise → validate schema → correlate → detect → score → output

Supports two input modes:
    --input     Single JSON file (backward compatible)
    --input-dir Directory of JSON files (primary mode for multiple sources)

Detection as Code versioning:
    Every pipeline run produces a run manifest in the output that includes:
    - Input files and their SHA256 hashes (corpus provenance)
    - Pipeline version
    - Detection IDs and versions that fired
    - Confidence score distribution
    - Schema validation pass rates per source type

    This manifest is what gets committed to reports/ in the git repo,
    making every detection result reproducible and auditable.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ingest import load_json, load_directory
from normalize import normalize_events
from schema_validator import validate_events, validate_schema_drift
from correlate import build_correlation_chains
from detect import run_all_detections


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DetectionLab v2: detection pipeline for multiple telemetry sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input", "-i",
        help="Path to single raw log JSON file",
    )
    input_group.add_argument(
        "--input-dir", "-d",
        help="Path to directory containing JSON files from multiple sources",
    )

    parser.add_argument("--output", "-o", default=None, help="Path to write alerts JSON")
    parser.add_argument("--window", type=int, default=300, help="Correlation window in seconds (default: 300)")
    parser.add_argument("--brute-threshold", type=int, default=5, help="Brute force failure threshold (default: 5)")
    parser.add_argument("--strict-schema", action="store_true", help="Reject events with optional field violations")
    parser.add_argument("--drift-check", action="store_true", help="Run schema drift analysis")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="Minimum confidence score to include in output (0.0-1.0)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress diagnostic output")

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------
    try:
        if args.input_dir:
            raw_events = load_directory(args.input_dir)
            input_source = args.input_dir
            input_mode = "directory containing multiple sources"
        else:
            raw_events = load_json(args.input)
            input_source = args.input
            input_mode = "single file"
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] Ingest failed: {e}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[+] Ingested {len(raw_events)} raw events ({input_mode})", file=sys.stderr)

    # ------------------------------------------------------------------
    # Normalise
    # ------------------------------------------------------------------
    normalised = normalize_events(raw_events)

    if not args.quiet:
        source_breakdown = {}
        for e in normalised:
            st = e.get("_source_type", "unknown")
            source_breakdown[st] = source_breakdown.get(st, 0) + 1
        print(f"[+] Normalised {len(normalised)} events:", file=sys.stderr)
        for src, count in sorted(source_breakdown.items()):
            print(f"    {src}: {count}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Schema validation
    # ------------------------------------------------------------------
    valid_events, rejected_events = validate_events(normalised, strict=args.strict_schema)

    if rejected_events and not args.quiet:
        print(f"[WARN] {len(rejected_events)} events rejected by schema", file=sys.stderr)

    if args.drift_check:
        validate_schema_drift(normalised)

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------
    chains = build_correlation_chains(valid_events, window_seconds=args.window)

    if not args.quiet:
        print(f"[+] Built {len(chains)} correlation chains", file=sys.stderr)
        multi_source = sum(1 for c in chains if c.source_diversity >= 2)
        print(f"    Chains using multiple sources: {multi_source}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Detect
    # ------------------------------------------------------------------
    alerts = run_all_detections(
        chains,
        window_seconds=args.window,
        brute_threshold=args.brute_threshold,
    )

    # Apply minimum confidence filter
    if args.min_confidence > 0:
        before = len(alerts)
        alerts = [a for a in alerts if a.get("confidence_score", 0) >= args.min_confidence]
        if not args.quiet:
            print(f"[+] Confidence filter ({args.min_confidence}): {before} → {len(alerts)} alerts", file=sys.stderr)

    # ------------------------------------------------------------------
    # Build run manifest (Detection as Code provenance record)
    # ------------------------------------------------------------------
    run_manifest = _build_run_manifest(
        input_source=input_source,
        input_mode=input_mode,
        raw_count=len(raw_events),
        normalised_count=len(normalised),
        rejected_count=len(rejected_events),
        chain_count=len(chains),
        alerts=alerts,
        window=args.window,
        args=args,
    )

    output_payload = {
        "_run_manifest": run_manifest,
        "alerts": alerts,
    }

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_payload, f, indent=2, default=str)
        if not args.quiet:
            print(f"[+] Output written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output_payload, indent=2, default=str))

    return 0


def _build_run_manifest(
    input_source: str,
    input_mode: str,
    raw_count: int,
    normalised_count: int,
    rejected_count: int,
    chain_count: int,
    alerts: list[dict],
    window: int,
    args,
) -> dict:
    """
    Build provenance manifest for Detection as Code git tracking.
    This record makes every pipeline run reproducible and auditable.
    """
    # Hash input files for corpus provenance
    input_hashes = {}
    input_path = Path(input_source)
    if input_path.is_dir():
        for jf in sorted(input_path.glob("*.json")):
            input_hashes[jf.name] = _sha256(jf)
    elif input_path.is_file():
        input_hashes[input_path.name] = _sha256(input_path)

    # Confidence distribution
    scores = [a.get("confidence_score", 0) for a in alerts]
    confidence_dist = {
        "high":          sum(1 for s in scores if s >= 0.80),
        "medium":        sum(1 for s in scores if 0.60 <= s < 0.80),
        "low":           sum(1 for s in scores if 0.40 <= s < 0.60),
        "informational": sum(1 for s in scores if s < 0.40),
    }

    return {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "pipeline_version": "2.0.0",
        "input_source":     input_source,
        "input_mode":       input_mode,
        "input_hashes":     input_hashes,
        "raw_event_count":  raw_count,
        "normalised_count": normalised_count,
        "rejected_count":   rejected_count,
        "schema_pass_rate": round((normalised_count - rejected_count) / normalised_count * 100, 1) if normalised_count else 0,
        "chain_count":      chain_count,
        "alert_count":      len(alerts),
        "detections_fired": list({a["detection_id"] for a in alerts}),
        "confidence_distribution": confidence_dist,
        "correlation_window_s": window,
        "min_confidence_filter": getattr(args, "min_confidence", 0.0),
    }


def _sha256(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"


if __name__ == "__main__":
    sys.exit(main())
