"""
replay_harness.py: Detection as Code regression test runner

This is the validation mechanism that makes Detection as Code claims credible.
Every detection in the registry has a corresponding test case that:
    1. Loads the immutable telemetry corpus for that detection
    2. Runs the full pipeline against it
    3. Asserts the expected alert fires with expected fields
    4. Asserts the clean baseline produces zero alerts
    5. Records confidence and entropy scores for the validation report

Git replay guarantee:
    Any commit in the repo history can be checked out and this harness
    run to reproduce the exact validation state at that point in time.
    The corpus files are immutable once committed; they are the ground
    truth against which all detection versions are measured.

Run modes:
    python Pipeline/replay_harness.py --suite all
    python Pipeline/replay_harness.py --suite endpoint
    python Pipeline/replay_harness.py --suite identity
    python Pipeline/replay_harness.py --suite persistence
    python Pipeline/replay_harness.py --test chain1_c2_beacon
    python Pipeline/replay_harness.py --report  (write JSON report to reports/ci/)
"""

import argparse
import json
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from ingest import load_json, load_directory
from normalize import normalize_events
from schema_validator import validate_events
from correlate import build_correlation_chains
from detect import run_all_detections


def _supports_unicode() -> bool:
    """Return True when stdout can encode the harness' decorative output."""
    encoding = sys.stdout.encoding or ""
    return encoding.lower().replace("-", "") in {"utf8", "utf8sig"}


UNICODE_OUTPUT = _supports_unicode()


def _safe_text(text: str) -> str:
    if UNICODE_OUTPUT:
        return text

    replacements = {
        "═": "=",
        "─": "-",
        "✅": "[PASS]",
        "❌": "[FAIL]",
        "⏭": "[SKIP]",
        "→": "->",
        "—": "-",
        "·": "-",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _print(text: str = "", **kwargs) -> None:
    print(_safe_text(text), **kwargs)


def _status_label(result: "TestResult") -> str:
    if UNICODE_OUTPUT:
        if result.skipped:
            return "⏭  SKIP"
        if result.passed:
            return "✅ PASS"
        return "❌ FAIL"

    if result.skipped:
        return "[SKIP]"
    if result.passed:
        return "[PASS]"
    return "[FAIL]"


# ---------------------------------------------------------------------------
# Test case registry
# ---------------------------------------------------------------------------

@dataclass
class ReplayTestCase:
    name:                   str
    suite:                  str
    description:            str
    telemetry_dir:          Optional[str]       # directory with multiple source files (primary)
    telemetry_file:         Optional[str]       # single file (fallback)
    baseline_file:          Optional[str]       # clean baseline; must produce 0 alerts
    expected_alert_count:   int
    expected_detection_ids: list[str]           = field(default_factory=list)
    expected_fields:        dict                = field(default_factory=dict)
    min_confidence:         float               = 0.40
    min_source_diversity:   int                 = 2
    correlation_window:     int                 = 300
    detection_version:      str                 = "v1"


TEST_REGISTRY: list[ReplayTestCase] = [

    ReplayTestCase(
        name="chain1_c2_beacon",
        suite="endpoint",
        description=(
            "Encoded PowerShell (Sysmon EID 1) followed by outbound network "
            "connection to Kali attacker IP (Sysmon EID 3). "
            "ProcessGuid join across source files. T1059.001 + T1071.001."
        ),
        telemetry_dir="telemetry/raw/chain1_c2_beacon",
        telemetry_file=None,
        baseline_file="telemetry/raw/clean_baseline.json",
        expected_alert_count=1,
        expected_detection_ids=["DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1"],
        expected_fields={"severity": "high", "source_diversity": 2},
        min_confidence=0.55,
        min_source_diversity=2,
        correlation_window=60,
        detection_version="v1",
    ),

    ReplayTestCase(
        name="chain2_brute_to_exec",
        suite="identity",
        description=(
            "Brute force failed logons from Kali (WinSec 4625) followed by "
            "successful logon (WinSec 4624) then process execution (Sysmon EID 1). "
            "Three-source correlation: 4625 + 4624 + EID1. T1110.001 + T1078 + T1059."
        ),
        telemetry_dir="telemetry/raw/chain2_brute_exec",
        telemetry_file=None,
        baseline_file="telemetry/raw/clean_baseline.json",
        expected_alert_count=1,
        expected_detection_ids=["DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1"],
        expected_fields={"severity": "critical", "source_diversity": 3},
        min_confidence=0.60,
        min_source_diversity=3,
        correlation_window=300,
        detection_version="v1",
    ),

    ReplayTestCase(
        name="chain3_persistence",
        suite="persistence",
        description=(
            "PowerShell process (Sysmon EID 1) writing registry Run key "
            "(Sysmon EID 13) and creating scheduled task (WinSec 4698). "
            "ProcessGuid and LogonId joins across source files. T1547.001 + T1053.005."
        ),
        telemetry_dir="telemetry/raw/chain3_persistence",
        telemetry_file=None,
        baseline_file="telemetry/raw/clean_baseline.json",
        expected_alert_count=1,
        expected_detection_ids=["DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1"],
        expected_fields={"severity": "high", "source_diversity": 2},
        min_confidence=0.55,
        min_source_diversity=2,
        correlation_window=120,
        detection_version="v1",
    ),

    ReplayTestCase(
        name="chain4_priv_to_exec",
        suite="identity",
        description=(
            "Privileged logon (WinSec 4624 + 4672) followed by service "
            "installation (WinSec 7045) and execution (WinSec 4688). "
            "LogonId join across source files. T1543.003 + T1078 + T1059."
        ),
        telemetry_dir="telemetry/raw/chain4_priv_exec",
        telemetry_file=None,
        baseline_file="telemetry/raw/clean_baseline.json",
        expected_alert_count=1,
        expected_detection_ids=["DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1"],
        expected_fields={"severity": "critical", "source_diversity": 4},
        min_confidence=0.60,
        min_source_diversity=4,
        correlation_window=300,
        detection_version="v1",
    ),

    ReplayTestCase(
        name="clean_baseline",
        suite="baseline",
        description="Clean environment telemetry; all detections must produce zero alerts.",
        telemetry_dir=None,
        telemetry_file="telemetry/raw/clean_baseline.json",
        baseline_file=None,
        expected_alert_count=0,
        min_confidence=0.0,
        min_source_diversity=1,
        correlation_window=300,
        detection_version="v1",
    ),
]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    name:       str
    passed:     bool
    message:    str
    skipped:    bool = False
    alerts:     list[dict] = field(default_factory=list)
    confidence_scores: list[float] = field(default_factory=list)
    source_diversity:  list[int]   = field(default_factory=list)
    duration_ms: float = 0.0


def run_test(tc: ReplayTestCase, verbose: bool = False) -> TestResult:
    import time
    start = time.time()

    # Resolve input source
    if tc.telemetry_dir:
        tpath = Path(tc.telemetry_dir)
        if not tpath.exists():
            return TestResult(
                name=tc.name, passed=False, skipped=True,
        message=f"SKIP: telemetry directory not found: {tc.telemetry_dir}",
            )
        loader = lambda: load_directory(tpath)
    elif tc.telemetry_file:
        tpath = Path(tc.telemetry_file)
        if not tpath.exists():
            return TestResult(
                name=tc.name, passed=False, skipped=True,
        message=f"SKIP: telemetry file not found: {tc.telemetry_file}",
            )
        loader = lambda: load_json(tpath)
    else:
        return TestResult(
            name=tc.name, passed=False,
            message="TEST CONFIG ERROR: no telemetry source specified",
        )

    try:
        raw       = loader()
        normed    = normalize_events(raw)
        valid, _  = validate_events(normed)
        chains    = build_correlation_chains(valid, window_seconds=tc.correlation_window)
        alerts    = run_all_detections(chains, window_seconds=tc.correlation_window)
    except Exception as e:
        return TestResult(
            name=tc.name, passed=False,
            message=f"PIPELINE ERROR: {type(e).__name__}: {e}\n{traceback.format_exc()}",
        )

    duration_ms = round((time.time() - start) * 1000, 1)
    failures: list[str] = []

    # Assert alert count
    if len(alerts) != tc.expected_alert_count:
        failures.append(
            f"alert_count: expected={tc.expected_alert_count} got={len(alerts)}"
        )

    # Assert expected detection IDs fired
    fired_ids = {a["detection_id"] for a in alerts}
    for did in tc.expected_detection_ids:
        if did not in fired_ids:
            failures.append(f"missing_detection_id: {did}")

    # Assert minimum confidence
    for alert in alerts:
        score = alert.get("confidence_score", 0)
        if score < tc.min_confidence:
            failures.append(
                f"confidence_too_low: {alert['detection_id']} "
                f"score={score} min={tc.min_confidence}"
            )

    # Assert minimum source diversity
    for alert in alerts:
        diversity = alert.get("source_diversity", 0)
        if diversity < tc.min_source_diversity:
            failures.append(
                f"insufficient_source_diversity: {alert['detection_id']} "
                f"diversity={diversity} min={tc.min_source_diversity}"
            )

    # Spot-check expected fields on first alert
    if alerts and tc.expected_fields:
        first = alerts[0]
        for fname, fval in tc.expected_fields.items():
            actual = first.get(fname)
            if actual != fval:
                failures.append(
                    f"field_mismatch:{fname} expected={fval} got={actual}"
                )

    # Baseline: also run against clean telemetry if specified
    if tc.baseline_file:
        baseline_path = Path(tc.baseline_file)
        if baseline_path.exists():
            try:
                b_raw    = load_json(baseline_path)
                b_normed = normalize_events(b_raw)
                b_valid, _ = validate_events(b_normed)
                b_chains = build_correlation_chains(b_valid, window_seconds=tc.correlation_window)
                b_alerts = run_all_detections(b_chains, window_seconds=tc.correlation_window)
                if b_alerts:
                    failures.append(
                        f"false_positives_on_baseline: {len(b_alerts)} alerts fired"
                    )
            except Exception as e:
                failures.append(f"baseline_error: {e}")

    conf_scores = [a.get("confidence_score", 0) for a in alerts]
    diversity   = [a.get("source_diversity", 0) for a in alerts]

    if failures:
        return TestResult(
            name=tc.name, passed=False,
            message=f"FAIL: {'; '.join(failures)}",
            alerts=alerts, confidence_scores=conf_scores,
            source_diversity=diversity, duration_ms=duration_ms,
        )

    return TestResult(
        name=tc.name, passed=True,
        message=(
            f"PASS: {tc.expected_alert_count} alert(s), "
            f"confidence={round(sum(conf_scores)/len(conf_scores), 3) if conf_scores else 'n/a'}, "
            f"diversity={max(diversity) if diversity else 'n/a'}"
        ),
        alerts=alerts, confidence_scores=conf_scores,
        source_diversity=diversity, duration_ms=duration_ms,
    )


def run_suite(suite_name: str, verbose: bool = False, write_report: bool = False) -> int:
    cases = TEST_REGISTRY if suite_name == "all" else [
        tc for tc in TEST_REGISTRY if tc.suite == suite_name
    ]

    if not cases:
        _print(f"[ERROR] No test cases for suite '{suite_name}'", file=sys.stderr)
        return 1

    results: list[TestResult] = []

    _print(f"\n{'═' * 72}")
    _print(f"  Detection Replay Harness: suite {suite_name}")
    _print(f"  DetectionLab v2: Detection as Code validation")
    _print(f"{'═' * 72}\n")

    for tc in cases:
        result = run_test(tc, verbose=verbose)
        results.append(result)

        status = _status_label(result)

        _print(f"  {status}  {tc.name}  [{tc.detection_version}]")
        _print(f"         {result.message}")

        if verbose and result.alerts:
            for a in result.alerts:
                _print(
                    f"         → {a.get('detection_id')} | "
                    f"confidence={a.get('confidence_score')} | "
                    f"diversity={a.get('source_diversity')} | "
                    f"noise={a.get('noise_classification')}"
                )
        _print()

    passed  = sum(1 for r in results if r.passed)
    failed  = sum(1 for r in results if not r.passed and not r.skipped)
    skipped = sum(1 for r in results if r.skipped)

    _print(f"{'─' * 72}")
    _print(f"  Results: {passed} passed · {failed} failed · {skipped} skipped")
    _print(f"{'─' * 72}\n")

    if write_report:
        _write_ci_report(results, suite_name)

    return 0 if failed == 0 else 1


def _write_ci_report(results: list[TestResult], suite_name: str) -> None:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite":        suite_name,
        "pipeline_version": "2.0.0",
        "summary": {
            "passed":  sum(1 for r in results if r.passed),
            "failed":  sum(1 for r in results if not r.passed and not r.skipped),
            "skipped": sum(1 for r in results if r.skipped),
        },
        "results": [
            {
                "name":       r.name,
                "passed":     r.passed,
                "skipped":    r.skipped,
                "message":    r.message,
                "duration_ms": r.duration_ms,
                "confidence_scores": r.confidence_scores,
                "source_diversity":  r.source_diversity,
            }
            for r in results
        ],
    }

    report_path = Path("reports/ci/replay_harness_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    _print(f"[+] CI report written to {report_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detection replay harness: Detection as Code validation"
    )
    parser.add_argument(
        "--suite", default="all",
        choices=["all", "endpoint", "identity", "persistence", "baseline"],
    )
    parser.add_argument("--test", default=None, help="Run a single named test case")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--report", action="store_true", help="Write JSON report to reports/ci/")
    args = parser.parse_args()

    if args.test:
        tc = next((t for t in TEST_REGISTRY if t.name == args.test), None)
        if not tc:
            _print(f"[ERROR] Test '{args.test}' not found.", file=sys.stderr)
            sys.exit(1)
        result = run_test(tc, verbose=args.verbose)
        status = _status_label(result)
        _print(f"\n{status}  {tc.name}: {result.message}\n")
        sys.exit(0 if result.passed else 1)

    sys.exit(run_suite(args.suite, verbose=args.verbose, write_report=args.report))
