"""Local validation controller for DetectionLab."""
from __future__ import annotations

import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ingest import load_json, load_directory
from normalize import normalize_events, to_epoch
from schema_validator import validate_events, validate_schema_drift
from correlate import build_correlation_chains
from detect import run_all_detections

PIPELINE_VERSION = "2.0.0"
PROFILE_VERSION = "1.0"
EXIT_OK, EXIT_EXPECTATION, EXIT_EXECUTION = 0, 2, 1

REQUIRED_MODULES = ["ingest.py", "normalize.py", "schema_validator.py", "correlate.py", "detect.py", "alert_schema.py", "run_pipeline.py", "replay_harness.py"]
KNOWN_KEYS = {"profile_id", "profile_version", "description", "telemetry", "scenarios", "notes"}
SCENARIO_REQUIRED = {"id", "input", "correlation_window_seconds", "expected_detection_ids", "expected_alert_count", "minimum_confidence", "minimum_source_diversity", "clean_baseline"}

def fail(message: str, code: int = EXIT_EXECUTION) -> int:
    print(f"[FAIL] {message}", file=sys.stderr)
    return code

def load_profile(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists(): raise ValueError(f"profile not found: {p}")
    try:
        with p.open(encoding="utf-8") as f: data = yaml.safe_load(f)
    except yaml.YAMLError as e: raise ValueError(f"invalid YAML: {e}") from e
    if not isinstance(data, dict): raise ValueError("profile root must be a mapping")
    missing = [k for k in ("profile_id", "profile_version", "description", "scenarios") if k not in data]
    if missing: raise ValueError(f"missing profile fields: {', '.join(missing)}")
    if str(data["profile_version"]) != PROFILE_VERSION: raise ValueError(f"unsupported profile_version: {data['profile_version']}")
    if not isinstance(data["scenarios"], list) or not data["scenarios"]: raise ValueError("scenarios must be a non-empty list")
    ids = set()
    for i, scenario in enumerate(data["scenarios"]):
        if not isinstance(scenario, dict): raise ValueError(f"scenario[{i}] must be a mapping")
        missing = sorted(SCENARIO_REQUIRED - set(scenario))
        if missing: raise ValueError(f"scenario[{i}] missing fields: {', '.join(missing)}")
        sid = scenario["id"]
        if sid in ids: raise ValueError(f"duplicate scenario id: {sid}")
        ids.add(sid)
        if not isinstance(scenario["expected_detection_ids"], list): raise ValueError(f"scenario {sid}: expected_detection_ids must be a list")
        if not isinstance(scenario["expected_alert_count"], int) or scenario["expected_alert_count"] < 0: raise ValueError(f"scenario {sid}: expected_alert_count must be non-negative integer")
        if not 0 <= float(scenario["minimum_confidence"]) <= 1: raise ValueError(f"scenario {sid}: minimum_confidence must be between 0 and 1")
        if int(scenario["minimum_source_diversity"]) < 1: raise ValueError(f"scenario {sid}: minimum_source_diversity must be >= 1")
        if not isinstance(scenario["clean_baseline"], dict) or "expected_alert_count" not in scenario["clean_baseline"]: raise ValueError(f"scenario {sid}: clean_baseline.expected_alert_count is required")
    return data

def resolve_path(value: str, base: Path = ROOT) -> Path:
    p = Path(value)
    return p if p.is_absolute() else base / p

def input_files(path: Path) -> list[Path]:
    if path.is_file(): return [path]
    if path.is_dir(): return sorted(path.glob("*.json"))
    return []

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def load_input(path: Path) -> list[dict]:
    if path.is_dir(): return load_directory(path)
    if path.is_file(): return load_json(path)
    raise ValueError(f"telemetry input not found: {path}")

def assess_data(path: Path, window: int = 300) -> tuple[dict, list[dict], list[dict], list]:
    files = input_files(path)
    if not files: raise ValueError(f"telemetry input has no JSON files: {path}")
    raw = load_input(path)
    norm = normalize_events(raw)
    valid, rejected = validate_events(norm)
    chains = build_correlation_chains(valid, window_seconds=window)
    source_counts = {}
    for e in norm: source_counts[e.get("_source_type", "unknown")] = source_counts.get(e.get("_source_type", "unknown"), 0) + 1
    telemetry_events = [e for e in norm if e.get("event_id") is not None]
    timestamps = [to_epoch(e.get("time")) for e in telemetry_events]
    parseable = sum(1 for t in timestamps if t != 0)
    ordering = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1) if timestamps[i] and timestamps[i+1])
    keys = ["process_guid", "logon_id", "src_ip", "user", "host", "process_guid", "logon_guid"]
    coverage = {k: round(sum(1 for e in norm if e.get(k)) / len(norm), 3) if norm else 0.0 for k in sorted(set(keys))}
    join_mechanisms = sorted({k for c in chains for k in c.join_fields})
    multi = sum(1 for c in chains if c.source_diversity >= 2)
    quality = {
        "raw_event_count": len(raw), "normalized_event_count": len(norm), "accepted_event_count": len(valid), "rejected_event_count": len(rejected),
        "schema_acceptance_rate": round(len(valid) / len(norm), 3) if norm else 0.0, "source_type_inventory": dict(sorted(source_counts.items())),
        "unknown_source_count": source_counts.get("unknown", 0), "timestamp_parseability": round(parseable / len(telemetry_events), 3) if telemetry_events else 0.0,
        "timestamp_ordering": "PASS" if ordering else "WARN", "source_diversity": len(source_counts - {"unknown"}) if isinstance(source_counts, set) else len([x for x in source_counts if x != "unknown"]),
        "key_coverage": coverage, "correlation_chain_count": len(chains), "multi_source_chain_count": multi,
        "correlation_join_mechanisms": join_mechanisms, "schema_drift": {str(k): sorted(v) for k, v in validate_schema_drift(norm).items()},
        "status": "FAIL" if not telemetry_events or rejected or parseable < len(telemetry_events) else ("WARN" if not multi or source_counts.get("unknown", 0) else "PASS"),
    }
    return quality, raw, norm, chains

def expected_validation(scenario: dict, alerts: list[dict], baseline_alerts: list[dict] | None) -> list[str]:
    errors = []
    if len(alerts) != scenario["expected_alert_count"]: errors.append(f"alert_count expected={scenario['expected_alert_count']} got={len(alerts)}")
    fired = {a.get("detection_id") for a in alerts}
    for did in scenario["expected_detection_ids"]:
        if did not in fired: errors.append(f"missing_detection_id:{did}")
    for a in alerts:
        if a.get("confidence_score", 0) < float(scenario["minimum_confidence"]): errors.append(f"confidence_too_low:{a.get('detection_id')}")
        if a.get("source_diversity", 0) < int(scenario["minimum_source_diversity"]): errors.append(f"source_diversity_too_low:{a.get('detection_id')}")
        if scenario.get("expected_severity") and a.get("severity") != scenario["expected_severity"]: errors.append(f"severity_mismatch:{a.get('detection_id')}")
    if baseline_alerts is not None and len(baseline_alerts) != scenario["clean_baseline"]["expected_alert_count"]: errors.append(f"baseline_alert_count expected={scenario['clean_baseline']['expected_alert_count']} got={len(baseline_alerts)}")
    return errors

def write_reports(report: dict, out: Path) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out / "validation_evidence.json", out / "validation_evidence.md"
    with json_path.open("w", encoding="utf-8") as f: json.dump(report, f, indent=2, sort_keys=True)
    q = report["quality"]
    lines = [f"# DetectionLab Portable Validation Controller", "", f"- Final status: **{report['final_status']}**", f"- Trustworthy: **{report['trustworthy']}**", f"- Profile: `{report['profile_id']}`", f"- Run UTC: `{report['run_utc']}`", "", "## Evidence", f"- Input hashes: `{json.dumps(report['input_hashes'], sort_keys=True)}`", f"- Events: raw={q['raw_event_count']}, normalized={q['normalized_event_count']}, accepted={q['accepted_event_count']}, rejected={q['rejected_event_count']}", f"- Schema acceptance: `{q['schema_acceptance_rate']}`", f"- Sources: `{json.dumps(q['source_type_inventory'], sort_keys=True)}`", f"- Correlation chains: {q['correlation_chain_count']} ({q['multi_source_chain_count']} using multiple sources)", f"- Join mechanisms: `{', '.join(q['correlation_join_mechanisms']) or 'none'}`", f"- Detections expected: `{report['expected_detection_ids']}`", f"- Detections observed: `{report['observed_detection_ids']}`", "", "## Findings"] + [f"- {x}" for x in report["findings"]] + ["", "## Quality JSON", "```json", json.dumps(q, indent=2, sort_keys=True), "```"]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path

def command_doctor(args) -> int:
    checks = [sys.version_info >= (3, 11), bool(yaml), all((Path(__file__).parent / m).exists() for m in REQUIRED_MODULES), (ROOT / "telemetry/raw").exists(), os.access(ROOT, os.W_OK)]
    try: load_profile(resolve_path(args.profile))
    except Exception as e: return fail(f"profile invalid: {e}")
    checks.append(True)
    if all(checks): print("DetectionLab Portable Validation Controller\nEnvironment ........ READY\nProfile ............ VALID\nRepository .......... READY"); return EXIT_OK
    return fail("execution readiness checks failed")

def command_init(args) -> int:
    w = Path(args.workspace).resolve()
    for name in ("telemetry", "profiles", "reports", "run-state"): (w / name).mkdir(parents=True, exist_ok=True)
    (w / "README.md").write_text("# DetectionLab validation workspace\n\nPlace exported JSON telemetry in `telemetry/`, profiles in `profiles/`, and generated evidence in `reports/`.\n", encoding="utf-8")
    print(f"Workspace initialized: {w}\nTelemetry .......... {w / 'telemetry'}\nProfiles ........... {w / 'profiles'}\nReports ............ {w / 'reports'}")
    return EXIT_OK

def command_assess(args, profile=None, scenario=None) -> tuple[int, dict | None]:
    try:
        path = resolve_path(args.input)
        q, raw, norm, chains = assess_data(path, int(args.window or (scenario or {}).get("correlation_window_seconds", 300)))
        report = {"controller": "DetectionLab Portable Validation Controller", "profile_id": (profile or {}).get("profile_id", "assessment-only"), "run_utc": datetime.now(timezone.utc).isoformat(), "pipeline_version": PIPELINE_VERSION, "telemetry_input": str(path), "input_files": [str(x) for x in input_files(path)], "input_hashes": {x.name: sha256(x) for x in input_files(path)}, "quality": q, "expected_detection_ids": (scenario or {}).get("expected_detection_ids", []), "observed_detection_ids": [], "findings": [], "trustworthy": q["status"] != "FAIL", "final_status": q["status"]}
        if q["status"] == "FAIL": report["findings"].append("Telemetry quality is insufficient for trusted validation.")
        out = resolve_path(args.output_dir or "reports/validation")
        jp, mp = write_reports(report, out)
        print(f"DetectionLab Portable Validation Controller\nEnvironment ........ READY\nTelemetry sources .. {', '.join(q['source_type_inventory'])}\nSchema acceptance .. {q['schema_acceptance_rate']}\nCorrelation keys ... {', '.join(q['correlation_join_mechanisms']) or 'none'}\nChains using multiple sources  {q['multi_source_chain_count']}\nAssessment .......... {q['status']}\nReport ............. {jp}")
        return (EXIT_OK if q["status"] in ("PASS", "WARN") else EXIT_EXPECTATION), report
    except Exception as e: return fail(str(e)), None

def command_validate(args) -> int:
    try: profile = load_profile(resolve_path(args.profile))
    except Exception as e: return fail(f"profile invalid: {e}")
    scenarios = profile["scenarios"]
    selected = [s for s in scenarios if not args.scenario or s["id"] == args.scenario]
    if not selected: return fail("no matching scenario")
    overall = EXIT_OK
    for s in selected:
        try:
            path = resolve_path(args.input) if args.input else resolve_path(s["input"], resolve_path(args.profile).parent.parent)
            q, raw, norm, chains = assess_data(path, int(s["correlation_window_seconds"]))
            alerts = run_all_detections(chains, window_seconds=int(s["correlation_window_seconds"]))
            baseline_alerts = None
            if s.get("baseline"):
                bpath = resolve_path(s["baseline"], resolve_path(args.profile).parent.parent)
                braw = load_input(bpath); bnorm = normalize_events(braw); bvalid, _ = validate_events(bnorm); bchains = build_correlation_chains(bvalid, window_seconds=int(s["correlation_window_seconds"])); baseline_alerts = run_all_detections(bchains, window_seconds=int(s["correlation_window_seconds"]))
            findings = expected_validation(s, alerts, baseline_alerts)
            report = {"controller": "DetectionLab Portable Validation Controller", "profile_id": profile["profile_id"], "profile_version": profile["profile_version"], "scenario_id": s["id"], "run_utc": datetime.now(timezone.utc).isoformat(), "pipeline_version": PIPELINE_VERSION, "telemetry_input": str(path), "input_files": [str(x) for x in input_files(path)], "input_hashes": {x.name: sha256(x) for x in input_files(path)}, "quality": q, "expected_detection_ids": sorted(s["expected_detection_ids"]), "observed_detection_ids": sorted({a.get("detection_id") for a in alerts}), "alerts": alerts, "expected_alert_count": s["expected_alert_count"], "observed_alert_count": len(alerts), "baseline_alert_count": len(baseline_alerts) if baseline_alerts is not None else None, "findings": findings, "trustworthy": q["status"] != "FAIL", "final_status": "PASS" if not findings and q["status"] != "FAIL" else "FAIL"}
            out = resolve_path(args.output_dir or "reports/validation") / s["id"]
            jp, mp = write_reports(report, out)
            if report["final_status"] != "PASS": overall = EXIT_EXPECTATION
            print(f"DetectionLab Portable Validation Controller\nEnvironment ........ READY\nProfile ............ VALID\nTelemetry sources .. {', '.join(q['source_type_inventory'])}\nSchema acceptance .. {q['schema_acceptance_rate']}\nCorrelation keys ... {', '.join(q['correlation_join_mechanisms']) or 'none'}\nChains using multiple sources  {q['multi_source_chain_count']}\nDetections expected  {s['expected_alert_count']}\nDetections observed  {len(alerts)}\nBaseline ........... {'PASS' if baseline_alerts is None or not baseline_alerts else 'FAIL'}\nValidation ......... {report['final_status']}\nReport ............. {jp}")
        except Exception as e: overall = EXIT_EXECUTION; print(f"[FAIL] scenario {s['id']}: {e}", file=sys.stderr)
    return overall

def command_gate(args) -> int:
    print("DetectionLab Engineering Gate")
    checks = []
    def run(label, cmd):
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        ok = p.returncode == 0; checks.append((label, ok)); print(f"{label:<30} {'PASS' if ok else 'FAIL'}")
        if not ok: print((p.stderr or p.stdout)[-1200:], file=sys.stderr)
        return ok
    ok = run("Repository health", [sys.executable, "-m", "compileall", "Pipeline"]) and run("Profile contracts", [sys.executable, "Pipeline/labctl.py", "doctor"]) and run("Replay regression 5/5", [sys.executable, "Pipeline/replay_harness.py", "--suite", "all", "--report"]) and run("Portable validation", [sys.executable, "Pipeline/labctl.py", "validate", "--profile", "profiles/detectionlab_regression.yml", "--scenario", "chain1_c2_beacon"])
    bad = Path(tempfile.mkdtemp(prefix="detectionlab-gate-")); (bad / "bad.json").write_text("{not json", encoding="utf-8")
    empty = bad / "empty"; empty.mkdir()
    invalid_profile = bad / "invalid.yml"; invalid_profile.write_text("profile_id: bad\nprofile_version: '9.9'\n", encoding="utf-8")
    failure_ok = all([
        subprocess.run([sys.executable, "Pipeline/labctl.py", "assess", "--input", str(bad)], cwd=ROOT, capture_output=True).returncode != 0,
        subprocess.run([sys.executable, "Pipeline/labctl.py", "assess", "--input", str(empty)], cwd=ROOT, capture_output=True).returncode != 0,
        subprocess.run([sys.executable, "Pipeline/labctl.py", "validate", "--profile", str(invalid_profile)], cwd=ROOT, capture_output=True).returncode != 0,
        subprocess.run([sys.executable, "Pipeline/labctl.py", "validate", "--profile", "profiles/missing.yml"], cwd=ROOT, capture_output=True).returncode != 0,
    ])
    checks.append(("Failure path checks", failure_ok)); print(f"{'Failure path checks':<30} {'PASS' if failure_ok else 'FAIL'}")
    integrity = run("Report integrity", [sys.executable, "-c", "import json; from pathlib import Path; p=Path('reports/validation/chain1_c2_beacon/validation_evidence.json'); m=Path('reports/validation/chain1_c2_beacon/validation_evidence.md'); d=json.loads(p.read_text()); assert d['final_status']=='PASS' and 'quality' in d and m.exists()"])
    export_contract = run("Windows export contract", [sys.executable, "-c", "from pathlib import Path; p=Path('windows/Export-DetectionLabTelemetry.ps1').read_text(); required=['sysmon_eid1.json','sysmon_eid3.json','sysmon_eid11.json','sysmon_eid13.json','sysmon_eid22.json','winsec_4624.json','winsec_4625.json','winsec_4672.json','winsec_4688.json','winsec_4698.json','winsec_7045.json']; assert all(x in p for x in required) and 'Get-WinEvent' in p and 'Remoting' not in p"])
    final = all(x[1] for x in checks) and integrity and export_contract
    print(f"{'CI compatible execution':<30} {'PASS' if final else 'FAIL'}\n\nFINAL STATUS ............. {'ACCEPTED' if final else 'FAILED'}")
    return EXIT_OK if final else EXIT_EXECUTION

def main() -> int:
    p = argparse.ArgumentParser(description="DetectionLab Portable Validation Controller")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doctor"); d.add_argument("--profile", default="profiles/detectionlab_regression.yml")
    i = sub.add_parser("init"); i.add_argument("--workspace", required=True)
    a = sub.add_parser("assess"); a.add_argument("--input", required=True); a.add_argument("--output-dir"); a.add_argument("--window", type=int, default=300)
    v = sub.add_parser("validate"); v.add_argument("--profile", required=True); v.add_argument("--input"); v.add_argument("--scenario"); v.add_argument("--output-dir")
    sub.add_parser("gate")
    args = p.parse_args()
    if args.command == "doctor": return command_doctor(args)
    if args.command == "init": return command_init(args)
    if args.command == "assess": return command_assess(args)[0]
    if args.command == "validate": return command_validate(args)
    return command_gate(args)

if __name__ == "__main__": sys.exit(main())
