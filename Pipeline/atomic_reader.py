"""
atomic_reader.py: Atomic Red Team test catalog and simulation selector

Reads Atomic Red Team YAML definition files directly from your local atomics
folder and produces a structured analysis of every available test for a given
technique. Tells you exactly which test number to run, what it does, what
executor it uses, and whether your environment can support it.

Usage:
    python Pipeline/atomic_reader.py --technique T1059.001
    python Pipeline/atomic_reader.py --technique T1059.001 --executor powershell
    python Pipeline/atomic_reader.py --technique T1059.001 --filter encoded
    python Pipeline/atomic_reader.py --technique T1059.001 --run-plan
    python Pipeline/atomic_reader.py --list
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML is required. Install it with: pip install pyyaml")
    sys.exit(1)


ATOMICS_PATH = Path("C:/AtomicRedTeam/atomics")

# Executors that work on Windows without special dependencies
WINDOWS_NATIVE_EXECUTORS = {"powershell", "command_prompt", "cmd"}

# Keywords that indicate an encoded/obfuscated PowerShell test
ENCODED_PS_KEYWORDS = {
    "encoded", "encodedcommand", "base64", "-enc", "obfuscat",
    "cradle", "invoke-expression", "iex", "bypass"
}


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def load_atomic_yaml(technique: str) -> Optional[dict]:
    """
    Load the Atomic Red Team YAML definition for a given technique ID.
    Tries both the technique folder directly and common filename patterns.
    """
    technique = technique.upper()
    technique_dir = ATOMICS_PATH / technique

    if not technique_dir.exists():
        print(f"[ERROR] Technique folder not found: {technique_dir}", file=sys.stderr)
        print(f"        Available techniques: run with --list to see all", file=sys.stderr)
        return None

    # Primary filename matches technique ID
    yaml_path = technique_dir / f"{technique}.yaml"
    if not yaml_path.exists():
        yaml_path = technique_dir / f"{technique}.yml"

    if not yaml_path.exists():
        # Fall back to any YAML in the folder
        yaml_files = list(technique_dir.glob("*.yaml")) + list(technique_dir.glob("*.yml"))
        if not yaml_files:
            print(f"[ERROR] No YAML definition found in {technique_dir}", file=sys.stderr)
            return None
        yaml_path = yaml_files[0]

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse {yaml_path}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Test analysis
# ---------------------------------------------------------------------------

def analyse_tests(
    data: dict,
    executor_filter: Optional[str] = None,
    keyword_filter: Optional[str] = None,
) -> list[dict]:
    """
    Extract and analyse all atomic tests from a loaded YAML definition.
    Returns a list of structured test summaries.
    """
    technique_id   = data.get("attack_technique", "Unknown")
    technique_name = data.get("display_name", "Unknown")
    raw_tests      = data.get("atomic_tests", [])

    results = []

    for i, test in enumerate(raw_tests, start=1):
        name        = test.get("name", "Unnamed test")
        description = test.get("description", "No description").strip()
        executor    = test.get("executor", {})
        exec_name   = executor.get("name", "unknown").lower()
        exec_cmd    = executor.get("command", executor.get("steps", ""))
        platforms   = [p.lower() for p in test.get("supported_platforms", [])]
        prereqs     = test.get("dependencies", [])
        input_args  = test.get("input_arguments", {})

        # Determine Windows compatibility
        windows_ok = "windows" in platforms
        native_ok  = exec_name in WINDOWS_NATIVE_EXECUTORS and windows_ok

        # Detect encoded PS indicators in name, description, or command
        combined_text = f"{name} {description} {exec_cmd}".lower()
        is_encoded_ps = any(kw in combined_text for kw in ENCODED_PS_KEYWORDS)

        # Apply filters
        if executor_filter and exec_name != executor_filter.lower():
            continue
        if keyword_filter and keyword_filter.lower() not in combined_text:
            continue

        # Summarise prerequisites
        prereq_summary = []
        for p in prereqs:
            prereq_summary.append({
                "description": p.get("description", ""),
                "check":       p.get("prereq_command", ""),
                "install":     p.get("get_prereq_command", ""),
            })

        results.append({
            "test_number":     i,
            "technique":       technique_id,
            "technique_name":  technique_name,
            "name":            name,
            "description":     description[:300],
            "executor":        exec_name,
            "platforms":       platforms,
            "windows_native":  native_ok,
            "is_encoded_ps":   is_encoded_ps,
            "has_prereqs":     len(prereqs) > 0,
            "prereq_count":    len(prereqs),
            "prereqs":         prereq_summary,
            "input_args":      list(input_args.keys()),
            "command_preview": str(exec_cmd)[:200] if exec_cmd else None,
            "recommendation":  _recommend(native_ok, prereqs, exec_name, windows_ok),
        })

    return results


def _recommend(native_ok: bool, prereqs: list, executor: str, windows_ok: bool) -> str:
    if not windows_ok:
        return "SKIP: not supported on Windows"
    if not native_ok:
        return f"SKIP: requires an executor other than the native one: {executor}"
    if len(prereqs) > 2:
        return "CAUTION: multiple prerequisites are required; check them before running"
    if len(prereqs) > 0:
        return "RUNNABLE: has prerequisites; verify them with -ShowPrereqs first"
    return "RUNNABLE: no prerequisites; safe to execute directly"


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_test_catalogue(tests: list[dict], verbose: bool = False) -> None:
    if not tests:
        print("\n  No tests match the specified filters.\n")
        return

    technique    = tests[0]["technique"]
    tech_name    = tests[0]["technique_name"]
    runnable     = [t for t in tests if "RUNNABLE" in t["recommendation"]]
    encoded_ps   = [t for t in tests if t["is_encoded_ps"]]

    print(f"\n{'═' * 70}")
    print(f"  Atomic Red Team: {technique}: {tech_name}")
    print(f"  Total tests: {len(tests)}  |  Runnable: {len(runnable)}  |  Encoded PS: {len(encoded_ps)}")
    print(f"{'═' * 70}\n")

    for t in tests:
        status = "✅" if "RUNNABLE" in t["recommendation"] and not t["has_prereqs"] else \
                 "⚠️ " if "CAUTION" in t["recommendation"] or ("RUNNABLE" in t["recommendation"] and t["has_prereqs"]) else "❌"

        encoded_tag = " [ENCODED-PS]" if t["is_encoded_ps"] else ""
        print(f"  {status} Test #{t['test_number']:02d}: {t['name']}{encoded_tag}")
        print(f"       Executor:  {t['executor']}  |  Platforms: {', '.join(t['platforms'])}")
        print(f"       Status:    {t['recommendation']}")

        if verbose:
            print(f"       Desc:      {t['description'][:120]}...")
            if t["command_preview"]:
                print(f"       Command:   {t['command_preview'][:100]}...")
            if t["prereqs"]:
                for p in t["prereqs"]:
                    print(f"       Prereq:    {p['description']}")

        print()

    if runnable:
        print(f"{'─' * 70}")
        print(f"  Recommended tests to run:")
        for t in runnable:
            tag = " ← encoded PS, matches DET-CHAIN-T1059.001-T1218.011-v1" if t["is_encoded_ps"] else ""
            print(f"    Invoke-AtomicTest {technique} -TestNumbers {t['test_number']}  # {t['name']}{tag}")
        print(f"{'─' * 70}\n")


def print_run_plan(tests: list[dict], technique: str) -> None:
    runnable = [t for t in tests if "RUNNABLE" in t["recommendation"] and not t["has_prereqs"]]
    encoded  = [t for t in runnable if t["is_encoded_ps"]]
    primary  = encoded if encoded else runnable[:3]

    print(f"\n{'═' * 70}")
    print(f"  Execution Plan: {technique}")
    print(f"{'═' * 70}\n")

    if not primary:
        print("  No directly runnable tests found without prerequisites.\n")
        return

    print("  Step 1: Run simulation:")
    for t in primary:
        print(f"\n    # Test #{t['test_number']}: {t['name']}")
        print(f"    Invoke-AtomicTest {technique} -TestNumbers {t['test_number']}")

    print("\n  Step 2: Capture telemetry immediately after execution:")
    print("""
    $since = (Get-Date).AddMinutes(-5)
    Get-WinEvent -LogName Security |
        Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -gt $since } |
        Select-Object Id, TimeCreated,
            @{N="Computer";E={$_.MachineName}},
            @{N="Message";E={$_.Message}} |
        ConvertTo-Json -Depth 5 |
        Out-File "C:\\DetectionLab_V2_fresh\\telemetry\\raw\\""" + f"{technique}_encoded_ps.json" + """ -Encoding UTF8
    """)

    print("  Step 3: Run pipeline against captured telemetry:")
    print(f"""
    python Pipeline/run_pipeline.py \\
        --input telemetry/raw/{technique}_encoded_ps.json \\
        --output reports/{technique}_validation.json \\
        --window 60
    """)

    print(f"{'─' * 70}\n")


# ---------------------------------------------------------------------------
# List all available techniques
# ---------------------------------------------------------------------------

def list_techniques() -> None:
    if not ATOMICS_PATH.exists():
        print(f"[ERROR] Atomics path not found: {ATOMICS_PATH}", file=sys.stderr)
        return

    techniques = sorted([
        d.name for d in ATOMICS_PATH.iterdir()
        if d.is_dir() and d.name.startswith("T")
    ])

    print(f"\n  Available techniques in {ATOMICS_PATH}")
    print(f"  Total: {len(techniques)}\n")

    for i, t in enumerate(techniques, 1):
        print(f"  {i:3d}. {t}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Atomic Red Team test catalogue and simulation selector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--technique", "-t",
        help="MITRE technique ID (e.g. T1059.001)",
    )
    parser.add_argument(
        "--executor", "-e",
        help="Filter by executor type (e.g. powershell, command_prompt)",
    )
    parser.add_argument(
        "--filter", "-f",
        help="Filter tests by keyword in name, description, or command",
    )
    parser.add_argument(
        "--run-plan",
        action="store_true",
        help="Output a complete execution and telemetry capture plan",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full descriptions and command previews",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all available technique folders",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text",
    )
    parser.add_argument(
        "--atomics-path",
        default=str(ATOMICS_PATH),
        help=f"Path to atomics folder (default: {ATOMICS_PATH})",
    )
    args = parser.parse_args()

    # Override atomics path if provided
    if args.atomics_path:
        ATOMICS_PATH = Path(args.atomics_path)

    if args.list:
        list_techniques()
        sys.exit(0)

    if not args.technique:
        parser.print_help()
        sys.exit(1)

    data = load_atomic_yaml(args.technique)
    if not data:
        sys.exit(1)

    tests = analyse_tests(
        data,
        executor_filter=args.executor,
        keyword_filter=args.filter,
    )

    if args.json:
        print(json.dumps(tests, indent=2))
    elif args.run_plan:
        print_run_plan(tests, args.technique.upper())
    else:
        print_test_catalogue(tests, verbose=args.verbose)
