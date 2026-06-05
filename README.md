# DetectionLab

![Detection Pipeline Validation](https://github.com/Bobby-Okafor/DetectionLab/actions/workflows/validate_pipeline.yml/badge.svg)

**Detection as Code portfolio** — multi-telemetry behavioural detections built across endpoint, network, and identity telemetry using a two-node Kali-Windows lab, Atomic Red Team adversary simulation, Python correlation pipelines, and Microsoft Sentinel KQL.

Every detection in this repository is:
- Validated against real Atomic Red Team telemetry captures
- Versioned and traceable through git history
- Regression-tested on every push via GitHub Actions
- Scored with entropy-based confidence metrics for noise reduction
- Documented with full provenance from simulation through alert output

---

## Detection as Code Methodology

Detections are treated as versioned, measurable systems — not isolated rules.

Each detection follows this lifecycle:

```
Adversary Behaviour (MITRE ATT&CK)
        ↓
Atomic Red Team Simulation (Kali → Windows lab)
        ↓
Telemetry Capture (Sysmon + Windows Security Events)
        ↓
Immutable Corpus Commit (telemetry/raw/<chain>/)
        ↓
Pipeline Replay (ingest → normalise → correlate → detect)
        ↓
Confidence Scoring (entropy + source diversity + field completeness)
        ↓
Validation Report (reports/validation/)
        ↓
Regression Test Case (Pipeline/replay_harness.py)
        ↓
CI Gate (GitHub Actions — green badge = all detections proven)
```

Any commit in the git history can be checked out and `python Pipeline/replay_harness.py --suite all` will reproduce the exact validation state at that point in time.

---

## ATT&CK Coverage Matrix

| Detection ID | Techniques | Behaviour | Sources | Status | Confidence |
|---|---|---|---|---|---|
| DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1 | T1059.001 + T1071.001 | Encoded PS → C2 beacon | Sysmon EID 1 + EID 3 | ✅ Validated | High |
| DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1 | T1110.001 + T1078 + T1059 | Brute force → auth exec | WinSec 4625 + 4624 + Sysmon EID 1 | ✅ Validated | High |
| DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1 | T1547.001 + T1053.005 | Registry + scheduled task persist | Sysmon EID 1 + EID 13 + WinSec 4698 | ✅ Validated | High |
| DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1 | T1543.003 + T1078 + T1059 | Priv logon → service → exec | WinSec 4624 + 4672 + 7045 + 4688 | ✅ Validated | High |

**Coverage: 4 validated**

---

## Lab Architecture

```
┌─────────────────────────────────────┐
│  Kali Linux 2024.3 (Attacker)       │
│  IP: 192.168.126.128                │
│  Tools: Hydra, Netcat, Impacket     │
│  Network: VMware Host-Only (VMnet1) │
└──────────────┬──────────────────────┘
               │ 192.168.126.0/24
┌──────────────┴──────────────────────┐
│  Windows 10 (Victim / Sensor)       │
│  Hostname: BOBBY                    │
│  IP: 192.168.126.1                  │
│  Sysmon: EID 1, 3, 11, 13, 22      │
│  Windows Security Auditing: enabled │
│  Atomic Red Team: installed         │
└─────────────────────────────────────┘
```

---

## Pipeline Architecture

```
Raw Telemetry
      │
      ▼
 ingest.py
      │
      ▼
 normalize.py
      │
      ▼
 schema_validator.py
      │
      ▼
 correlate.py
      │
      ▼
 CorrelationChain Objects
      │
      ▼
 detect.py
      │
      ▼
 Alert Objects
      │
      ▼
 replay_harness.py
      │
      ▼
 Validation Results
```

### Ingestion

`Pipeline/ingest.py` loads a validation corpus from either a single JSON file or a multi-file directory. Directory mode merges all JSON files in `telemetry/raw/<chain>/`, preserves source-file provenance through `_source_file`, and abstracts telemetry source type through filename-derived tags such as `sysmon_process`, `sysmon_network`, `winsec_logon_success`, `winsec_service`, and `winsec_privilege`.

### Normalization

`Pipeline/normalize.py` converts Sysmon flat key/value messages and Windows Security message text into a common event schema. It abstracts raw `Id`/`EventID` values into normalized `event_id`, converts timestamps to UTC ISO format, normalizes `LogonId` casing, and extracts source-specific fields such as `ProcessGuid`, `CommandLine`, `TargetObject`, `TaskName`, `ServiceName`, `SourceIp`, and privilege lists.

### Correlation

`Pipeline/correlate.py` builds `CorrelationChain` objects from normalized events. The correlation engine joins by high-specificity `ProcessGuid`, session-level `LogonId`, attacker `src_ip`, `user+host`, and scoped host/time joins for event types such as Windows Security 7045 that do not reliably carry user or logon context. Each chain records join fields, source diversity, event span, entropy, and composite confidence.

### Detection

`Pipeline/detect.py` operates on `CorrelationChain` objects, not raw events. Detections require cross-source evidence before firing, which means alerts represent validated behavior chains rather than isolated signatures. This is the boundary where telemetry correlation becomes detection logic.

### Validation

`Pipeline/replay_harness.py` replays committed corpora through ingestion, normalization, schema validation, correlation, and detection. Each test case asserts expected detection IDs, alert counts, severity, source diversity, confidence thresholds, and clean-baseline behavior. A passing replay is the acceptance gate for Detection-as-Code changes.

---

## Validation Methodology

Detections are validated using `Pipeline/replay_harness.py` against immutable telemetry corpora committed under `telemetry/raw/`.

Validation workflow:

1. Collect telemetry into immutable corpus directories under `telemetry/raw/`
2. Normalize telemetry into the canonical event schema
3. Execute schema validation
4. Correlate events using `ProcessGuid`, `LogonId`, source IP, and temporal joins
5. Execute detection logic against `CorrelationChain` objects
6. Generate structured alert objects
7. Validate expected detections using `replay_harness.py`

Run the replay validation suite:

```bash
python Pipeline/replay_harness.py --verbose
```

Current validation status:

| Detection | Status |
|---|---|
| ExecToC2 | PASS |
| BruteToExec | PASS |
| PersistenceEstablish | PASS |
| PrivEscToExec | PASS |
| Baseline | PASS |

Validation results:

- 5 passed
- 0 failed
- 0 skipped

Replay validation serves as regression testing for detection logic, correlation joins, schema expectations, and corpus integrity. A passing result means the corpus loads, schema validation succeeds, correlation chains are built, expected detections fire, and the clean baseline remains alert-free.

### Corpus Integrity Checks

Validation requires:

- Real correlation keys
- Real `ProcessGuid` relationships
- Real `LogonId` relationships
- Timestamp consistency across sources
- Multi-source corroboration
- A clean baseline that remains alert-free

---

## Validation Lessons Learned

### Chain1 ProcessGuid Investigation

Initial chain1 validation relied on synthetic `ProcessGuid` values recorded in `provenance.json`. Live Sysmon Event ID 1 and Event ID 3 collection showed those values did not exist in the actual telemetry emitted by the Windows sensor.

The correlation assumption was validated against live telemetry instead of being trusted from the simulation notes. The corpus was corrected using real `ProcessGuid` values extracted from Sysmon process creation and network connection events.

Detection logic did not require modification. The fix was made at the corpus-quality layer, and replay validation continued to pass after the corrected telemetry was committed.

This exercise demonstrated the importance of telemetry validation, corpus integrity, and evidence-based detection engineering before changing detection logic.

---

## Detection Registry

| Detection ID | Evidence | Join Model | ATT&CK | Validation Corpus |
|---|---|---|---|---|
| `DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1` | Sysmon EID 1 encoded PowerShell + Sysmon EID 3 network connection | `ProcessGuid` | T1059.001, T1071.001 | `telemetry/raw/chain1_c2_beacon/` |
| `DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1` | WinSec 4625 failures + WinSec 4624 success + Sysmon EID 1 execution | `src_ip`, `LogonId` | T1110.001, T1078, T1059 | `telemetry/raw/chain2_brute_exec/` |
| `DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1` | Sysmon EID 1 scripting process + Sysmon EID 13 registry persistence + WinSec 4698 scheduled task | `ProcessGuid`, `LogonId` | T1547.001, T1053.005 | `telemetry/raw/chain3_persistence/` |
| `DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1` | WinSec 4624 logon + WinSec 4672 privilege assignment + WinSec 7045 service install + WinSec 4688 execution | `LogonId`, scoped `host_time` for 7045 | T1543.003, T1078, T1059 | `telemetry/raw/chain4_priv_exec/` |

The registry is implemented in `Pipeline/replay_harness.py`. Each row above has a corresponding replay test case, Python detection path in `Pipeline/detect.py`, raw telemetry corpus under `telemetry/raw/`, and Sentinel KQL query under `kql/`.

---

## Replay Harness Usage

Run the full validation suite:

```bash
python Pipeline/replay_harness.py --suite all --verbose --report
```

Expected result:

```text
5 passed
0 failed
0 skipped
```

A passing suite confirms:

- Corpus files load successfully
- Schema validation accepts required fields
- Correlation chains are built
- Expected detections fire
- Source-diversity and confidence assertions pass
- Clean baseline produces zero alerts

---

## Corpus Inventory

| Corpus | Purpose | Sources | Expected Result |
|---|---|---|---|
| `chain1_c2_beacon` | Encoded PowerShell to C2 beacon | Sysmon EID 1, Sysmon EID 3 | `DET-CHAIN-T1059.001-T1071.001-ExecToC2-v1` |
| `chain2_brute_exec` | Brute force followed by authenticated execution | WinSec 4625, WinSec 4624, Sysmon EID 1 | `DET-CHAIN-T1110.001-T1078-T1059-BruteToExec-v1` |
| `chain3_persistence` | Registry Run key and scheduled task persistence | Sysmon EID 1, Sysmon EID 13, WinSec 4698 | `DET-CHAIN-T1547.001-T1053.005-PersistenceEstablish-v1` |
| `chain4_priv_exec` | Privileged logon to service installation and execution | WinSec 4624, WinSec 4672, WinSec 7045, WinSec 4688 | `DET-CHAIN-T1543.003-T1078-T1059-PrivEscToExec-v1` |
| `clean_baseline.json` | Benign baseline control | Sysmon + Windows Security baseline events | Zero alerts |

---

## Confidence Scoring

Every alert carries a composite confidence score derived from four factors:

| Factor | Weight | Description |
|---|---|---|
| Source diversity | 35% | How many distinct telemetry sources contributed |
| Shannon entropy | 25% | Distribution of events across source types |
| Field completeness | 20% | Ratio of populated fields in contributing events |
| Join field strength | 20% | Specificity of the correlation join (ProcessGuid > LogonId > IP > user+host) |

**Noise classification:**

| Score | Label | Triage guidance |
|---|---|---|
| ≥ 0.80 + 3 sources | SIGNAL | Prioritise — high confidence multi-source |
| ≥ 0.60 + 2 sources | LIKELY_SIGNAL | Investigate — cross-source corroboration |
| ≥ 0.40 | INVESTIGATE | Verify before escalating |
| < 0.40 | LOW_FIDELITY | Tune or suppress |

---

## Repository Structure

```text
DetectionLab/
│
├── Pipeline/                       # Detection as Code engine
│   ├── ingest.py                   # Multi-source ingestion
│   ├── normalize.py                # Sysmon + WinSec normalisation
│   ├── correlate.py                # Cross-telemetry correlation engine
│   ├── detect.py                   # Behavioural detection chains
│   ├── alert_schema.py             # Structured alert with confidence scoring
│   ├── schema_validator.py         # Field contract enforcement
│   ├── replay_harness.py           # Detection as Code regression tests
│   ├── run_pipeline.py             # CLI entry point
│   └── atomic_reader.py            # Atomic test catalogue reader
│
├── telemetry/
│   └── raw/                        # Immutable validation corpus
│       ├── chain1_c2_beacon/       # Sysmon EID 1 + EID 3
│       ├── chain2_brute_exec/      # WinSec 4625 + 4624 + Sysmon EID 1
│       ├── chain3_persistence/     # Sysmon EID 1 + EID 13 + WinSec 4698
│       ├── chain4_priv_exec/       # WinSec 4624 + 4672 + 7045 + 4688
│       └── clean_baseline.json     # Zero-alert baseline
│
├── attack_runs/                    # Simulation execution records
│   ├── chain1_T1059.001_T1071.001/
│   ├── chain2_T1110.001_T1078_T1059/
│   └── chain3_T1547.001_T1053.005/
│
├── reports/
│   ├── validation/                 # Per-detection validation reports
│   └── ci/                         # CI coverage reports
│
├── kql/                            # Microsoft Sentinel queries
├── requirements.txt                # Python dependency manifest
├── validation_report.txt           # Latest local replay evidence
│
└── .github/workflows/
    └── validate_pipeline.yml       # CI — runs replay harness on every push
```

---

## Quick Start

```bash
git clone https://github.com/Bobby-Okafor/DetectionLab.git
cd DetectionLab
pip install -r requirements.txt

# Run multi-source pipeline against C2 beacon telemetry
python Pipeline/run_pipeline.py \
  --input-dir telemetry/raw/chain1_c2_beacon \
  --output reports/validation/chain1_output.json \
  --window 60

# Run full regression suite
python Pipeline/replay_harness.py --suite all --verbose

# Browse Atomic test catalogue
python Pipeline/atomic_reader.py --technique T1059.001 --run-plan
```

---

## Tools and Stack

| Layer | Tool |
|---|---|
| Adversary simulation | Atomic Red Team, Hydra, Netcat, Impacket |
| Attacker platform | Kali Linux 2024.3 (VMware Host-Only) |
| Endpoint telemetry | Sysmon (EID 1, 3, 11, 13, 22) |
| Identity telemetry | Windows Security Events (4624, 4625, 4672, 4688, 4698, 7045) |
| SIEM / detection language | Microsoft Sentinel, KQL |
| Normalisation pipeline | Python 3.11+ |
| Detection format | Python + Sigma |
| Confidence scoring | Shannon entropy + composite weighting |
| Version control | Git, GitHub Actions CI |

---

## Author

**Bobby Okafor**
Detection Engineer — endpoint, identity, and network telemetry
[GitHub](https://github.com/Bobby-Okafor) · [LinkedIn](https://www.linkedin.com/in/bobby-okafor-40a521380)
