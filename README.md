# Detection-Pipeline-Prototype-

This repository contains a lightweight Python-based detection pipeline for analyzing Windows process telemetry and identifying multi-event attack patterns.


## Pipeline Capabilities
- Ingests raw JSON logs with inconsistent encoding
- Parses Windows Event ID 4688 process creation events
- Normalizes timestamps for accurate event sequencing
- Structures process, parent, and command-line data

## Detection Approach
Focuses on behavioral correlation rather than single-event indicators.

Current detection:
- Encoded PowerShell → rundll32 execution (stateful chain)

## Key Insight
Detection reliability depends on correct event ordering.

Raw telemetry contained inconsistent timestamp formats, which broke correlation logic. This pipeline resolves that by normalizing time before detection.

## Purpose
Demonstrates detection engineering concepts:
- Log normalization
- Time-based correlation
- Behavioral detection logic
- False positive awareness
