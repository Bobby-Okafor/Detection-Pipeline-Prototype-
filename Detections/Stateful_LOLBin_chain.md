
# Detection: Stateful LOLBin Execution Chain

## Summary
Detection of multi-event behavior where encoded PowerShell execution is followed by rundll32 execution within a short time window.

## Why This Matters
Single events are often benign. However, chained behavior across processes is more indicative of malicious activity.

This pattern reflects:
- Defense evasion (encoded PowerShell)
- LOLBin abuse (rundll32)
- Multi-stage execution

## Detection Logic
1. Identify PowerShell execution with encoded commands
2. Track subsequent process events within a 60-second window
3. Flag if rundll32.exe is executed shortly after

## Key Insight
Detection is not based on a single log, but on **event sequencing over time**

## Pipeline Role
- Normalizes inconsistent timestamps
- Orders events chronologically
- Enables reliable time-window correlation

## Challenges
- Raw timestamps were inconsistent (milliseconds vs ISO format)
- Without normalization, event sequencing was unreliable

## False Positives
- Admin scripts invoking encoded PowerShell
- Legitimate rundll32 usage (rare but possible)

## Improvements
- Add parent-child validation
- Add network correlation
- Introduce scoring instead of binary alerts
