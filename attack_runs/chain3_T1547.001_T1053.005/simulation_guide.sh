# Chain 3: Persistence Establishment via Registry + Scheduled Task
# Victim: Windows BOBBY (192.168.126.1)
# Techniques: T1547.001 + T1053.005

# ============================================================
# STEP 1 — Windows: Run Atomic persistence tests
# ============================================================

# Registry Run key persistence (T1547.001)
# Invoke-AtomicTest T1547.001 -TestNumbers 1

# Scheduled task persistence (T1053.005)
# Invoke-AtomicTest T1053.005 -TestNumbers 4

# Or manually simulate combined persistence:
# powershell -ExecutionPolicy Bypass -Command @"
#   New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
#     -Name 'SecurityUpdate' `
#     -Value 'C:\Users\LENOVO\AppData\Roaming\update.exe' `
#     -PropertyType String -Force
#
#   schtasks /create /sc onlogon /tn 'SecurityUpdate' `
#     /tr 'C:\Users\LENOVO\AppData\Roaming\update.exe' /f
# "@

# ============================================================
# STEP 2 — Windows: Capture telemetry
# ============================================================

# $since = (Get-Date).AddMinutes(-5)
#
# Sysmon EID 1 (PowerShell process)
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
#     Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain3_persistence\sysmon_eid1.json" -Encoding UTF8
#
# Sysmon EID 13 (registry writes)
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
#     Where-Object { $_.Id -eq 13 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain3_persistence\sysmon_eid13.json" -Encoding UTF8
#
# WinSec 4698 (scheduled task created)
# Get-WinEvent -LogName Security |
#     Where-Object { $_.Id -eq 4698 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain3_persistence\winsec_4698.json" -Encoding UTF8

# ============================================================
# STEP 3 — Cleanup after simulation
# ============================================================

# Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityUpdate' -ErrorAction SilentlyContinue
# schtasks /delete /tn 'SecurityUpdate' /f

# ============================================================
# STEP 4 — Validate
# ============================================================

# python Pipeline/run_pipeline.py \
#     --input-dir telemetry/raw/chain3_persistence \
#     --output reports/validation/chain3_validation.json \
#     --window 120

# python Pipeline/replay_harness.py --test chain3_persistence --verbose
