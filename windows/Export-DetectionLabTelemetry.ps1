[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory, [int]$LookbackHours = 24)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$start = (Get-Date).AddHours(-1 * $LookbackHours)
function Export-Channel($LogName, $Ids, $FileName) {
  try {
    $events = Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$Ids; StartTime=$start} -ErrorAction Stop |
      Sort-Object TimeCreated | ForEach-Object { [ordered]@{Id=$_.Id; TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o'); ProviderName=$_.ProviderName; MachineName=$_.MachineName; Message=$_.Message} }
    @($events) | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory $FileName)
    Write-Host "Exported $($events.Count) events to $FileName"
  } catch { Write-Warning "Unable to export $LogName ($($Ids -join ',')): $($_.Exception.Message)" }
}
Export-Channel 'Microsoft-Windows-Sysmon/Operational' @(1) 'sysmon_eid1.json'
Export-Channel 'Microsoft-Windows-Sysmon/Operational' @(3) 'sysmon_eid3.json'
Export-Channel 'Microsoft-Windows-Sysmon/Operational' @(11) 'sysmon_eid11.json'
Export-Channel 'Microsoft-Windows-Sysmon/Operational' @(13) 'sysmon_eid13.json'
Export-Channel 'Microsoft-Windows-Sysmon/Operational' @(22) 'sysmon_eid22.json'
Export-Channel 'Security' @(4624) 'winsec_4624.json'
Export-Channel 'Security' @(4625) 'winsec_4625.json'
Export-Channel 'Security' @(4672) 'winsec_4672.json'
Export-Channel 'Security' @(4688) 'winsec_4688.json'
Export-Channel 'Security' @(4698) 'winsec_4698.json'
Export-Channel 'System' @(7045) 'winsec_7045.json'
Write-Host "Export complete. Existing logging policy was not changed; empty or unavailable channels require review before validation."
