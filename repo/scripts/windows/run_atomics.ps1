<#
.SYNOPSIS
  Installs Invoke-AtomicRedTeam and runs a small set of low-impact tests.
#>

Write-Host "[+] Installing Invoke-AtomicRedTeam framework from PowerShell Gallery..."
try {
  Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
} catch {
  Register-PSRepository -Default -ErrorAction SilentlyContinue
  Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
}

Import-Module Invoke-AtomicRedTeam

Write-Host "[+] Getting prerequisites for select tests (downloads atomics)..."
Get-AtomicTechnique -Technique T1059.001,T1112,T1047 | ForEach-Object {
  Invoke-AtomicTest $_.Technique -GetPrereqs -Confirm:$false
}

Write-Host "[+] Running T1059.001 (PowerShell) test #1..."
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Confirm:$false

Write-Host "[+] Running T1112 (Modify Registry) test #1..."
Invoke-AtomicTest T1112 -TestNumbers 1 -Confirm:$false

Write-Host "[+] Running T1047 (WMI) test #1..."
Invoke-AtomicTest T1047 -TestNumbers 1 -Confirm:$false

Write-Host "[+] Done. Check Wazuh alerts and dashboards."
