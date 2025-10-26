<#
.SYNOPSIS
  Installs Wazuh agent on Windows and points it to the manager.
.USAGE
  Run as Administrator:
    .\install_wazuh_agent.ps1 -ManagerIP 192.168.56.10
#>
param(
  [Parameter(Mandatory=$false)][string]$ManagerIP = "192.168.56.10"
)

$DownloadUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent.msi"
$msi = "$env:TEMP\wazuh-agent.msi"

Write-Host "[+] Downloading Wazuh Agent: $DownloadUrl"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $msi

Write-Host "[+] Installing Wazuh Agent..."
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn WAZUH_MANAGER=`"$ManagerIP`"" -Wait -NoNewWindow

Write-Host "[+] Starting service..."
Start-Service WazuhSvc
Get-Service Wazuh* | Format-Table Name,Status

Write-Host "[+] Installed. Verify enrollment in the Wazuh dashboard Agents page."
