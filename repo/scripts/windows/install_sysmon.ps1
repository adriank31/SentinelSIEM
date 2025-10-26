<#
.SYNOPSIS
  Installs Sysmon and applies a community configuration.

.NOTES
  - Requires admin PowerShell.
  - Downloads Sysmon from Microsoft Sysinternals page if winget is unavailable.
  - Downloads a community Sysmon config (SwiftOnSecurity by default).
#>

param(
  [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
)

function Install-Sysmon {
  Write-Host "[+] Installing Sysmon..."

  # Try winget first (Win10/11 with winget)
  $winget = (Get-Command winget -ErrorAction SilentlyContinue)
  if ($winget) {
    try {
      winget install --id Microsoft.Sysinternals.Sysmon -e -h
    } catch {
      Write-Warning "winget install failed, falling back to manual download..."
    }
  }

  if (-not (Get-Command sysmon64.exe -ErrorAction SilentlyContinue)) {
    $tmp = "$env:TEMP\sysmon.zip"
    $url = "https://download.sysinternals.com/files/Sysmon.zip"
    Write-Host "[+] Downloading Sysmon from $url"
    Invoke-WebRequest -Uri $url -OutFile $tmp
    Expand-Archive -LiteralPath $tmp -DestinationPath "$env:ProgramData\Sysmon" -Force
    $env:PATH += ";$env:ProgramData\Sysmon"
  }

  if (-not (Get-Command sysmon64.exe -ErrorAction SilentlyContinue)) {
    throw "Sysmon not found. Please install manually from https://learn.microsoft.com/sysinternals/downloads/sysmon"
  }
}

function Apply-SysmonConfig {
  param([string]$ConfigUrl)
  $cfg = "$env:TEMP\sysmon.xml"
  Write-Host "[+] Downloading Sysmon config: $ConfigUrl"
  Invoke-WebRequest -Uri $ConfigUrl -OutFile $cfg

  Write-Host "[+] Installing Sysmon service with config..."
  & sysmon64.exe -accepteula -i $cfg | Write-Host
  Start-Sleep -Seconds 2
  Get-Service Sysmon64 | Format-Table Name,Status,StartType
}

Install-Sysmon
Apply-SysmonConfig -ConfigUrl $ConfigUrl
Write-Host "[+] Sysmon installed and configured."
