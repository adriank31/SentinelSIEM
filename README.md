# SentinelSIEM — Threat Detection & Incident Response Lab (Wazuh + ELK)

Reproducible, security-first SOC lab using **Wazuh (Manager + Indexer + Dashboard)** with **Windows 10** and **Kali Linux** endpoints. Collect telemetry (Sysmon + Wazuh agent), create detections (Sigma/Wazuh rules), emulate adversary behavior (Atomic Red Team), and produce incident reports mapped to **MITRE ATT&CK**.

> **Scope:** Single-node, lab-grade deployment for training and portfolio projects. For production, split roles, harden access, and follow the assisted or step-by-step install guides from Wazuh.

---

## What you’ll build

- **Wazuh all-in-one** on Ubuntu 22.04 (Manager + Indexer + Dashboard).
- **Windows 10** workstation with **Sysmon** (rich endpoint telemetry) + **Wazuh Agent**.
- **Kali** attacker VM with optional Wazuh agent and **Atomic Red Team** to trigger detections.
- **Custom detections** (Sigma → Wazuh local rules) and **Wazuh/Kibana dashboards**.
- **Incident reports** with timelines & MITRE ATT&CK mappings (e.g., T1059.001 PowerShell, T1047 WMI, T1112 Modify Registry).

---

## Table of Contents

1. [Architecture](#architecture)  
2. [Requirements](#requirements)  
3. [VirtualBox Networking](#virtualbox-networking)  
4. [Static IP Configuration](#static-ip-configuration)  
5. [Install Wazuh (Ubuntu)](#install-wazuh-ubuntu)  
6. [Windows 10: Sysmon + Wazuh Agent](#windows-10-sysmon--wazuh-agent)  
7. [Kali: Wazuh Agent (optional)](#kali-wazuh-agent-optional)  
8. [Detections: Sigma → Wazuh](#detections-sigma--wazuh)  
9. [Atomic Red Team: Run Tests](#atomic-red-team-run-tests)  
10. [Dashboards](#dashboards)  
11. [Incident Reports](#incident-reports)  
12. [Validation Checklist](#validation-checklist)  
13. [Troubleshooting](#troubleshooting)  
14. [Security Notes](#security-notes)  
15. [Repo Layout](#repo-layout)  
16. [Screenshots to Capture](#screenshots-to-capture)  
17. [References](#references)  
18. [License & Acknowledgements](#license--acknowledgements)

---

## Architecture

<img width="4598" height="1338" alt="Untitled diagram-2025-10-26-194944" src="https://github.com/user-attachments/assets/41b8ab80-fd36-4312-ade8-5fbf128aa43a" />

---

```
          Internet (NAT)
               │
     ┌─────────┼─────────┐
     │         │         │
 [Ubuntu]   [Windows]   [Kali]
 Wazuh/ELK   Sysmon+Agent  Atomic + Agent
 192.168.56.10  .20         .30
     │           │           │
     └──────── Host-only vboxnet0 (192.168.56.0/24) ─────────┘
```

**NICs per VM**
- Adapter 1: **Host-only** (`vboxnet0`) — static IPs
- Adapter 2: **NAT** — Internet for updates/tools

**Static IP Plan**

| VM                | OS             | Host-only IP     |
|-------------------|----------------|------------------|
| Wazuh-Manager     | Ubuntu 22.04   | `192.168.56.10`  |
| Win10-Workstation | Windows 10     | `192.168.56.20`  |
| Kali-Attacker     | Kali Linux     | `192.168.56.30`  |

> **DHCP Note:** Disable Host-only DHCP or set its pool to start ≥ `.101` so `.10/.20/.30` never collide.

---

## Requirements

- **VirtualBox** + Extension Pack
- Host with **16 GB RAM (min)**, **8 vCPU recommended**, ~120 GB free disk
- ISOs/VMs: Ubuntu 22.04, Windows 10, Kali (latest)
- Internet access (through NAT)
- Basic CLI & PowerShell familiarity

---

## VirtualBox Networking

1. **Create Host-only network**: `vboxnet0`
   - Host IP: `192.168.56.1`
   - DHCP: **Off** (or pool start ≥ `192.168.56.101`)
2. On **each VM**:
   - Adapter 1 = **Host-only** (`vboxnet0`)
   - Adapter 2 = **NAT**

**Connectivity Test (after static IPs):**
- Ping each VM ↔ each VM by Host-only IP.

---

## Static IP Configuration

### Ubuntu 22.04 (Wazuh VM)

Identify NICs:
```bash
ip addr show
```

Create `/etc/netplan/02-hostonly.yaml`:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:   # NAT
      dhcp4: true
    enp0s8:   # Host-only
      dhcp4: false
      addresses: [192.168.56.10/24]
```

Apply & verify:
```bash
sudo netplan generate && sudo netplan apply
ip addr show enp0s8
```

### Windows 10 (Workstation)

Admin PowerShell:
```powershell
Get-NetAdapter | Sort-Object ifIndex | ft ifIndex,Name,Status
# Replace "Ethernet 2" with your Host-only NIC name
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.20 -PrefixLength 24
```

### Kali (Attacker)

```bash
# Replace enp0s8 with your Host-only ifname
sudo nmcli con add type ethernet ifname enp0s8 con-name hostonly \
  ipv4.method manual ipv4.addresses 192.168.56.30/24 ipv4.gateway "" ipv4.dns ""
sudo nmcli con up hostonly
```

---

## Install Wazuh (Ubuntu)

> Single-node, all-in-one for labs. Use the **wazuh-install.sh** quickstart script to deploy Manager, Indexer, and Dashboard together.

```bash
sudo apt update && sudo apt -y upgrade
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Access dashboard from the host browser:
- `https://192.168.56.10:5601` (accept self-signed cert)
- Store the credentials shown by the installer

> For more granular or multi-node installs, follow Wazuh’s assisted or step-by-step guides.

---

## Windows 10: Sysmon + Wazuh Agent

1. **Install Sysmon**  
   Download Sysmon (Sysinternals). Use a reputable community config like **SwiftOnSecurity** or **Olaf Hartong’s modular** to get high-signal events out of the box.

   Admin PowerShell:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Sysmon64.exe -i .\sysmonconfig.xml
   Get-Service Sysmon64
   ```

2. **Install Wazuh Agent (Windows)**  
   Use the Wazuh dashboard’s **Deploy new agent** workflow or the Windows agent package. Set **Manager address** to your Wazuh server (`192.168.56.10`).

   Verify:
   ```powershell
   Get-Service | ? Name -like "Wazuh*" | ft Name,Status
   ```

**Expected:** Windows host appears **Active** in Wazuh Agents and Sysmon events begin to flow.

---

## Kali: Wazuh Agent (optional)

```bash
sudo apt update
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt -y install wazuh-agent
sudo sed -i 's@<address>.*</address>@<address>192.168.56.10</address>@' /var/ossec/etc/ossec.conf
sudo systemctl enable --now wazuh-agent
```

---

## Detections: Sigma → Wazuh

Place Sigma rules under `detections/sigma/`. Example (PowerShell download cradle):

`detections/sigma/windows_powershell_download.yml`
```yaml
title: Suspicious PowerShell Download Cradle
id: 7a2a9c2e-0b52-4a8a-b0b7-ps-download
status: experimental
description: Detects PowerShell web download cradles
author: Your Name
logsource:
  product: windows
  service: powershell
detection:
  selection:
    Message|contains:
      - "Invoke-WebRequest"
      - "DownloadString"
      - "IEX(New-Object Net.WebClient)"
  condition: selection
fields:
  - Computer
  - User
  - Message
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

Translate/tune in Wazuh via **local rules** (manager):

`/var/ossec/etc/rules/local_rules.xml`
```xml
<group name="windows,sysmon,powershell,">
  <rule id="100001" level="8">
    <if_group>sysmon_event1|windows-powershell</if_group>
    <field name="win.eventdata.Image">.*powershell\.exe</field>
    <match>Invoke-WebRequest|DownloadString|IEX\(New-Object Net\.WebClient\)</match>
    <description>Suspicious PowerShell download cradle detected</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <options>no_full_log</options>
  </rule>
</group>
```

Apply & watch:
```bash
sudo systemctl restart wazuh-manager
tail -f /var/ossec/logs/ossec.log
```

> **Tip:** Adjust `<if_group>` and `<field>` to match your exact decoders/fields (Sysmon Event ID 1 / PowerShell 4104).

---

## Atomic Red Team: Run Tests

> Run **inside this lab only**. Choose low-impact tests you can easily revert.

**Windows (Admin PowerShell):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1 -UseBasicParsing | iex
Install-AtomicRedTeam

# Execution: PowerShell (T1059.001)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Confirm:$false

# Registry (T1112)
Invoke-AtomicTest T1112 -TestNumbers 1 -Confirm:$false

# WMI (T1047)
Invoke-AtomicTest T1047 -TestNumbers 1 -Confirm:$false
```

**Expected:** Your local rule and/or built-in rules alert. You’ll see the alert in **Security events / Alerts** and related Sysmon/PowerShell logs.

---

## Dashboards

- In Wazuh/Kibana, create:
  - **Events over time** (filter to your hosts)
  - **Top Processes / Users / Hosts**
  - **ATT&CK tags** or **Rule IDs** breakdown
- Export to NDJSON and store in `dashboards/`.

Import (another environment):
- **Stack Management → Saved Objects → Import** your NDJSON.

---

## Incident Reports

Create **investigation write-ups** under `incidents/` using this template:

`incidents/incident_report_template.md`
```markdown
# Incident Report — <Title>

## Summary
Short paragraph describing detection and outcome.

## Scope
- Host: <hostname> (<ip>)
- User: <user>
- Timeframe: <start> → <end>

## Timeline
- <time> Detection fired (Rule ID / Name)
- <time> Correlated event(s) (Sysmon ID, fields)
- <time> Containment/Remediation

## Detection & Telemetry
- Rule(s): IDs, names, excerpts
- Source logs: Sysmon 1/3/7/11/4688, PowerShell 4104, etc.

## MITRE ATT&CK Mapping
- Tactic(s): <e.g., Execution>
- Technique(s): T1059.001 (PowerShell)
- Evidence: link to alert/events

## Root Cause
Atomic Red Team emulation: <test id / command>

## Recommendations
- <control 1>, <control 2>

## Screenshots
- Insert Wazuh alert, event details, dashboard view
```

---

## Validation Checklist

- Host-only DHCP disabled or pool ≥ `.101`
- Static IPs: Ubuntu `.10`, Windows `.20`, Kali `.30`
- Ping matrix succeeds between all VMs
- Wazuh Dashboard reachable at `https://192.168.56.10:5601`
- Windows agent **Active**; Sysmon events observed
- (Optional) Kali agent **Active**
- Sigma/Wazuh rule installed & alerts on Atomic tests
- Dashboard shows time-series spikes during tests
- At least one incident report added with screenshots

---

## Troubleshooting

**Agent not showing up**
- Verify manager IP in agent config (`ossec.conf`)
- Check logs:
  - Manager: `/var/ossec/logs/ossec.log`
  - Windows: `C:\Program Files (x86)\ossec-agent\ossec.log`
- Local firewalls: allow Host-only subnet (ICMP for testing)

**No Sysmon events**
- Ensure Sysmon installed & running: `Get-Service Sysmon64`
- Confirm your Sysmon config enables process/network logs
- Check Event Viewer → **Applications and Services Logs → Microsoft → Windows → Sysmon/Operational**

**Rule not firing**
- Compare event fields vs. your `<field>` and `<match>` patterns
- Tail `ossec.log` during test
- Increase rule `level` only after confirming matches

**No Internet in VMs**
- NAT adapter must be enabled and DHCP on

---

## Security Notes

- **Isolate** the lab (Host-only for East/West, NAT only for updates)
- Restrict Dashboard to Host-only bind, gate with UFW
- Rotate default credentials & store in a password manager
- Snapshot before/after major changes and before running Atomics
- Do **not** run Atomics outside of owned/test networks

---

## Repo Layout

```
.
├─ README.md
├─ VM_Setup_Guide.md
├─ detections/
│  └─ sigma/
│     └─ windows_powershell_download.yml
├─ incidents/
│  ├─ incident_report_template.md
│  └─ incident_report_T1059_001.md
├─ dashboards/
│  ├─ wazuh_overview.ndjson
│  └─ screenshots/
│     ├─ kibana_dashboard_overview.png
│     └─ kibana_attack_tactics.png
├─ scripts/
│  ├─ atomic_examples.ps1
│  └─ linux_helpers.sh
└─ snapshots/
   └─ notes.md
```

---

## Screenshots to Capture
Whatever you want to capture or you do NOT have to capture anything at all.

---

## References

- **Wazuh Quickstart / Install script** — https://documentation.wazuh.com/current/quickstart.html  
- **Wazuh Agent (Windows) install** — https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html  
- **Wazuh Agent (Overview/Deploy New Agent)** — https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html  
- **Sysmon (Sysinternals)** — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon  
- **Sysmon configs**:  
  - SwiftOnSecurity — https://github.com/SwiftOnSecurity/sysmon-config  
  - Olaf Hartong (modular) — https://github.com/olafhartong/sysmon-modular  
- **Atomic Red Team / Invoke-AtomicRedTeam** — https://github.com/redcanaryco/invoke-atomicredteam  
  - Install guide — https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam  
- **MITRE ATT&CK T1059.001 (PowerShell)** — https://attack.mitre.org/techniques/T1059/001/

---

## License & Acknowledgements

- This repo is for **educational/testing** purposes. Offensive actions must remain within this isolated lab.
- Thanks to **Wazuh**, **Elastic**, **Microsoft Sysinternals**, and **Red Canary** (Atomic Red Team) for their tooling and docs.
