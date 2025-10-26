# VM_Setup_Guide — VirtualBox + OS ISOs + Networking (SentinelSIEM)

This guide takes you from a clean host to a working **3‑VM** lab for **SentinelSIEM**:
- **Wazuh‑Manager** (Ubuntu 22.04 LTS) — `192.168.56.10`
- **Win10‑Workstation** (Windows 10) — `192.168.56.20`
- **Kali‑Attacker** (Kali Linux) — `192.168.56.30`

Each VM has **two NICs**:
- **Adapter 1:** Host‑only (`vboxnet0`) — *static IPs*
- **Adapter 2:** NAT — *Internet access for updates/tools*

---

## 1) Install VirtualBox & Get OS ISOs (Official sources)

### VirtualBox (host)
1) Download and install **VirtualBox** for your host OS.  
   • Community downloads: https://www.virtualbox.org/wiki/Downloads  
   • (Optional) **Extension Pack** (match your VirtualBox version): https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html

> The Extension Pack enables features like USB 2.0/3.0, RDP, PXE boot, etc. It must match your installed VirtualBox version.

### Ubuntu 22.04 LTS (Jammy) ISO
- Ubuntu 22.04 LTS (Jammy) release page (Desktop images available):  
  https://releases.ubuntu.com/jammy/

### Windows 10 ISO
- Microsoft **Windows 10** download page (ISO / Media Creation Tool):  
  https://www.microsoft.com/software-download/windows10

> Microsoft now prioritizes Windows 11, but the Windows 10 ISO remains available from the page above.

### Kali Linux ISO
- **Get Kali** (official download hub): https://www.kali.org/get-kali/  
- (Recommended) **Verify your download** (checksums + GPG):  
  https://www.kali.org/docs/introduction/download-official-kali-linux-images/  
  https://www.kali.org/docs/introduction/download-images-securely/

---

## 2) Create the Host‑Only Network (`vboxnet0`)

In **VirtualBox Manager**: **File → Tools → Network Manager → Host‑only Networks**  
1) **Create** a Host‑only network named `vboxnet0`.  
2) Set **IPv4 Address** = `192.168.56.1`, **Mask** = `255.255.255.0`.  
3) **DHCP Server**: either **Disable**, or set the **Start** to `192.168.56.101` (so our static `.10/.20/.30` IPs never collide).

We’ll use `192.168.56.0/24` for East/West traffic between VMs.

---

## 3) Create the Three VMs (base settings)

Attach **two adapters** to each VM:
- Adapter 1 = **Host‑only** (`vboxnet0`)
- Adapter 2 = **NAT**

Suggested resources (tune to your host capacity):
| VM                | OS Image                | vCPU | RAM   | Disk (VDI, dynamic) |
|-------------------|-------------------------|------|-------|---------------------|
| Wazuh‑Manager     | Ubuntu 22.04 LTS ISO    | 4    | 8–12G | 80–120G             |
| Win10‑Workstation | Windows 10 ISO          | 4    | 6–8G  | 80–120G             |
| Kali‑Attacker     | Kali ISO                | 2–4  | 4–8G  | 40–80G              |

Mount each ISO: **Settings → Storage → (Controller) → Add optical drive → Choose disk**.

> You can add **Guest Additions** after install for better display/clipboard integration (optional).

---

## 4) Install the Operating Systems

Boot each VM from its ISO and install normally:
- **Ubuntu 22.04 LTS** → Standard **Desktop** install.
- **Windows 10** → Use the ISO (or Media Creation Tool to make USB media).
- **Kali Linux** → Choose the **Installer** image for a persistent VM.

After install, confirm **Internet** works via **NAT** (e.g., browse a site in Windows; `ping 8.8.8.8` in Ubuntu/Kali).

---

## 5) Assign Static IPs (Host‑only NIC only)

We pin the **Host‑only** addresses and leave **NAT** on DHCP.

### Ubuntu (Wazuh‑Manager) — `192.168.56.10/24`
Find NIC names:
```bash
ip addr show
```
Create `/etc/netplan/02-hostonly.yaml`:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:      # NAT NIC (name may differ)
      dhcp4: true
    enp0s8:      # Host-only NIC (name may differ)
      dhcp4: false
      addresses: [192.168.56.10/24]
```
Apply:
```bash
sudo netplan generate && sudo netplan apply
ip addr show enp0s8
```

### Windows 10 (Workstation) — `192.168.56.20/24`
Admin **PowerShell**:
```powershell
Get-NetAdapter | Sort-Object ifIndex | ft ifIndex,Name,Status
# Replace "Ethernet 2" with your Host-only NIC name:
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.20 -PrefixLength 24
```

### Kali (Attacker) — `192.168.56.30/24`
```bash
# Replace enp0s8 with your Host-only ifname
sudo nmcli con add type ethernet ifname enp0s8 con-name hostonly \
  ipv4.method manual ipv4.addresses 192.168.56.30/24 ipv4.gateway "" ipv4.dns ""
sudo nmcli con up hostonly
ip addr show enp0s8
```

> **Do not** set a default gateway on Host‑only. Leave **NAT** adapter on DHCP so Internet continues to work.

---

## 6) Verify the Connectivity Matrix

From **each VM**, ping the others on Host‑only IPs:

- From **Ubuntu**:
  ```bash
  ping -c 2 192.168.56.20
  ping -c 2 192.168.56.30
  ```
- From **Windows** (PowerShell):
  ```powershell
  Test-Connection -Count 2 192.168.56.10
  Test-Connection -Count 2 192.168.56.30
  ```
- From **Kali**:
  ```bash
  ping -c 2 192.168.56.10
  ping -c 2 192.168.56.20
  ```

All six pings should succeed.

---

## 7) Take Baseline Snapshots

In **VirtualBox Manager**, take snapshots:
- After OS install (`base-os`)
- After networking works (`net-configured`)
- Before/after major installs/tests (`post-wazuh`, `pre-atomic`, etc.)

Snapshots make rollback painless during testing and rule‑tuning.

---

## Appendix — Official Download Links (for convenience)

- **VirtualBox** (base packages): https://www.virtualbox.org/wiki/Downloads  
- **VirtualBox Extension Pack**: https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html  
- **Ubuntu 22.04 LTS (Jammy) releases**: https://releases.ubuntu.com/jammy/  
- **Windows 10 ISO / Media Creation Tool**: https://www.microsoft.com/software-download/windows10  
- **Kali Linux — Get Kali**: https://www.kali.org/get-kali/  
- **Kali — Verify downloads (checksums + GPG)**: https://www.kali.org/docs/introduction/download-official-kali-linux-images/  
  and https://www.kali.org/docs/introduction/download-images-securely/
