#!/usr/bin/env bash
# Usage: sudo ./install_wazuh_agent.sh <MANAGER_IP>
set -euo pipefail
MANAGER_IP="${1:-192.168.56.10}"

echo "[+] Adding Wazuh APT repo..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

echo "[+] Installing wazuh-agent..."
sudo apt update && sudo apt -y install wazuh-agent

echo "[+] Pointing agent to manager at ${MANAGER_IP} ..."
sudo sed -i "s@<address>.*</address>@<address>${MANAGER_IP}</address>@" /var/ossec/etc/ossec.conf

echo "[+] Enabling and starting agent..."
sudo systemctl enable --now wazuh-agent

echo "[+] Done."
