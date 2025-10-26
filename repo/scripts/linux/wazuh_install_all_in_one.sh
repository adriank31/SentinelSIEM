#!/usr/bin/env bash
set -euo pipefail
echo "[+] Updating system..."
sudo apt update && sudo apt -y upgrade

echo "[+] Downloading Wazuh installer..."
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh

echo "[+] Running all-in-one install (Manager + Indexer + Dashboard)..."
sudo bash ./wazuh-install.sh -a

echo "[+] Done. Access dashboard at: https://192.168.56.10:5601 (accept self-signed cert)"
