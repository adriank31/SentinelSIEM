#!/usr/bin/env bash
# Lightweight discovery commands that map to common ATT&CK discovery techniques.
set -euo pipefail
echo "[+] Host discovery (whoami, uname, ip, processes)"
whoami || true
uname -a || true
ip a || true
ps aux | head -n 20 || true
echo "[+] Done."
