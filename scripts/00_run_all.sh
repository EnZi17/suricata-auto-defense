#!/bin/bash
# scripts/00_run_all.sh
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == --help ]]; then
  echo "Usage: sudo bash $0"
  exit 0
fi
[[ $# -eq 0 ]] || { echo 'Unknown argument.' >&2; exit 1; }
trap 'echo "Startup failed at line $LINENO; inspect journalctl -u suricata -u suricata-defense -n 50" >&2' ERR

if [ "$EUID" -ne 0 ]; then
  echo "[-] Vui lòng chạy bằng sudo."
  exit 1
fi

echo "[+] Khởi động toàn bộ hệ thống Suricata IDS/IPS..."

bash "$SCRIPT_DIR/01_setup_suricata.sh"
bash "$SCRIPT_DIR/02_rule_manager.sh" --install
systemctl restart suricata
for ((i=0; i<30; i++)); do
    [[ -f /var/log/suricata/eve.json ]] && break
    sleep 1
done
[[ -f /var/log/suricata/eve.json ]] || { echo 'Missing eve.json'; exit 1; }
systemctl enable --now suricata-defense
systemctl restart suricata-defense
sleep 2
systemctl is-active --quiet suricata suricata-defense
echo '[+] IDS and UFW defense started. Target: 10.203.0.1; attacker: 10.203.0.2'
echo '[+] Alerts: /var/log/suricata/eve.json; block log: /var/log/suricata_blocked_ips.log'
