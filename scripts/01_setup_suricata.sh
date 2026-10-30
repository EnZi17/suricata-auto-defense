#!/bin/bash
# scripts/01_setup_suricata.sh

set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(dirname -- "$SCRIPT_DIR")
if [[ ${1:-} == --help ]]; then
  echo "Usage: sudo bash $0 (Ubuntu 24.04 single-VM lab)"
  exit 0
fi
[[ $# -eq 0 ]] || { echo 'This model captures suri-host; no --iface argument is needed.' >&2; exit 1; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 is required.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'systemd is required.' >&2; exit 1; }
trap 'echo "Setup failed at line $LINENO. See journalctl -u suricata -n 50" >&2' ERR

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Vui lòng chạy script này với quyền root (sudo)."
  exit 1
fi

echo "[+] Bắt đầu cài đặt môi trường và Suricata..."

# 1. Cài đặt các gói cần thiết
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y suricata jq ufw curl iproute2 ethtool python3-yaml openssh-server nginx nmap

# Some Suricata packages already include suricata-update.
if ! command -v suricata-update >/dev/null 2>&1; then
  apt-get install -y suricata-update
fi

# 2. Create the dedicated capture network; leave management networking intact.
IFACE=suri-host
install -d /usr/local/lib/suricata-lab /opt/suricata-auto-defense/scripts /opt/suricata-auto-defense/config
install -m 755 "$SCRIPT_DIR/lab_network.sh" /usr/local/lib/suricata-lab/network.sh
install -m 644 "$REPO_DIR/config/suricata-lab-network.service" /etc/systemd/system/suricata-lab-network.service
systemctl daemon-reload
systemctl enable --now suricata-lab-network.service
/usr/local/lib/suricata-lab/network.sh
echo "[+] Sử dụng card mạng giao diện: $IFACE"

# 3. Cấu hình UFW mở sẵn cổng SSH (22) và Web (80) trước khi kích hoạt
ufw allow 22/tcp
ufw allow 80/tcp
if [[ -n ${SSH_CONNECTION:-} ]]; then
  read -r _ _ _ management_port <<< "$SSH_CONNECTION"
  [[ $management_port =~ ^[0-9]+$ ]]
  ufw allow "$management_port/tcp"
fi
ufw --force enable
/usr/sbin/sshd -t
nginx -t
systemctl enable --now ssh nginx

# 4. Cập nhật luật Suricata và kiểm tra cấu hình
echo "[+] Đang cập nhật luật Suricata..."
# Keep update failures visible and stop rather than claiming success.
suricata-update
BACKUP="/etc/suricata/suricata.yaml.pre-lab.$(date +%Y%m%d%H%M%S).$$"
cp -p /etc/suricata/suricata.yaml "$BACKUP"
RULE_BACKUP="${BACKUP}.rules"
if [[ -f /etc/suricata/rules/local.rules ]]; then
  cp -p /etc/suricata/rules/local.rules "$RULE_BACKUP"
fi

echo "[+] Kiểm tra tính hợp lệ của cấu hình Suricata (-T)..."
if ! python3 "$SCRIPT_DIR/configure_lab.py" /etc/suricata/suricata.yaml "$REPO_DIR/rules/local.rules" ||
   ! suricata -T -c /etc/suricata/suricata.yaml; then
  cp -p "$BACKUP" /etc/suricata/suricata.yaml
  if [[ -f $RULE_BACKUP ]]; then
    cp -p "$RULE_BACKUP" /etc/suricata/rules/local.rules
  else
    rm -f /etc/suricata/rules/local.rules
  fi
  echo "Restored configuration: $BACKUP" >&2
  exit 1
fi
install -d /etc/systemd/system/suricata.service.d
install -m 644 "$REPO_DIR/config/suricata-lab.override.conf" /etc/systemd/system/suricata.service.d/lab.conf
if [[ ! -f "$REPO_DIR/config/suricata-defense.conf" ]]; then
  install -m 600 "$REPO_DIR/config/suricata-defense.conf.example" "$REPO_DIR/config/suricata-defense.conf"
fi
# Preserve local defense settings; deploy a root-readable copy.
install -m 600 "$REPO_DIR/config/suricata-defense.conf" /opt/suricata-auto-defense/config/suricata-defense.conf
(
  source /opt/suricata-auto-defense/config/suricata-defense.conf
  for ip in "${WHITELIST_IPS[@]}"; do
    [[ $ip != 10.203.0.2 ]] || { echo 'Remove attacker 10.203.0.2 from WHITELIST_IPS.' >&2; exit 1; }
  done
)
install -m 755 "$SCRIPT_DIR/03_auto_defense.sh" /opt/suricata-auto-defense/scripts/03_auto_defense.sh
install -m 644 "$REPO_DIR/config/suricata-defense.service" /etc/systemd/system/suricata-defense.service
# Deployment override belongs to setup; keep the team's source unit unchanged.
install -d /etc/systemd/system/suricata-defense.service.d
cat > /etc/systemd/system/suricata-defense.service.d/deployment.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/bin/bash /opt/suricata-auto-defense/scripts/03_auto_defense.sh --daemon
UNIT
systemctl daemon-reload
systemctl enable suricata
systemctl restart suricata
systemctl is-active --quiet suricata

echo "[+] Hoàn tất thiết lập cơ bản cho Suricata!"
