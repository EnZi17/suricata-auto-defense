#!/bin/bash
# scripts/00_run_all.sh

if [ "$EUID" -ne 0 ]; then
  echo "[-] Vui lòng chạy bằng sudo."
  exit 1
}

echo "[+] Khởi động toàn bộ hệ thống Suricata IDS/IPS..."

# Kiểm tra file cấu hình chung
if [ -f "$(dirname "$0")/../config/suricata-defense.conf" ]; then
    source "$(dirname "$0")/../config/suricata-defense.conf"
else
    echo "[-] Không tìm thấy file cấu hình suricata-defense.conf!"
    exit 1
fi

echo "[+] Hệ thống đã sẵn sàng kết nối các module (Setup -> Rules -> Defense -> Alert)."
