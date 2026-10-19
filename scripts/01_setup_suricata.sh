#!/bin/bash
# scripts/01_setup_suricata.sh

set -e

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Vui lòng chạy script này với quyền root (sudo)."
  exit 1
fi

echo "[+] Bắt đầu cài đặt môi trường và Suricata..."

# 1. Cài đặt các gói cần thiết
apt update && apt install -y suricata jq ufw curl

# 2. Tự động nhận diện card mạng (mặc định là enp0s3 dựa trên môi trường của bạn)
IFACE=${1:-$(ip route show | grep default | awk '{print $5}' | head -n1)}
echo "[+] Sử dụng card mạng giao diện: $IFACE"

# 3. Cấu hình UFW mở sẵn cổng SSH (22) và Web (80) trước khi kích hoạt
ufw allow 22/tcp
ufw allow 80/tcp
ufw --force enable

# 4. Cập nhật luật Suricata và kiểm tra cấu hình
echo "[+] Đang cập nhật luật Suricata..."
suricata-update || true

echo "[+] Kiểm tra tính hợp lệ của cấu hình Suricata (-T)..."
suricata -T -c /etc/suricata/suricata.yaml

echo "[+] Hoàn tất thiết lập cơ bản cho Suricata!"
