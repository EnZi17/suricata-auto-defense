#!/bin/bash
# scripts/03_auto_defense.sh
# Võ Minh Thông – Auto Defense & GitHub Management
# Đọc eve.json realtime, chặn IP vi phạm bằng UFW, ghi log, gửi Telegram

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
CONFIG_FILE="$SCRIPT_DIR/../config/suricata-defense.conf"
EVE_JSON="/var/log/suricata/eve.json"
BLOCK_LOG="/var/log/suricata_blocked_ips.log"
TELEGRAM_SCRIPT="$SCRIPT_DIR/04_telegram_alert.sh"
PID_FILE="/tmp/auto_defense.pid"
COOLDOWN_DIR="/tmp/suricata_cooldown"

# ── Load cấu hình ──────────────────────────────────────────────────────────────
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "[-] Không tìm thấy file cấu hình: $CONFIG_FILE"
    exit 1
fi

# ── Kiểm tra quyền root ────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[-] Vui lòng chạy với quyền root (sudo)."
    exit 1
fi

# ── Kiểm tra jq ───────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
    echo "[-] Cần cài jq: sudo apt install -y jq"
    exit 1
fi

mkdir -p "$COOLDOWN_DIR"

# ── Kiểm tra IP có trong whitelist không ──────────────────────────────────────
is_whitelisted() {
    local ip="$1"
    for wip in "${WHITELIST_IPS[@]}"; do
        if [ "$wip" = "$ip" ]; then
            return 0
        fi
    done
    return 1
}

# ── Kiểm tra IP đã bị chặn chưa ──────────────────────────────────────────────
is_blocked() {
    local ip="$1"
    ufw status | grep -q "DENY.*$ip"
}

# ── Kiểm tra cooldown (tránh spam alert) ──────────────────────────────────────
in_cooldown() {
    local ip="$1"
    local cooldown_file="$COOLDOWN_DIR/${ip//\./_}"
    if [ -f "$cooldown_file" ]; then
        local last_time
        last_time=$(cat "$cooldown_file")
        local now
        now=$(date +%s)
        local diff=$(( now - last_time ))
        if [ "$diff" -lt "${ALERT_COOLDOWN:-60}" ]; then
            return 0  # còn trong cooldown
        fi
    fi
    return 1  # hết cooldown
}

# ── Cập nhật thời điểm alert cho IP ──────────────────────────────────────────
update_cooldown() {
    local ip="$1"
    local cooldown_file="$COOLDOWN_DIR/${ip//\./_}"
    date +%s > "$cooldown_file"
}

# ── Chặn IP ───────────────────────────────────────────────────────────────────
block_ip() {
    local ip="$1"
    local signature="$2"
    local severity="$3"

    # Bỏ qua whitelist
    if is_whitelisted "$ip"; then
        echo "[~] $(date '+%H:%M:%S') Whitelist - bỏ qua IP: $ip"
        return
    fi

    # Bỏ qua nếu đã chặn rồi
    if is_blocked "$ip"; then
        echo "[~] $(date '+%H:%M:%S') Đã chặn trước đó: $ip"
        return
    fi

    # Bỏ qua nếu còn trong cooldown
    if in_cooldown "$ip"; then
        echo "[~] $(date '+%H:%M:%S') Cooldown - bỏ qua: $ip"
        return
    fi

    echo "[!] $(date '+%H:%M:%S') CHẶN IP: $ip | Rule: $signature | Severity: $severity"

    # Chặn bằng UFW (ưu tiên cao nhất - insert vị trí 1)
    ufw insert 1 deny from "$ip" to any

    # Ghi log
    echo "$(date '+%Y-%m-%d %H:%M:%S') | BLOCKED | $ip | $signature | severity=$severity" >> "$BLOCK_LOG"

    # Cập nhật cooldown
    update_cooldown "$ip"

    # Gửi cảnh báo Telegram (4 tham số: ip, signature, severity, action)
    if [ -x "$TELEGRAM_SCRIPT" ]; then
        bash "$TELEGRAM_SCRIPT" "$ip" "$signature" "$severity" "BLOCKED"
    fi
}

# ── Gỡ chặn IP ────────────────────────────────────────────────────────────────
unban_ip() {
    local ip="$1"

    if ! ufw status | grep -q "DENY.*$ip"; then
        echo "[-] IP $ip không có trong danh sách chặn của UFW."
        return 1
    fi

    ufw delete deny from "$ip" to any
    echo "[+] Đã gỡ chặn: $ip"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | UNBANNED | $ip" >> "$BLOCK_LOG"

    # Xoá cooldown
    rm -f "$COOLDOWN_DIR/${ip//\./_}"
}

# ── Hiển thị danh sách IP bị chặn ────────────────────────────────────────────
list_blocked() {
    echo "========================================="
    echo " Danh sách IP đã bị chặn bởi Auto Defense"
    echo "========================================="
    if [ -f "$BLOCK_LOG" ]; then
        grep "| BLOCKED |" "$BLOCK_LOG" | awk -F'|' '{printf "  IP: %-18s | %s\n", $3, $1}' | sort -u
    else
        echo "  (Chưa có IP nào bị chặn)"
    fi
    echo ""
    echo " UFW hiện tại:"
    ufw status | grep "DENY" || echo "  (Không có rule DENY)"
    echo "========================================="
}

# ── Chạy daemon - đọc eve.json realtime ──────────────────────────────────────
run_daemon() {
    echo "[+] ======================================"
    echo "[+] Suricata Auto Defense đang khởi động"
    echo "[+] Theo dõi: $EVE_JSON"
    echo "[+] Log file: $BLOCK_LOG"
    echo "[+] ======================================"

    # Kiểm tra file eve.json tồn tại
    if [ ! -f "$EVE_JSON" ]; then
        echo "[-] Không tìm thấy file eve.json tại: $EVE_JSON"
        echo "[-] Hãy đảm bảo Suricata đang chạy."
        exit 1
    fi

    # Lưu PID
    echo $$ > "$PID_FILE"
    echo "[+] PID: $$"

    # Đọc eve.json realtime
    tail -F "$EVE_JSON" 2>/dev/null | while read -r line; do

        # Chỉ xử lý event type = alert
        event_type=$(echo "$line" | jq -r '.event_type // empty' 2>/dev/null)
        [ "$event_type" != "alert" ] && continue

        # Lấy thông tin cần thiết
        src_ip=$(echo "$line" | jq -r '.src_ip // empty' 2>/dev/null)
        signature=$(echo "$line" | jq -r '.alert.signature // empty' 2>/dev/null)
        severity=$(echo "$line" | jq -r '.alert.severity // 3' 2>/dev/null)

        # Bỏ qua nếu thiếu thông tin
        [ -z "$src_ip" ] && continue
        [ -z "$signature" ] && continue

        echo "[*] $(date '+%H:%M:%S') Alert: $src_ip | $signature | sev=$severity"

        # Chỉ chặn nếu severity đủ cao (mặc định <= 2)
        if [ "$severity" -le "${MIN_SEVERITY:-2}" ]; then
            block_ip "$src_ip" "$signature" "$severity"
        fi

    done
}

# ── Dừng daemon ───────────────────────────────────────────────────────────────
stop_daemon() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill "$pid" 2>/dev/null; then
            echo "[+] Đã dừng Auto Defense (PID: $pid)"
        else
            echo "[-] Không thể dừng tiến trình PID: $pid"
        fi
        rm -f "$PID_FILE"
    else
        echo "[-] Không tìm thấy PID file. Auto Defense chưa chạy?"
    fi
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
case "$1" in
    --daemon)
        run_daemon
        ;;
    --stop)
        stop_daemon
        ;;
    --list)
        list_blocked
        ;;
    --unban)
        if [ -z "$2" ]; then
            echo "[-] Thiếu địa chỉ IP. Dùng: $0 --unban <ip>"
            exit 1
        fi
        unban_ip "$2"
        ;;
    *)
        echo ""
        echo "  Suricata Auto Defense – Võ Minh Thông"
        echo "  ======================================="
        echo "  Cách dùng:"
        echo "    sudo $0 --daemon       : Chạy daemon, theo dõi eve.json realtime"
        echo "    sudo $0 --stop         : Dừng daemon"
        echo "    sudo $0 --list         : Xem danh sách IP đã bị chặn"
        echo "    sudo $0 --unban <ip>   : Gỡ chặn một IP cụ thể"
        echo ""
        ;;
esac
