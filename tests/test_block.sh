#!/bin/bash
# tests/test_block.sh
# Kiểm thử script 03_auto_defense.sh – Võ Minh Thông

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
DEFENSE_SCRIPT="$SCRIPT_DIR/../scripts/03_auto_defense.sh"
BLOCK_LOG="/var/log/suricata_blocked_ips.log"
TEST_IP="192.168.254.254"  # IP giả để test, không ảnh hưởng thật
PASS=0
FAIL=0

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   TEST: 03_auto_defense.sh           ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Hàm kiểm tra kết quả
check() {
    local desc="$1"
    local result="$2"
    if [ "$result" = "0" ]; then
        echo "  [✓ PASS] $desc"
        ((PASS++))
    else
        echo "  [✗ FAIL] $desc"
        ((FAIL++))
    fi
}

# ── Test 1: Script tồn tại ─────────────────────────────────────────────────
[ -f "$DEFENSE_SCRIPT" ]
check "Script 03_auto_defense.sh tồn tại" $?

# ── Test 2: Script có thể thực thi ────────────────────────────────────────
chmod +x "$DEFENSE_SCRIPT"
[ -x "$DEFENSE_SCRIPT" ]
check "Script có quyền thực thi (chmod +x)" $?

# ── Test 3: Hiển thị help khi không có tham số ────────────────────────────
output=$(sudo bash "$DEFENSE_SCRIPT" 2>&1)
echo "$output" | grep -qi "cách dùng"
check "Hiển thị hướng dẫn khi không có tham số" $?

# ── Test 4: --list chạy không lỗi ─────────────────────────────────────────
sudo bash "$DEFENSE_SCRIPT" --list &>/dev/null
check "--list chạy không lỗi" $?

# ── Test 5: --unban không có IP báo lỗi đúng ──────────────────────────────
output=$(sudo bash "$DEFENSE_SCRIPT" --unban 2>&1)
echo "$output" | grep -qi "thiếu\|Dùng:"
check "--unban thiếu IP → hiển thị thông báo lỗi" $?

# ── Test 6: Chặn IP test bằng UFW ─────────────────────────────────────────
sudo ufw insert 1 deny from "$TEST_IP" to any &>/dev/null
ufw_result=$(sudo ufw status | grep "$TEST_IP")
[ -n "$ufw_result" ]
check "UFW có thể chặn IP thử nghiệm ($TEST_IP)" $?

# ── Test 7: --unban xoá được IP test ──────────────────────────────────────
sudo bash "$DEFENSE_SCRIPT" --unban "$TEST_IP" &>/dev/null
ufw_result=$(sudo ufw status | grep "$TEST_IP")
[ -z "$ufw_result" ]
check "--unban xoá IP thành công khỏi UFW" $?

# ── Test 8: Ghi log hoạt động ─────────────────────────────────────────────
sudo touch "$BLOCK_LOG" && [ -f "$BLOCK_LOG" ]
check "File log /var/log/suricata_blocked_ips.log tồn tại" $?

# ── Test 9: --stop khi chưa chạy không crash ──────────────────────────────
sudo bash "$DEFENSE_SCRIPT" --stop &>/dev/null
check "--stop khi chưa chạy không bị crash" $?

# ── Kết quả ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
TOTAL=$((PASS + FAIL))
echo "  Kết quả: $PASS/$TOTAL PASS | $FAIL FAIL"
if [ "$FAIL" = "0" ]; then
    echo "  🎉 Tất cả test đều PASS!"
else
    echo "  ⚠️  Có $FAIL test FAIL, kiểm tra lại!"
fi
echo "══════════════════════════════════════════"
echo ""
