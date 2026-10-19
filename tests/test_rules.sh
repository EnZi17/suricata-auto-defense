#!/bin/bash
# tests/test_rules.sh
# Kiểm thử rules/local.rules và scripts/02_rule_manager.sh – Nguyễn Ngọc Thái
#
#   sudo ./tests/test_rules.sh            : test cú pháp, dải SID và các lệnh của 02_rule_manager.sh
#   sudo ./tests/test_rules.sh --live [s] : chờ Attacker tạo traffic (mặc định 180s), kiểm tra alert trong eve.json

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
REPO_RULES="$SCRIPT_DIR/../rules/local.rules"
MANAGER="$SCRIPT_DIR/../scripts/02_rule_manager.sh"
SURICATA_YAML="/etc/suricata/suricata.yaml"
EVE_JSON="/var/log/suricata/eve.json"
PASS=0
FAIL=0

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

summary() {
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
    [ "$FAIL" = "0" ]
}

if [ "$EUID" -ne 0 ]; then
    echo "[-] Vui lòng chạy với quyền root (sudo)."
    exit 1
fi
command -v suricata &>/dev/null || { echo "[-] Chưa cài Suricata."; exit 1; }

# SID của các luật đang bật trong một file
enabled_sids() {
    grep -E '^[[:space:]]*(alert|drop|reject|pass)[[:space:]]' "$1" \
        | sed -nE 's/.*sid:[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p'
}

# ══════════════════════════════════════════════════════════════════════════════
# Chế độ --live: kiểm tra alert thật trong eve.json
# ══════════════════════════════════════════════════════════════════════════════
if [ "$1" = "--live" ]; then
    WAIT="${2:-180}"
    command -v jq &>/dev/null || { echo "[-] Cần cài jq."; exit 1; }
    [ -f "$EVE_JSON" ] || { echo "[-] Không tìm thấy $EVE_JSON"; exit 1; }
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')
    START_LINE=$(wc -l < "$EVE_JSON")

    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║   LIVE TEST: local.rules             ║"
    echo "╚══════════════════════════════════════╝"
    echo ""
    echo "  Chạy trên máy Attacker trong ${WAIT}s tới (Server: $SERVER_IP):"
    echo "    ping -c 30 -i 0.1 $SERVER_IP"
    echo "    nmap -sS -p 1-200 $SERVER_IP"
    echo "    for i in \$(seq 1 6); do ssh -o BatchMode=yes fake@$SERVER_IP; done"
    echo "    curl --path-as-is http://$SERVER_IP/../../etc/passwd"
    echo "  (hoặc: ./attacker/simulate_attacks.sh → 5. Run all)"
    echo ""

    declare -A RULE_GROUPS=(
        ["ICMP           (1000001-1000009)"]="1000001 1000009"
        ["Nmap scan      (1000010-1000019)"]="1000010 1000019"
        ["SSH brute-force(1000020-1000029)"]="1000020 1000029"
        ["Path Traversal (1000030-1000039)"]="1000030 1000039"
    )
    ORDER=("ICMP           (1000001-1000009)" "Nmap scan      (1000010-1000019)"
           "SSH brute-force(1000020-1000029)" "Path Traversal (1000030-1000039)")

    new_alerts() {
        tail -n +"$((START_LINE + 1))" "$EVE_JSON" \
            | jq -r 'select(.event_type=="alert") | "\(.alert.signature_id) \(.alert.severity) \(.src_ip) \(.alert.signature)"' 2>/dev/null
    }

    all_seen() {
        local alerts="$1" g lo hi
        for g in "${ORDER[@]}"; do
            read -r lo hi <<< "${RULE_GROUPS[$g]}"
            awk -v lo="$lo" -v hi="$hi" '$1>=lo && $1<=hi {f=1} END {exit !f}' <<< "$alerts" || return 1
        done
    }

    for ((t = 0; t < WAIT; t += 5)); do
        ALERTS=$(new_alerts)
        all_seen "$ALERTS" && break
        printf "\r  [*] Đang chờ traffic... %3ss / %ss" "$t" "$WAIT"
        sleep 5
    done
    echo ""
    echo ""
    ALERTS=$(new_alerts)

    for g in "${ORDER[@]}"; do
        read -r lo hi <<< "${RULE_GROUPS[$g]}"
        hits=$(awk -v lo="$lo" -v hi="$hi" '$1>=lo && $1<=hi' <<< "$ALERTS")
        [ -n "$hits" ]
        check "$g có alert trong eve.json" $?
        [ -n "$hits" ] && awk '{sid=$1; sev=$2; ip=$3; $1=$2=$3=""; sub(/^ +/, ""); print "sid=" sid " sev=" sev " src=" ip "  " $0}' <<< "$hits" | sort | uniq -c | sed "s/^/      /"
    done
    summary
    exit $?
fi

# ══════════════════════════════════════════════════════════════════════════════
# Test tĩnh + 02_rule_manager.sh (chạy trên bản sao tạm, không ảnh hưởng hệ thống)
# ══════════════════════════════════════════════════════════════════════════════
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export RULES_FILE="$WORK/local.rules"
export RULE_LOG="$WORK/rule_manager.log"
export NO_RELOAD=1
cp "$REPO_RULES" "$RULES_FILE"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   TEST: local.rules + 02_rule_manager║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Phần 1: local.rules ───────────────────────────────────────────────────────
echo "  ── rules/local.rules"

# Test 1: file tồn tại
[ -f "$REPO_RULES" ]
check "File rules/local.rules tồn tại" $?

# Test 2: cú pháp hợp lệ với suricata -T
suricata -T -c "$SURICATA_YAML" -S "$REPO_RULES" -l "$WORK" &>/dev/null
check "Cú pháp hợp lệ (suricata -T -S local.rules)" $?

# Test 3: không trùng SID
dups=$(enabled_sids "$REPO_RULES" | sort | uniq -d)
[ -z "$dups" ]
check "Không có SID trùng lặp" $?

# Test 4-7: mỗi nhóm có luật và SID nằm đúng dải
check_group() {
    local name="$1" pattern="$2" lo="$3" hi="$4" sids bad
    sids=$(grep -E '^[[:space:]]*alert[[:space:]]' "$REPO_RULES" | grep -E "msg:\"LOCAL $pattern" \
        | sed -nE 's/.*sid:[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p')
    bad=$(awk -v lo="$lo" -v hi="$hi" '$1<lo || $1>hi' <<< "$sids")
    [ -n "$sids" ] && [ -z "$bad" ]
    check "Nhóm $name: $(wc -w <<< "$sids") luật, SID trong dải $lo–$hi" $?
}
check_group "ICMP" "ICMP" 1000001 1000009
check_group "Nmap" "Nmap" 1000010 1000019
check_group "SSH" "SSH" 1000020 1000029
check_group "Path Traversal" "Path Traversal" 1000030 1000039

# Test 8: luật ICMP/Nmap/SSH có threshold hoặc detection_filter để tránh báo giả
missing=$(grep -E '^[[:space:]]*alert[[:space:]]' "$REPO_RULES" | grep -E 'msg:"LOCAL (ICMP|Nmap|SSH)' \
    | grep -vE 'threshold:|detection_filter:')
[ -z "$missing" ]
check "Luật ICMP/Nmap/SSH đều có threshold/detection_filter" $?

# ── Phần 2: 02_rule_manager.sh ────────────────────────────────────────────────
echo ""
echo "  ── scripts/02_rule_manager.sh"

# Test 9: script tồn tại và thực thi được
chmod +x "$MANAGER"
[ -x "$MANAGER" ]
check "Script 02_rule_manager.sh có quyền thực thi" $?

# Test 10: hiển thị hướng dẫn khi không có tham số
grep -qi "cách dùng" <<< "$("$MANAGER" 2>&1)"
check "Hiển thị hướng dẫn khi không có tham số" $?

# Test 11: tham số sai → exit 1
"$MANAGER" --foo &>/dev/null
[ $? -ne 0 ]
check "Tham số không hợp lệ (--foo) → báo lỗi" $?

# Test 12: chạy không có quyền root → từ chối
tmp_mgr=$(mktemp /tmp/rule_manager_XXXX.sh)
cp "$MANAGER" "$tmp_mgr" && chmod 755 "$tmp_mgr"
runuser -u nobody -- bash "$tmp_mgr" --list 2>&1 | grep -qi "quyền root"
check "Không có quyền root → từ chối" $?
rm -f "$tmp_mgr"

# Test 13: --list hiển thị đủ số luật
total=$(enabled_sids "$RULES_FILE" | wc -l)
grep -q "Tổng: $total luật" <<< "$("$MANAGER" --list)"
check "--list hiển thị đủ $total luật" $?

# Test 14: --disable comment đúng luật
"$MANAGER" --disable 1000001 &>/dev/null
grep -qE '^#[[:space:]]*alert.*sid:1000001;' "$RULES_FILE" && grep -qE '1000001[[:space:]]+DISABLED' <<< "$("$MANAGER" --list)"
check "--disable 1000001 → luật bị comment (DISABLED)" $?

# Test 15: --disable không ảnh hưởng luật khác
[ "$(enabled_sids "$RULES_FILE" | wc -l)" -eq $((total - 1)) ]
check "--disable chỉ tắt đúng 1 luật" $?

# Test 16: --enable bỏ comment
"$MANAGER" --enable 1000001 &>/dev/null
grep -qE '^alert.*sid:1000001;' "$RULES_FILE"
check "--enable 1000001 → luật được bật lại" $?

# Test 17: --add luật hợp lệ
"$MANAGER" --add 'alert tcp any any -> $HOME_NET 23 (msg:"LOCAL Test Telnet"; flags:S,12; priority:3; sid:1000099; rev:1;)' &>/dev/null
[ $? -eq 0 ] && grep -q 'sid:1000099;' "$RULES_FILE"
check "--add luật hợp lệ (SID 1000099) → được thêm" $?

# Test 18: --add luật sai cú pháp → từ chối, file giữ nguyên
before=$(md5sum < "$RULES_FILE")
"$MANAGER" --add 'alert tcp any any -> any any (msg:"LOCAL Bad"; foo:1; sid:1000098; rev:1;)' &>/dev/null
rc=$?
[ $rc -ne 0 ] && [ "$before" = "$(md5sum < "$RULES_FILE")" ]
check "--add luật sai cú pháp → bị từ chối, khôi phục file cũ" $?

# Test 19: --add SID trùng → từ chối
"$MANAGER" --add 'alert tcp any any -> any any (msg:"LOCAL Dup"; sid:1000010; rev:1;)' 2>&1 | grep -q "đã tồn tại"
check "--add SID trùng (1000010) → bị từ chối" $?

# Test 20: --add SID ngoài dải local → từ chối
"$MANAGER" --add 'alert tcp any any -> any any (msg:"LOCAL Range"; sid:2000; rev:1;)' 2>&1 | grep -q "ngoài dải"
check "--add SID ngoài dải (2000) → bị từ chối" $?

# Test 21: --disable SID không phải số / không tồn tại
"$MANAGER" --disable abc 2>&1 | grep -q "không hợp lệ" && "$MANAGER" --disable 1999999 2>&1 | grep -q "Không tìm thấy"
check "--disable SID sai / không tồn tại → báo lỗi" $?

# Test 22: --reload với file bị sửa hỏng → khôi phục bản backup
"$MANAGER" --reload &>/dev/null                  # lưu bản hợp lệ hiện tại làm backup
echo 'alert tcp any any -> any any (msg:"LOCAL Broken" sid:1000097;)' >> "$RULES_FILE"
"$MANAGER" --reload &>/dev/null
rc=$?
[ $rc -ne 0 ] && ! grep -q "Broken" "$RULES_FILE"
check "--reload file lỗi → không reload, khôi phục backup" $?

# Test 23: --reload file hợp lệ → OK
"$MANAGER" --reload &>/dev/null
check "--reload file hợp lệ → thành công" $?

# Test 24: ghi log thao tác
grep -q "RELOAD | FAILED -> rollback" "$RULE_LOG" && grep -q "ADD sid=1000099 | OK" "$RULE_LOG"
check "Ghi log thao tác vào file log" $?

# ── Phần 3: Suricata đang chạy đã nạp local.rules ─────────────────────────────
echo ""
echo "  ── Suricata trên hệ thống"

# Test 25: suricata.yaml khai báo local.rules
grep -qE '^[[:space:]]*-[[:space:]]+/etc/suricata/rules/local.rules' "$SURICATA_YAML"
check "suricata.yaml khai báo /etc/suricata/rules/local.rules" $?

# Test 26: service suricata đang chạy
systemctl is-active --quiet suricata
check "Service suricata đang chạy" $?

summary
