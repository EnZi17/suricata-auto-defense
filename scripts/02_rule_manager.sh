#!/bin/bash
# scripts/02_rule_manager.sh
# Nguyễn Ngọc Thái – Rule Engine
# Quản lý luật Suricata (local.rules) bằng sed/CLI: cài đặt, xem, thêm, bật/tắt theo SID, reload an toàn

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
REPO_RULES="$SCRIPT_DIR/../rules/local.rules"

# Có thể ghi đè bằng biến môi trường (dùng cho tests/test_rules.sh)
RULES_FILE="${RULES_FILE:-/etc/suricata/rules/local.rules}"
SURICATA_YAML="${SURICATA_YAML:-/etc/suricata/suricata.yaml}"
BACKUP_FILE="${RULES_FILE}.bak"
RULE_LOG="${RULE_LOG:-/var/log/suricata_rule_manager.log}"
NO_RELOAD="${NO_RELOAD:-0}"   # 1 = chỉ kiểm tra cú pháp, không reload Suricata

SID_MIN=1000000
SID_MAX=1999999
ACTIONS="alert|drop|reject|pass"

# ── Tiện ích ──────────────────────────────────────────────────────────────────
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$RULE_LOG" 2>/dev/null
}

die() {
    echo "[-] $1"
    exit 1
}

require_root() {
    [ "$EUID" -eq 0 ] || die "Vui lòng chạy với quyền root (sudo)."
}

require_suricata() {
    command -v suricata &>/dev/null || die "Chưa cài Suricata. Chạy scripts/01_setup_suricata.sh trước."
}

require_rules_file() {
    [ -f "$RULES_FILE" ] || die "Không tìm thấy $RULES_FILE. Chạy: sudo $0 --install"
}

validate_sid() {
    local sid="$1"
    [ -n "$sid" ] || die "Thiếu SID. Dùng: $0 $2 <sid>"
    [[ "$sid" =~ ^[0-9]+$ ]] || die "SID không hợp lệ: '$sid' (phải là số)."
}

# Dòng luật (bật hoặc đã comment) có SID tương ứng
rule_line() {
    grep -nE "^[[:space:]]*#?[[:space:]]*($ACTIONS)[[:space:]].*sid:[[:space:]]*$1[[:space:]]*;" "$RULES_FILE"
}

is_disabled() {
    rule_line "$1" | cut -d: -f2- | grep -qE '^[[:space:]]*#'
}

backup_rules() {
    cp -p "$RULES_FILE" "$BACKUP_FILE"
}

restore_rules() {
    if [ -f "$BACKUP_FILE" ]; then
        cp -p "$BACKUP_FILE" "$RULES_FILE"
        echo "[!] Đã khôi phục file luật từ backup: $BACKUP_FILE"
        log_msg "RESTORE | $RULES_FILE <- $BACKUP_FILE"
    else
        echo "[!] Không có file backup để khôi phục."
    fi
}

# Kiểm tra cú pháp local.rules bằng suricata -T (chỉ nạp file này với -S)
test_rules() {
    local tmpdir out rc
    tmpdir=$(mktemp -d)
    out=$(suricata -T -c "$SURICATA_YAML" -S "$RULES_FILE" -l "$tmpdir" 2>&1)
    rc=$?
    rm -rf "$tmpdir"
    if [ $rc -ne 0 ]; then
        echo "[-] suricata -T báo lỗi:"
        echo "$out" | grep -E "^E:" | sed 's/^/    /'
    fi
    return $rc
}

# Áp dụng thay đổi: kiểm tra -> lỗi thì khôi phục, đúng thì giữ
apply_or_rollback() {
    local action="$1"
    if test_rules; then
        echo "[+] Kiểm tra cú pháp OK."
        log_msg "$action | OK"
        return 0
    fi
    restore_rules
    log_msg "$action | FAILED -> rollback"
    return 1
}

reload_suricata() {
    if [ "$NO_RELOAD" = "1" ]; then
        echo "[~] NO_RELOAD=1: bỏ qua reload Suricata."
        return 0
    fi
    if ! systemctl is-active --quiet suricata; then
        echo "[~] Suricata chưa chạy, đang khởi động..."
        systemctl restart suricata && echo "[+] Đã khởi động Suricata." && return 0
        return 1
    fi
    if suricatasc -c reload-rules 2>/dev/null | grep -q '"return": "OK"'; then
        echo "[+] Đã reload luật (suricatasc reload-rules)."
    else
        systemctl reload suricata || return 1
        echo "[+] Đã reload luật (systemctl reload suricata)."
    fi
}

# ── --install: chép local.rules vào hệ thống và khai báo trong suricata.yaml ─
cmd_install() {
    [ -f "$REPO_RULES" ] || die "Không tìm thấy $REPO_RULES"
    mkdir -p "$(dirname "$RULES_FILE")"
    [ -f "$RULES_FILE" ] && backup_rules
    install -m 644 "$REPO_RULES" "$RULES_FILE"
    echo "[+] Đã cài $RULES_FILE"

    if grep -qE "^[[:space:]]*-[[:space:]]+$RULES_FILE[[:space:]]*$" "$SURICATA_YAML"; then
        echo "[~] $SURICATA_YAML đã khai báo $RULES_FILE"
    else
        cp -p "$SURICATA_YAML" "$SURICATA_YAML.bak"
        sed -i "/^rule-files:/a\\  - $RULES_FILE" "$SURICATA_YAML"
        echo "[+] Đã thêm $RULES_FILE vào rule-files trong $SURICATA_YAML"
    fi

    if ! apply_or_rollback "INSTALL"; then
        [ -f "$SURICATA_YAML.bak" ] && cp -p "$SURICATA_YAML.bak" "$SURICATA_YAML"
        die "Cài đặt thất bại, đã khôi phục cấu hình cũ."
    fi
    backup_rules
    reload_suricata
}

# ── --list: liệt kê luật theo SID ─────────────────────────────────────────────
cmd_list() {
    local total=0 on=0 off=0 line sid msg prio status
    printf "\n  %-8s  %-8s  %-4s  %s\n" "SID" "STATUS" "PRI" "MESSAGE"
    printf "  %-8s  %-8s  %-4s  %s\n" "--------" "--------" "----" "----------------------------------------"
    while IFS= read -r line; do
        sid=$(sed -nE 's/.*sid:[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' <<< "$line")
        msg=$(sed -nE 's/.*msg:[[:space:]]*"([^"]*)".*/\1/p' <<< "$line")
        prio=$(sed -nE 's/.*priority:[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' <<< "$line")
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            status="DISABLED"; ((off++))
        else
            status="ENABLED"; ((on++))
        fi
        ((total++))
        printf "  %-8s  %-8s  %-4s  %s\n" "$sid" "$status" "${prio:--}" "$msg"
    done < <(grep -E "^[[:space:]]*#?[[:space:]]*($ACTIONS)[[:space:]].*sid:" "$RULES_FILE")
    echo ""
    echo "  Tổng: $total luật | $on bật | $off tắt  ($RULES_FILE)"
    echo ""
}

# ── --show <sid>: in toàn bộ nội dung một luật ───────────────────────────────
cmd_show() {
    local sid="$1" found
    validate_sid "$sid" "--show"
    found=$(rule_line "$sid")
    [ -n "$found" ] || die "Không tìm thấy luật có SID $sid."
    echo "$found" | cut -d: -f2-
}

# ── --add "<rule>": thêm luật mới, sai cú pháp thì từ chối và khôi phục ─────
cmd_add() {
    local rule="$1" sid
    [ -n "$rule" ] || die "Thiếu nội dung luật. Dùng: $0 --add \"<rule>\""
    [[ "$rule" =~ ^($ACTIONS)[[:space:]] ]] || die "Luật phải bắt đầu bằng: ${ACTIONS//|/, }"
    grep -qE 'msg:[[:space:]]*"[^"]+"' <<< "$rule" || die "Luật thiếu msg:\"...\";"

    sid=$(sed -nE 's/.*sid:[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' <<< "$rule")
    [ -n "$sid" ] || die "Luật thiếu sid:<số>;"
    if [ "$sid" -lt "$SID_MIN" ] || [ "$sid" -gt "$SID_MAX" ]; then
        die "SID $sid nằm ngoài dải local ($SID_MIN – $SID_MAX)."
    fi
    [ -z "$(rule_line "$sid")" ] || die "SID $sid đã tồn tại. Xem: $0 --show $sid"

    backup_rules
    echo "$rule" >> "$RULES_FILE"
    echo "[+] Đã thêm luật SID $sid, đang kiểm tra cú pháp..."
    apply_or_rollback "ADD sid=$sid" || die "Luật bị từ chối."
    echo "[+] Chạy '$0 --reload' để áp dụng."
}

# ── --disable / --enable <sid>: comment / bỏ comment bằng sed ────────────────
cmd_disable() {
    local sid="$1"
    validate_sid "$sid" "--disable"
    [ -n "$(rule_line "$sid")" ] || die "Không tìm thấy luật có SID $sid."
    if is_disabled "$sid"; then
        echo "[~] Luật SID $sid đã tắt từ trước."
        return 0
    fi
    backup_rules
    sed -i -E "/sid:[[:space:]]*$sid[[:space:]]*;/ s/^([[:space:]]*)($ACTIONS)([[:space:]])/\1# \2\3/" "$RULES_FILE"
    is_disabled "$sid" || { restore_rules; die "Không tắt được luật SID $sid."; }
    echo "[+] Đã tắt luật SID $sid."
    apply_or_rollback "DISABLE sid=$sid" || exit 1
    echo "[+] Chạy '$0 --reload' để áp dụng."
}

cmd_enable() {
    local sid="$1"
    validate_sid "$sid" "--enable"
    [ -n "$(rule_line "$sid")" ] || die "Không tìm thấy luật có SID $sid."
    if ! is_disabled "$sid"; then
        echo "[~] Luật SID $sid đang bật."
        return 0
    fi
    backup_rules
    sed -i -E "/sid:[[:space:]]*$sid[[:space:]]*;/ s/^([[:space:]]*)#[[:space:]]*($ACTIONS)([[:space:]])/\1\2\3/" "$RULES_FILE"
    is_disabled "$sid" && { restore_rules; die "Không bật được luật SID $sid."; }
    echo "[+] Đã bật luật SID $sid."
    apply_or_rollback "ENABLE sid=$sid" || exit 1
    echo "[+] Chạy '$0 --reload' để áp dụng."
}

# ── --reload: suricata -T trước, lỗi thì khôi phục backup, đúng mới reload ──
cmd_reload() {
    echo "[*] Kiểm tra cú pháp $RULES_FILE bằng suricata -T..."
    if ! test_rules; then
        restore_rules
        log_msg "RELOAD | FAILED -> rollback"
        test_rules >/dev/null || die "File backup cũng lỗi, cần sửa tay $RULES_FILE."
        die "Không reload. File luật đã được khôi phục về bản hợp lệ gần nhất."
    fi
    echo "[+] Kiểm tra cú pháp OK."
    reload_suricata || die "Reload Suricata thất bại."
    backup_rules   # lưu lại bản hợp lệ gần nhất
    log_msg "RELOAD | OK"
}

usage() {
    echo ""
    echo "  Suricata Rule Manager – Nguyễn Ngọc Thái"
    echo "  ========================================="
    echo "  Cách dùng:"
    echo "    sudo $0 --install          : Cài rules/local.rules vào $RULES_FILE và khai báo trong suricata.yaml"
    echo "    sudo $0 --list             : Liệt kê luật (SID, trạng thái, priority, msg)"
    echo "    sudo $0 --show <sid>       : Xem nội dung một luật"
    echo "    sudo $0 --add \"<rule>\"     : Thêm luật mới (sai cú pháp sẽ bị từ chối)"
    echo "    sudo $0 --disable <sid>    : Tắt luật theo SID"
    echo "    sudo $0 --enable <sid>     : Bật luật theo SID"
    echo "    sudo $0 --reload           : Kiểm tra (suricata -T) rồi reload Suricata"
    echo ""
    echo "  Dải SID: ICMP 1000001-09 | Nmap 1000010-19 | SSH 1000020-29 | Path Traversal 1000030-39"
    echo ""
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
case "$1" in
    --install|--list|--show|--add|--disable|--enable|--reload)
        require_root
        require_suricata
        ;;
    -h|--help|"")
        usage
        exit 0
        ;;
    *)
        echo "[-] Tham số không hợp lệ: $1"
        usage
        exit 1
        ;;
esac

[ "$1" = "--install" ] || require_rules_file

case "$1" in
    --install) cmd_install ;;
    --list)    cmd_list ;;
    --show)    cmd_show "$2" ;;
    --add)     cmd_add "$2" ;;
    --disable) cmd_disable "$2" ;;
    --enable)  cmd_enable "$2" ;;
    --reload)  cmd_reload ;;
esac
