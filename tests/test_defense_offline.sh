#!/bin/bash
# Exercise defense functions with a fake UFW; no root or network access needed.
set -Eeuo pipefail
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
sed -n '/^is_whitelisted()/,/^case "\$1" in/{ /^case /!p; }' \
    "$DIR/../scripts/03_auto_defense.sh" > "$WORK/functions.sh"
source "$WORK/functions.sh"
WHITELIST_IPS=(127.0.0.1 10.203.0.1)
ALERT_COOLDOWN=5
BLOCK_LOG="$WORK/blocked.log"
COOLDOWN_DIR="$WORK/cooldown"
mkdir "$COOLDOWN_DIR"
touch "$WORK/ufw"
TELEGRAM_SCRIPT="$WORK/no-telegram-hook"
FAIL_UFW=0
ufw() {
    case "$1" in
        status) cat "$WORK/ufw" ;;
        insert)
            [[ $FAIL_UFW == 0 ]] || return 1
            printf 'Anywhere DENY IN %s\n' "$5" >> "$WORK/ufw"
            ;;
        delete) : > "$WORK/ufw" ;;
        *) return 1 ;;
    esac
}
block_ip 10.203.0.1 'whitelist test' 2
[[ ! -s $WORK/ufw && ! -f $BLOCK_LOG ]]
echo '[PASS] Whitelist is never blocked'
block_ip 10.203.0.2 'scan test' 2
grep -q '10.203.0.2' "$WORK/ufw"
grep -q 'BLOCKED.*10.203.0.2.*scan test' "$BLOCK_LOG"
[[ -f $COOLDOWN_DIR/10_203_0_2 ]]
echo '[PASS] Alert blocks IP and records local log'
block_ip 10.203.0.2 'duplicate test' 2
[[ $(wc -l < "$WORK/ufw") -eq 1 ]]
[[ $(grep -c BLOCKED "$BLOCK_LOG") -eq 1 ]]
echo '[PASS] Duplicate alert creates no duplicate rule/log'
unban_ip 10.203.0.2
[[ ! -s $WORK/ufw && ! -f $COOLDOWN_DIR/10_203_0_2 ]]
grep -q UNBANNED "$BLOCK_LOG"
echo '[PASS] Unban removes rule and cooldown and writes log'
echo '[+] All offline defense tests passed.'
