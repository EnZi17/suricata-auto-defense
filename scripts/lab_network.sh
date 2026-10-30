#!/bin/bash
# Persistent isolated attacker; never reconfigure the management interface.
set -Eeuo pipefail
NS=suricata-attacker
HOST=suri-host
PEER=suri-peer
if ! ip link show "$HOST" &>/dev/null; then
  ip -j -4 route show table all | python3 -c '
import ipaddress,json,sys
lab=ipaddress.ip_network("10.203.0.0/30")
for r in json.load(sys.stdin):
    dst=r.get("dst", "default")
    if dst != "default" and lab.overlaps(ipaddress.ip_network(dst, strict=False)):
        sys.exit("Lab subnet overlaps an existing route: " + dst)
'
  if ip netns list | awk '{print $1}' | grep -qx "$NS"; then
    echo 'Namespace already exists without suri-host; inspect it before retrying.' >&2
    exit 1
  fi
  ip netns add "$NS"
  if ! ip link add "$HOST" type veth peer name "$PEER" netns "$NS"; then
    ip netns delete "$NS"
    exit 1
  fi
  ip link set "$HOST" alias suricata-single-vm-lab
else
  [[ $(cat "/sys/class/net/$HOST/ifalias") == suricata-single-vm-lab ]] || {
    echo 'suri-host belongs to another configuration.' >&2; exit 1;
  }
  ip netns exec "$NS" ip link show "$PEER" >/dev/null
fi
ip addr replace 10.203.0.1/30 dev "$HOST"
ip link set "$HOST" up
ip netns exec "$NS" ip addr replace 10.203.0.2/30 dev "$PEER"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$PEER" up
ethtool -K "$HOST" gro off gso off tso off tx off
ip netns exec "$NS" ethtool -K "$PEER" gro off gso off tso off tx off
