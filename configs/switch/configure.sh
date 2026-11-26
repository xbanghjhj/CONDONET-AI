#!/bin/sh
set -eu

sysctl -qw net.ipv6.conf.all.disable_ipv6=1
if ! ip link show dev br0 >/dev/null 2>&1; then
    ip link add name br0 type bridge vlan_filtering 1 vlan_default_pvid 0
fi
ip link set dev br0 up
for port in eth1 eth2 eth3 eth4 eth5 eth6; do
    ip link set dev "$port" master br0
    ip link set dev "$port" up
done

port=2
for vlan in 10 20 30 40 50; do
    bridge vlan add dev eth1 vid "$vlan"
    bridge vlan add dev "eth$port" vid "$vlan" pvid untagged
    port=$((port + 1))
done
