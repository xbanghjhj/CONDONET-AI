#!/bin/sh
set -eu

sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip link set dev eth1 up
for vlan in 10 20 30 40 50; do
    if ! ip link show dev "eth1.$vlan" >/dev/null 2>&1; then
        ip link add link eth1 name "eth1.$vlan" type vlan id "$vlan"
    fi
    ip link set dev "eth1.$vlan" up
    ip address replace "10.60.$vlan.1/24" dev "eth1.$vlan"
done

ip link set dev eth2 up
ip address replace 10.60.254.1/30 dev eth2
ip route replace default via 10.60.254.2 dev eth2
sysctl -qw net.ipv4.ip_forward=1
nft -f /condonet/nat.nft
