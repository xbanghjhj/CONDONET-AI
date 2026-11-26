#!/bin/sh
set -eu

sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip link set dev eth1 up
ip address replace "$1" dev eth1
if [ "$#" -eq 2 ]; then
    ip route replace default via "$2" dev eth1
fi
