#!/bin/sh
set -eu

test "$interface" = eth1
case "$1" in
    deconfig)
        ip -4 address flush dev "$interface" scope global
        ip -4 route flush dev "$interface" root 0/0 exact 0/0
        : > /etc/resolv.conf
        ;;
    bound|renew)
        test "$subnet" = 255.255.255.0
        test -n "$router"
        test -n "$dns"
        address="$ip/24"
        current=$(ip -o -4 address show dev "$interface" scope global | awk '{print $4}')
        if [ "$current" != "$address" ]; then
            ip -4 address flush dev "$interface" scope global
        fi
        ip -4 address replace "$address" dev "$interface"
        ip -4 route replace default via "${router%% *}" dev "$interface"
        {
            for nameserver in $dns; do
                printf 'nameserver %s\n' "$nameserver"
            done
        } > /etc/resolv.conf
        ;;
esac
