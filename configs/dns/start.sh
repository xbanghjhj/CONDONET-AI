#!/bin/sh
set -eu

config=/condonet/dns.conf
if [ -f /run/condonet-dns-fixture ]; then
    config=/run/condonet-dns-active.conf
    sed 's/^host-record=portal\.condo\.test,10\.60\.50\.10$/host-record=portal.condo.test,10.60.50.11/' /condonet/dns.conf > "$config"
fi
exec /usr/sbin/dnsmasq --keep-in-foreground --conf-file="$config" --log-facility=-
