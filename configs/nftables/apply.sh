#!/bin/sh
set -eu

rules=${1:-/condonet/firewall/condonet.nft}
exec 9>/run/condonet-firewall.lock
flock -x 9
nft -c -f "$rules"

snapshot=$(mktemp)
trap 'rm -f "$snapshot"' EXIT
printf '%s\n' 'destroy table ip condonet' > "$snapshot"
tables=$(nft list tables)
if printf '%s\n' "$tables" | grep -qx 'table ip condonet'; then
    nft list table ip condonet >> "$snapshot"
fi

nft -f "$rules"
if nft list chain ip condonet input | grep -Eq 'type filter hook input .*policy drop;' &&
   nft list chain ip condonet forward | grep -Eq 'type filter hook forward .*policy drop;'; then
    exit 0
fi

printf '%s\n' 'CondoNet firewall postcheck failed, restoring previous table' >&2
nft -f "$snapshot"
exit 1
