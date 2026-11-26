#!/bin/sh
set -eu

case ${1:-} in
    -h|--help)
        printf 'Usage: sh scripts/capture.sh OUTPUT_DIR [LAB_NAME]\n'
        exit 0
        ;;
esac
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf 'Usage: sh scripts/capture.sh OUTPUT_DIR [LAB_NAME]\n' >&2
    exit 2
fi

output=$1
lab=${2:-condonet}
prefix=clab-$lab
collector=$(dirname -- "$0")/capture-pcap.py
mkdir -- "$output"
output=$(cd -- "$output" && pwd)
exec > "$output/capture.log" 2>&1
set -x

running=$(docker ps --filter "label=containerlab=$lab" --format '{{.Names}}')
running=$(printf '%s\n' "$running" | sort)
expected=$(printf '%s\n' "$prefix-admin" "$prefix-camera" "$prefix-guest" "$prefix-gw" \
    "$prefix-resident" "$prefix-svc" "$prefix-sw" "$prefix-wan")
test "$running" = "$expected"
command -v tcpdump

docker exec -i "$prefix-sw" python3 - eth1 'vlan' 12 < "$collector" \
    > "$output/trunk.pcap" 2> "$output/trunk-capture.log" &
trunk_pid=$!
docker exec -i "$prefix-wan" python3 - eth1 'tcp port 80' 12 < "$collector" \
    > "$output/wan.pcap" 2> "$output/wan-capture.log" &
wan_pid=$!
trap 'wait "$trunk_pid" || :; wait "$wan_pid" || :' EXIT

attempt=0
until grep -q '^listening on eth1$' "$output/trunk-capture.log" &&
      grep -q '^listening on eth1$' "$output/wan-capture.log"; do
    kill -0 "$trunk_pid" "$wan_pid"
    attempt=$((attempt + 1))
    test "$attempt" -lt 25
    sleep 0.2
done

for host_vlan in admin:10 resident:20 guest:30 camera:40; do
    host=${host_vlan%:*}
    vid=${host_vlan#*:}
    docker exec "$prefix-$host" ping -n -c 1 -W 1 "10.60.$vid.1" \
        > "$output/$host-gateway.log"
done
docker exec "$prefix-resident" curl --noproxy '*' -fsS --max-time 5 http://10.60.50.10/ \
    > "$output/resident-portal.html"
docker exec "$prefix-resident" curl --noproxy '*' -fsS --max-time 5 http://10.60.254.2/source \
    > "$output/wan-http.json"
wait "$trunk_pid"
wait "$wan_pid"
trap - EXIT

tcpdump -nn -e -r "$output/trunk.pcap" > "$output/trunk-packets.log"
tcpdump -nn -e -r "$output/wan.pcap" > "$output/wan-packets.log"
for vid in 10 20 30 40; do
    grep -E "vlan $vid,.*10\.60\.$vid\.[0-9]+ > 10\.60\.$vid\.1: ICMP echo request" "$output/trunk-packets.log"
done
for vid in 20 50; do
    grep -E "vlan $vid,.*10\.60\.20\.[0-9]+\.[0-9]+ > 10\.60\.50\.10\.80: Flags \[S\]" "$output/trunk-packets.log"
    grep -E "vlan $vid,.*10\.60\.50\.10\.80 > 10\.60\.20\.[0-9]+\.[0-9]+: Flags \[S\.\]" "$output/trunk-packets.log"
done
grep -F 'CondoNet Portal' "$output/resident-portal.html"
grep -E '10\.60\.254\.1\.[0-9]+ > 10\.60\.254\.2\.80: Flags \[S\]' "$output/wan-packets.log"
grep -Eq '"source"[[:space:]]*:[[:space:]]*"10\.60\.254\.1"' "$output/wan-http.json"
