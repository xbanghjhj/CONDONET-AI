#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf '%s\n' 'Usage: sh security/sensor.sh check|start LAB LOG_DIR or stop LAB' >&2
    exit 2
fi
action=$1
lab=$2
output=${3:-}
case "$lab" in
    ''|*[!a-zA-Z0-9-]*|-*) exit 2 ;;
esac
gateway=clab-$lab-gw
sensor=condonet-ids-$lab
image=jasonish/suricata:8.0.8
config=$(cd "$(dirname -- "$0")" && pwd)

if [ "$action" = stop ] && [ "$#" -eq 2 ]; then
    label=$(docker inspect --type container -f '{{index .Config.Labels "condonet.ids.lab"}}' "$sensor")
    test "$label" = "$lab"
    exec docker stop "$sensor"
fi

if [ "$#" -ne 3 ]; then
    exit 2
fi
case "$action" in
    check) set -- --rm ;;
    start) set -- --rm -d --name "$sensor" --label "condonet.ids.lab=$lab" ;;
    *) exit 2 ;;
esac

scope=$(docker inspect --type container -f '{{index .Config.Labels "containerlab"}} {{.HostConfig.NetworkMode}} {{.State.Running}}' "$gateway")
test "$scope" = "$lab none true"
mkdir -m 0770 -- "$output"
output=$(cd -- "$output" && pwd)
output_group=$(stat -c %g -- "$output")
if [ "$action" = check ]; then
    set -- "$@" --network none
else
    set -- "$@" --network "container:$gateway"
fi
set -- "$@" --cap-drop ALL --cap-add NET_RAW --group-add "$output_group" \
    --mount "type=bind,src=$config,dst=/etc/condonet-ids,readonly" \
    --mount "type=bind,src=$output,dst=/var/log/suricata" \
    --entrypoint /usr/bin/suricata "$image" -c /etc/condonet-ids/suricata.yaml
if [ "$action" = check ]; then
    set -- "$@" -T
else
    set -- "$@" --af-packet=eth1
fi
exec docker run "$@"
