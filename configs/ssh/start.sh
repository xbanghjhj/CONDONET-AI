#!/bin/sh
set -eu

mkdir -p /run/sshd
ssh-keygen -A
exec /usr/sbin/sshd -D -e -f /condonet/ssh/sshd_config
