#!/bin/sh
set -eu

if ! supervisorctl pid >/dev/null 2>&1; then
    supervisord -c /etc/supervisor/supervisord.conf
fi
