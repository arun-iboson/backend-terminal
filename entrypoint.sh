#!/bin/sh
set -e

cd /www/example-terminal-backend

if [ -f "$SWARM_SECRET_FILE_PATH" ]; then
    # Use 'set -a' to automatically export all variables defined from here on
    set -a
    . "$SWARM_SECRET_FILE_PATH"
    set +a
    echo "Loaded and exported secrets from $SWARM_SECRET_FILE_PATH"
fi

ruby web.rb -p ${PORT:-4567} -o 0.0.0.0
