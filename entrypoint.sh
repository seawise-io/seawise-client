#!/bin/sh
# LinuxServer.io-style entrypoint: handle PUID/PGID, then drop to non-root user.

PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Create group/user with requested IDs if they don't match
CURRENT_UID=$(id -u seawise 2>/dev/null)
CURRENT_GID=$(id -g seawise 2>/dev/null)

if [ "$CURRENT_GID" != "$PGID" ] || [ "$CURRENT_UID" != "$PUID" ]; then
    deluser seawise 2>/dev/null
    delgroup seawise 2>/dev/null
    addgroup -g "$PGID" -S seawise
    adduser -u "$PUID" -G seawise -S -D -H seawise
fi

echo "Running as uid=$(id -u seawise) gid=$(id -g seawise)"

# Ensure config directory exists with correct ownership
mkdir -p /config
chown "$PUID:$PGID" /config /app

# Drop privileges and run the app
exec su-exec seawise /app/seawise-client "$@"
