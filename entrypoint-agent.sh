#!/bin/sh
# Entrypoint for the seawise-agent image.
#
# Started with --user: runs the agent as that user, nothing else.
# Started as root: drops to PUID:PGID (default 1000:1000) by numeric ID, so
# IDs that already exist in the image (such as GID 100 "users") are reused
# and /etc is never written. Works on a read-only root filesystem.
set -eu

AGENT=/app/seawise-agent

if [ "$(id -u)" != "0" ]; then
    exec "$AGENT" "$@"
fi

PUID=${PUID:-1000}
PGID=${PGID:-1000}

for v in "PUID=$PUID" "PGID=$PGID"; do
    case "${v#*=}" in
        ''|*[!0-9]*)
            echo "ERROR: ${v%%=*} must be a number, got '${v#*=}'" >&2
            exit 1
            ;;
    esac
done

if [ "$PUID" -eq 0 ] || [ "$PGID" -eq 0 ]; then
    echo "ERROR: running as root (PUID=0 or PGID=0) is not supported." >&2
    echo "       Use PUID/PGID values >= 1 (default: 1000)." >&2
    exit 1
fi

DATA_DIR=${SEAWISE_DATA_DIR:-/config}
mkdir -p "$DATA_DIR"
if [ "$(stat -c %u:%g "$DATA_DIR")" != "$PUID:$PGID" ]; then
    chown "$PUID:$PGID" "$DATA_DIR"
fi
# Older images could leave root-owned files here; hand them to PUID:PGID so
# the agent can read them. Contents are not changed.
find "$DATA_DIR" -xdev -user 0 -exec chown -h "$PUID:$PGID" {} +

echo "Running as uid=$PUID gid=$PGID"
exec su-exec "$PUID:$PGID" "$AGENT" "$@"
