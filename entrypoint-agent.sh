#!/bin/sh
# Entrypoint for the seawise-agent image.
#
# Started with --user: runs the agent as that user, nothing else.
# Started as root: drops to PUID:PGID (default 1000:1000) by numeric ID, so
# IDs that already exist in the image (such as GID 100 "users") are reused
# and /etc is never written. Works on a read-only root filesystem.
# The agent never runs with user or group 0 and always has no_new_privs set.
set -eu

AGENT=/app/seawise-agent

die() {
    echo "ERROR: $*" >&2
    exit 1
}

if [ "$(id -u)" != "0" ]; then
    for g in $(id -G); do
        if [ "$g" = "0" ]; then
            die "running with group 0 (root) is not supported; use --user UID:GID with GID >= 1"
        fi
    done
    exec setpriv --nnp "$AGENT" "$@"
fi

PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Digits and length are checked before any comparison, so nothing can
# overflow or wrap to 0. 4294967295 is (uid_t)-1, which setuid rejects.
check_id() {
    case "$2" in
        *[!0]*) ;;
        *[0-9]*)
            die "running as root ($1=$2) is not supported; use PUID/PGID values >= 1 (default: 1000)"
            ;;
    esac
    case "$2" in
        ''|*[!0-9]*|0*)
            die "$1 must be a number from 1 to 4294967294 without leading zeros, got '$2'"
            ;;
    esac
    if [ "${#2}" -gt 10 ] || [ "$2" -gt 4294967294 ]; then
        die "$1 must be a number from 1 to 4294967294, got '$2'"
    fi
}
check_id PUID "$PUID"
check_id PGID "$PGID"

DATA_DIR=${SEAWISE_DATA_DIR:-/config}
# The handover below changes owners as root, so it only runs on the data
# folder: /config or /data, or a folder inside them.
in_data_root() {
    case "$1" in
        /config|/config/*|/data|/data/*) return 0 ;;
    esac
    return 1
}
case "$DATA_DIR" in
    */.|*/./*|*/..|*/../*) die "SEAWISE_DATA_DIR must not contain . or .., got '$DATA_DIR'" ;;
esac
in_data_root "$DATA_DIR" ||
    die "SEAWISE_DATA_DIR must be /config, /data or a folder inside them, got '$DATA_DIR'"
mkdir -p "$DATA_DIR"
real=$(realpath "$DATA_DIR")
in_data_root "$real" ||
    die "SEAWISE_DATA_DIR resolves to '$real', outside /config and /data"
DATA_DIR=$real

warn() {
    echo "WARNING: $*" >&2
}
glob_escape() {
    printf '%s\n' "$1" | sed 's/[][*?\\]/\\&/g'
}
DATA_GLOB=$(glob_escape "$DATA_DIR")
# Mount points inside the data folder (mountinfo field 5, octal escapes
# decoded) are never walked or changed, whatever device they are on.
MOUNTS=$(D="$DATA_DIR" awk '{
    m = $5
    gsub(/\\040/, " ", m); gsub(/\\011/, "\t", m); gsub(/\\134/, "\\", m)
    if (index(m, ENVIRON["D"] "/") == 1) print m
}' /proc/self/mountinfo)

# Older images could leave root-owned files here; hand them to PUID:PGID so
# the agent can read them. Contents are not changed. find never follows
# symlinks and chown -h changes the link itself. Folders the user already
# owns and mount points are skipped, so no DAC capabilities are needed.
# Files go first, then folders deepest first and the data folder itself
# last, so nothing is locked out mid-way.
root_owned() {
    n=$#
    while IFS= read -r m; do
        [ -n "$m" ] || continue
        set -- "$@" -path "$(glob_escape "$m")" -prune -o
    done <<MOUNTS_END
$MOUNTS
MOUNTS_END
    set -- "$@" \( -type d ! -user 0 ! -path "$DATA_GLOB" -prune \) -o \(
    i=1
    while [ "$i" -le "$n" ]; do
        eval "set -- \"\$@\" \"\${$i}\""
        i=$((i + 1))
    done
    set -- "$@" -user 0 -print0 \)
    shift "$n"
    find "$DATA_DIR" -xdev "$@"
}
chown_all() {
    # shellcheck disable=SC3045 # busybox sh supports read -d
    while IFS= read -r -d '' f; do
        chown -h "$PUID:$PGID" "$f" || return 1
    done
}
handover() {
    if ! root_owned ! -type d | chown_all; then
        warn "could not hand some root-owned files in $DATA_DIR to $PUID:$PGID"
    fi
    if ! root_owned ! -path "$DATA_GLOB" -type d | sort -z -r | chown_all; then
        warn "could not hand some root-owned folders in $DATA_DIR to $PUID:$PGID"
    fi
    if ! left=$(root_owned ! -path "$DATA_GLOB" | tr -cd '\0' | wc -c); then
        warn "could not check $DATA_DIR for root-owned entries"
    elif [ "$left" -ne 0 ]; then
        warn "$left root-owned entries remain in $DATA_DIR; the agent may not be able to read them"
    fi
}
# Only a folder that is empty or holds client state is taken over, so a
# parent folder mapped by mistake is never handed to PUID:PGID.
has_state() {
    for f in machine.json account.json config.json password.hash frpc.toml v2; do
        if [ -e "$DATA_DIR/$f" ] || [ -L "$DATA_DIR/$f" ]; then
            return 0
        fi
    done
    return 1
}
# shellcheck disable=SC3040 # busybox sh supports pipefail
set -o pipefail
owner=$(stat -c %u:%g "$DATA_DIR")
if entries=$(ls -A "$DATA_DIR" 2>/dev/null); then
    case "$entries" in
        ''|lost+found) ;;
        *) has_state ||
            die "$DATA_DIR is not empty and holds no SeaWise client state; map an empty folder (or your existing SeaWise data folder) to $DATA_DIR" ;;
    esac
    handover
elif [ "$owner" != "$PUID:$PGID" ]; then
    # Without DAC capabilities root cannot enter another user's 0700
    # folder. A folder PUID:PGID already owns is the agent's own.
    die "cannot read $DATA_DIR; make it owned by $PUID:$PGID or start the container with --user"
fi
if [ "$owner" != "$PUID:$PGID" ]; then
    chown "$PUID:$PGID" "$DATA_DIR" ||
        die "cannot give $DATA_DIR to $PUID:$PGID; keep the CHOWN, SETUID and SETGID capabilities or start the container with --user"
fi

echo "Running as uid=$PUID gid=$PGID"
exec setpriv --nnp su-exec "$PUID:$PGID" "$AGENT" "$@"
