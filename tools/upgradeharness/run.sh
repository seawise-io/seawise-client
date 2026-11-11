#!/bin/sh
# Runs the upgrade harness: published 1.x images and the agent image built
# from this checkout share a data volume on a Docker network without
# internet access, against a local stand-in for the SeaWise API.
#
# Needs Docker. Go runs in GO_IMAGE. Environment:
#   GO_IMAGE       Go toolchain image (default: the Makefile's pinned image)
#   HARNESS_WORK   work folder for caches, logs and the image context
#                  (default: a new folder under /tmp)
#   HARNESS_RUNS   consecutive runs that must all pass (default 1)
#   HARNESS_MIN_FREE_GB  stop when less disk is free (default 4)
#   HARNESS_GOCACHE, HARNESS_GOMODCACHE  Go caches (default: in HARNESS_WORK)
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GO_IMAGE=${GO_IMAGE:-$(sed -n 's/^GO_IMAGE ?= //p' "$ROOT/Makefile")}
OWN_WORK=0
if [ -z "${HARNESS_WORK:-}" ]; then
	HARNESS_WORK=$(mktemp -d /tmp/upgradeharness.XXXXXX)
	OWN_WORK=1
fi
WORK=$HARNESS_WORK
RUNS=${HARNESS_RUNS:-1}
MIN_FREE=${HARNESS_MIN_FREE_GB:-4}
GC=${HARNESS_GOCACHE:-$WORK/gocache}
GM=${HARNESS_GOMODCACHE:-$WORK/gomod}
ID=uh$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
NET=$ID
AGENT_IMAGE=seawise-upgradeharness-agent:$ID
V1_IMAGES="ghcr.io/seawise-io/seawise-client@sha256:3583a4c6c395389b69fd5c227a40b7b2582524d657fe85d30af9f4926ad32231
ghcr.io/seawise-io/seawise-client@sha256:25599fe34dd95a92f169482d300240042eacd12dfa4b485624ba233e7581df33"

free_check() {
	avail=$(df --output=avail -BG "$WORK" | tail -1 | tr -dc 0-9)
	if [ "$avail" -lt "$MIN_FREE" ]; then
		echo "upgradeharness: only ${avail}G free, stopping" >&2
		exit 3
	fi
}

cleanup() {
	for c in $(docker ps -aq --filter "name=^${ID}"); do docker rm -f "$c" >/dev/null 2>&1 || true; done
	for v in $(docker volume ls -q --filter "name=^${ID}"); do docker volume rm -f "$v" >/dev/null 2>&1 || true; done
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker rmi "$AGENT_IMAGE" >/dev/null 2>&1 || true
	# A work folder made here keeps only the logs.
	if [ "$OWN_WORK" = 1 ]; then
		chmod -R u+w "$WORK" 2>/dev/null || true
		find "$WORK" -mindepth 1 -maxdepth 1 ! -name out -exec rm -rf {} + 2>/dev/null || true
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$GC" "$GM" "$WORK/image" "$WORK/out"
free_check

gorun() {
	net=$1; shift
	docker run --rm --init --cpus=4 --memory=4g --memory-swap=4g \
		--user "$(id -u):$(id -g)" --network "$net" \
		-v "$ROOT":/src -w /src -v "$GC":/gc -v "$GM":/gm \
		-e GOCACHE=/gc -e GOMODCACHE=/gm -e HOME=/tmp -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -p=2" \
		"$@"
}

# Agent binary with the release flags of Dockerfile.agent.
VERSION=${VERSION:-0.0.0-upgradeharness}
case $VERSION in
*[!A-Za-z0-9.+-]* | '') echo "upgradeharness: invalid VERSION" >&2; exit 2 ;;
esac
gorun bridge -e CGO_ENABLED=0 -v "$WORK/image":/out "$GO_IMAGE" sh -c "go build -trimpath -buildvcs=false \
	-ldflags='-s -w -buildid= -X github.com/seawise/client/internal/constants.Version=$VERSION' \
	-o /out/seawise-agent ./cmd/seawise-agent"
# The test binary is built while the network is still reachable, so the
# module cache is complete before the internal network is used.
gorun bridge "$GO_IMAGE" go test -tags upgradeharness -run '^$' ./tools/upgradeharness >/dev/null

# Image: Dockerfile.agent's runtime stage unchanged, over the binary above.
cp "$ROOT/entrypoint-agent.sh" "$WORK/image/"
{
	printf 'FROM scratch AS builder\nCOPY seawise-agent /seawise-agent\n\n'
	sed -n '/^# Runtime stage/,$p' "$ROOT/Dockerfile.agent"
} > "$WORK/image/Dockerfile"
free_check
docker build -q --build-arg VERSION="$VERSION" -t "$AGENT_IMAGE" "$WORK/image" >/dev/null

for img in $V1_IMAGES; do
	docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
done

docker network create --internal "$NET" >/dev/null
SOCK_GID=$(stat -c %g /var/run/docker.sock)
rc=0
i=1
while [ "$i" -le "$RUNS" ]; do
	free_check
	mkdir -p "$WORK/out/run$i"
	start=$(date +%s)
	if gorun "$NET" --name "${ID}-test" --network-alias api.upgrade.test --network-alias frp-1.upgrade-harness.seawise.dev \
		--group-add "$SOCK_GID" -v /var/run/docker.sock:/var/run/docker.sock \
		-v "$WORK/out/run$i":"$WORK/out/run$i" \
		-e GOPROXY=off -e HARNESS_NETWORK="$NET" -e HARNESS_DIR="$WORK/out/run$i" -e HARNESS_AGENT_IMAGE="$AGENT_IMAGE" \
		"$GO_IMAGE" go test -tags upgradeharness -count=1 -timeout 45m -v ./tools/upgradeharness > "$WORK/out/run$i/test.log" 2>&1; then
		echo "run $i: PASS in $(( $(date +%s) - start ))s"
	else
		echo "run $i: FAIL in $(( $(date +%s) - start ))s (log: $WORK/out/run$i/test.log)"
		rc=1
		break
	fi
	i=$((i + 1))
done
echo "logs: $WORK/out"
exit $rc
