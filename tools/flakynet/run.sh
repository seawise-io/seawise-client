#!/bin/sh
# Runs the agent through a faulty network. The agent image built from this
# checkout (test roots only), a test edge with the device API and update
# repository, and a netem sidecar in the agent's network namespace run on a
# Docker network without internet access. Faults are applied to the agent's
# side of the link; TestFlakyReport then checks every scenario.
#
# Needs Docker and the sch_netem kernel module. Go runs in GO_IMAGE.
# Building the images fetches Alpine packages; the runs never leave the
# internal network. Environment:
#   GO_IMAGE       Go toolchain image (default: the Makefile's pinned image)
#   FLAKY_WORK     work folder for caches, logs and the image context
#                  (default: a new folder under /tmp)
#   FLAKY_RUNS     consecutive runs that must all pass (default 1)
#   FLAKY_MIN_FREE_GB  stop when less disk is free (default 4)
#   FLAKY_GOCACHE, FLAKY_GOMODCACHE  Go caches (default: in FLAKY_WORK)
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GO_IMAGE=${GO_IMAGE:-$(sed -n 's/^GO_IMAGE ?= //p' "$ROOT/Makefile")}
OWN_WORK=0
if [ -z "${FLAKY_WORK:-}" ]; then
	FLAKY_WORK=$(mktemp -d /tmp/flakynet.XXXXXX)
	OWN_WORK=1
fi
WORK=$FLAKY_WORK
RUNS=${FLAKY_RUNS:-1}
MIN_FREE=${FLAKY_MIN_FREE_GB:-4}
GC=${FLAKY_GOCACHE:-$WORK/gocache}
GM=${FLAKY_GOMODCACHE:-$WORK/gomod}
ID=fn$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
NET=$ID
AGENT_IMAGE=seawise-flakynet-agent:$ID
TOOLS_IMAGE=seawise-flakynet-tools:$ID
UIDGID="$(id -u):$(id -g)"
BASE=$(sed -n 's/^FROM \(alpine:[^ ]*\)$/\1/p' "$ROOT/Dockerfile.agent" | head -1)

free_check() {
	avail=$(df --output=avail -BG "$WORK" | tail -1 | tr -dc 0-9)
	if [ "$avail" -lt "$MIN_FREE" ]; then
		echo "flakynet: only ${avail}G free, stopping" >&2
		exit 3
	fi
}

stop_run() {
	for c in $(docker ps -aq --filter "name=^${ID}-"); do docker rm -f "$c" >/dev/null 2>&1 || true; done
}

cleanup() {
	stop_run
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker rmi "$AGENT_IMAGE" "$TOOLS_IMAGE" >/dev/null 2>&1 || true
	if [ "$OWN_WORK" = 1 ]; then
		chmod -R u+w "$WORK" 2>/dev/null || true
		find "$WORK" -mindepth 1 -maxdepth 1 ! -name out -exec rm -rf {} + 2>/dev/null || true
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$GC" "$GM" "$WORK/image" "$WORK/tools" "$WORK/bin" "$WORK/out"
free_check

gorun() {
	docker run --rm --init --cpus=4 --memory=4g --memory-swap=4g --user "$UIDGID" \
		-v "$ROOT":/src -w /src -v "$GC":/gc -v "$GM":/gm -v "$WORK/bin":/out \
		-e GOCACHE=/gc -e GOMODCACHE=/gm -e HOME=/tmp -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -p=2" -e CGO_ENABLED=0 \
		"$GO_IMAGE" "$@"
}

# The agent as released, with the test roots of the seawise_tuftest tag.
gorun go build -trimpath -buildvcs=false -tags seawise_tuftest \
	-ldflags='-s -w -buildid= -X github.com/seawise/client/internal/constants.Version=2.0.0' \
	-o /out/seawise-agent ./cmd/seawise-agent
gorun go test -c -tags flakynet -o /out/flakynet.test ./tools/flakynet

# Agent image: Dockerfile.agent's runtime stage unchanged.
cp "$WORK/bin/seawise-agent" "$ROOT/entrypoint-agent.sh" "$WORK/image/"
{
	printf 'FROM scratch AS builder\nCOPY seawise-agent /seawise-agent\n\n'
	sed -n '/^# Runtime stage/,$p' "$ROOT/Dockerfile.agent"
} > "$WORK/image/Dockerfile"
free_check
docker build -q -t "$AGENT_IMAGE" "$WORK/image" >/dev/null
# Edge and netem tools.
printf 'FROM %s\nRUN apk add --no-cache iproute2 iproute2-tc\n' "$BASE" > "$WORK/tools/Dockerfile"
docker build -q -t "$TOOLS_IMAGE" "$WORK/tools" >/dev/null

docker network create --internal "$NET" >/dev/null

now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

# scen NAME KIND START END appends a scenario to the log.
scen() {
	printf '{"name":"%s","kind":"%s","start":"%s","end":"%s"}\n' "$1" "$2" "$3" "$4" >> "$IO/scenarios.jsonl"
	echo "  $1 done"
}

netem() { docker exec "${ID}-netem" "$@"; }

agent_start() {
	docker run -d --name "${ID}-agent" --network "$NET" --cpus 1 --memory 128m --memory-swap 128m \
		--read-only --tmpfs /tmp --user "$UIDGID" --cap-drop ALL --security-opt no-new-privileges \
		-v "$IO/data":/config -v "$IO/tuf":/tuf:ro -v "$IO/ca.pem":/ca.pem:ro \
		-e SSL_CERT_FILE=/ca.pem -e SEAWISE_TEST_TUF_DIR=/tuf "$AGENT_IMAGE" >/dev/null
}

wait_for() { # FILE PATTERN SECONDS
	w=0
	until grep -q "$2" "$1" 2>/dev/null; do
		w=$((w + 1))
		if [ "$w" -gt "$(($3 * 5))" ]; then
			echo "flakynet: timed out waiting for $2 in $1" >&2
			return 1
		fi
		sleep 0.2
	done
}

one_run() {
	IO=$1
	mkdir -p "$IO"
	: > "$IO/control"
	: > "$IO/scenarios.jsonl"
	docker run -d --name "${ID}-world" --network "$NET" \
		--network-alias tunnel-us-east.seawise.dev --network-alias api.flakynet.test \
		--sysctl net.ipv4.ip_unprivileged_port_start=0 --cpus 1 --memory 512m --memory-swap 512m \
		--read-only --tmpfs /tmp --user "$UIDGID" --cap-drop ALL --security-opt no-new-privileges \
		-v "$IO":/io -v "$WORK/bin":/flaky:ro -e FLAKYNET_ROLE=world -e FLAKYNET_DIR=/io \
		"$TOOLS_IMAGE" /flaky/flakynet.test -test.run '^TestWorld$' -test.v -test.timeout 3h >/dev/null
	w=0
	until [ -f "$IO/ready" ]; do
		w=$((w + 1))
		if [ "$w" -gt 300 ]; then
			echo "flakynet: the world did not start" >&2
			docker logs "${ID}-world" > "$IO/world.log" 2>&1
			return 1
		fi
		sleep 0.2
	done
	agent_start
	docker run -d --name "${ID}-netem" --network "container:${ID}-agent" --cap-drop ALL --cap-add NET_ADMIN \
		"$TOOLS_IMAGE" sleep 7200 >/dev/null
	wait_for "$IO/events.jsonl" '"kind":"up"' 120 || { docker logs "${ID}-agent" > "$IO/agent.log" 2>&1; return 1; }
	sleep 30

	s=$(now); sleep 60; scen baseline steady "$s" "$(now)"

	netem tc qdisc add dev eth0 root netem delay 300ms 50ms
	s=$(now); sleep 120; e=$(now)
	netem tc qdisc del dev eth0 root
	scen latency-300ms steady "$s" "$e"
	sleep 20

	netem tc qdisc add dev eth0 root netem delay 80ms loss 5%
	s=$(now); sleep 120; e=$(now)
	netem tc qdisc del dev eth0 root
	scen loss-5pct steady "$s" "$e"
	sleep 20

	s=$(now); netem ip link set eth0 down; sleep 10; netem ip link set eth0 up; e=$(now)
	sleep 70; scen flap-10s outage "$s" "$e"

	s=$(now); netem ip link set eth0 down; sleep 60; netem ip link set eth0 up; e=$(now)
	sleep 70; scen flap-60s outage "$s" "$e"

	netem tc qdisc add dev eth0 root netem loss 100%
	s=$(now); sleep 45; e=$(now)
	netem tc qdisc del dev eth0 root
	sleep 70; scen blackhole-45s outage "$s" "$e"

	s=$(now); echo "block_raw on" >> "$IO/control"; sleep 120; e=$(now)
	echo "block_raw off" >> "$IO/control"
	scen raw-tls-blocked raw_block "$s" "$e"

	# The agent's clock cannot be moved in a container; the edge's clock
	# (certificates, signed times) moves instead and the agent starts again.
	docker rm -f "${ID}-netem" >/dev/null
	for off in 10m -10m 48h -48h; do
		echo "offset $off" >> "$IO/control"
		sleep 1
		docker rm -f "${ID}-agent" >/dev/null
		s=$(now); agent_start; sleep 60; e=$(now)
		scen "clock-edge-$off" clock "$s" "$e"
	done
	# A device without a real-time clock boots near 1970 with the time
	# floor it stored: seen from the agent, the edge is 56 years ahead.
	docker rm -f "${ID}-agent" >/dev/null
	echo "offset 490896h" >> "$IO/control"
	echo floor >> "$IO/control"
	sleep 1
	s=$(now); agent_start; sleep 60; e=$(now)
	scen clock-boot-1970 clock "$s" "$e"
	echo "offset 0s" >> "$IO/control"

	echo stop >> "$IO/control"
	docker wait "${ID}-world" >/dev/null
	docker logs "${ID}-world" > "$IO/world.log" 2>&1
	docker logs "${ID}-agent" > "$IO/agent.log" 2>&1
	stop_run
	docker run --rm --network none --user "$UIDGID" -v "$IO":/io:ro -v "$WORK/bin":/flaky:ro \
		-e FLAKYNET_ROLE=report -e FLAKYNET_DIR=/io "$TOOLS_IMAGE" \
		/flaky/flakynet.test -test.run '^TestFlakyReport$' -test.v > "$IO/report.log" 2>&1
}

rc=0
run=1
while [ "$run" -le "$RUNS" ]; do
	free_check
	start=$(date +%s)
	echo "run $run"
	if one_run "$WORK/out/run$run"; then
		echo "run $run: PASS in $(( $(date +%s) - start ))s"
	else
		echo "run $run: FAIL in $(( $(date +%s) - start ))s (logs: $WORK/out/run$run)"
		stop_run
		rc=1
		break
	fi
	run=$((run + 1))
done
echo "logs: $WORK/out"
exit $rc
