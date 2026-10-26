# tunnelwire

Wire library for `seawise-tunnel/1`, shared by the edge and the agent. It is
a separate Go module so the edge can import it without the client's
dependencies; it depends only on the protobuf runtime, `libp2p/go-yamux/v5`
(MPL-2.0, whose only runtime dependency is `libp2p/go-buffer-pool`, MIT)
and the standard library.

| Package | Contents |
|---|---|
| `proto/seawise/tunnel/v1` | the schema; `tunnelpb` is generated from it |
| `wire` | framing, strict decoding and validation of every message, header and relay prefix |
| `handshake` | Hello and HelloAck signatures, Hello checks, negotiation, peer edge handshake |
| `caps` | yamux configuration, stream caps, buffer budgets, liveness, session lifetime |
| `httpwire` | request-bytes rules of a data stream |
| `claims` | RouteSet, flags and signed-state payload checks, relayed call binding |
| `ladder` | reference model of the agent's fallback ladder |
| `wsconn` | byte stream over WebSocket messages |

Vectors live in `testdata/vectors` (see its README).

## Stream window and buffer budgets

Streams are multiplexed with `libp2p/go-yamux/v5`. A stream starts with the
256 KiB receive window yamux fixes and doubles it each round trip while its
reader keeps up, to at most 16 MiB (go-yamux stalls a stream if the cap is
not a power of two). Every window reservation goes through a `caps.Gate`,
go-yamux's memory manager.

The agent's session budget is 48 MiB, strict: 32.25 MiB holds the initial
windows of 128 data streams and stream 0, the remaining 15.75 MiB is the
growth pool, enough for one busy stream to reach 16 MiB
(`TestBusyStreamGrowsIdleStreamsStaySmall`, `Test128StreamsStayWithinBudget`).
`max_streams` stays at 128. go-yamux closes the whole session when an
incoming stream's initial window cannot be reserved, so an initial window
beyond 129 (an edge exceeding `max_streams`, or a new stream racing an old
one's cleanup) is taken from the growth pool; the session closes only when
both pools are spent.

The edge charges a per-session budget (48 MiB default) and its 256 MiB
global budget and refuses any reservation that does not fit; the edge
opens data streams itself, so a refusal fails only that open.

Per-stream throughput: frp v0.67 uses `hashicorp/yamux` with a static 6 MiB
window on both sides (`client/connector.go`, `server/service.go`), a bound
of about 60 MiB/s per stream at 100 ms RTT. `TestThroughputAt100msRTT` sends
512 MiB each way over a loopback link with 50 ms added in each direction
and requires at least 50 MiB/s on one stream; it measures about 75 MiB/s
both for downloads (edge receiving) and uploads (agent receiving). Window
growth needs an RTT sample, so go-yamux pings once at session start and then
every 10 minutes; its keepalive is off.

## Fuzzing

```
go test ./wire/ -run '^$' -fuzz '^FuzzControlFrame$' -fuzztime 10m -fuzzminimizetime 10s
```

Large control frames make minimization slow; a short `-fuzzminimizetime`
keeps minimization from running past `-fuzztime`. One early 60 s run of
`FuzzControlFrame` without that flag ended in a failure that wrote no
failing input; it did not recur in about 32 minutes of later runs (10 min
each with `-race` at GOMAXPROCS 1 and 4, and repeated 60 s and 120 s runs),
so it is recorded as an engine-side failure, not a parser defect.

## Mutation testing

`testdata/MUTATION_SURVIVORS.md` lists every mutant that survives and why
it is equivalent.
