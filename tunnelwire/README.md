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

Streams are multiplexed with `libp2p/go-yamux/v5`. A stream starts with a
256 KiB receive window and doubles it each round trip while its reader
keeps up, to at most 16 MiB. Every window reservation goes through a
`caps.Gate`, go-yamux's memory manager: the agent charges a 32 MiB session
budget, the edge a per-session budget (32 MiB default) and its 256 MiB
global budget. Growth is granted only from what the budget has left, so one
busy stream can grow while idle streams keep 256 KiB
(`TestBusyStreamGrowsIdleStreamsStaySmall`). `max_streams` stays at
budget / 256 KiB = 128.

go-yamux closes the whole session when an incoming stream's initial window
cannot be reserved. The agent gate therefore always grants initial windows,
whose number `MaxIncomingStreams` caps at `max_streams`, and refuses only
growth. Its worst case is the 32 MiB budget plus initial windows of streams
opened after the budget filled: at most 64 MiB. The edge gate refuses both,
since the edge opens data streams itself and a refused open fails only that
stream.

Per-stream throughput: frp v0.67 uses `hashicorp/yamux` with a static 6 MiB
window on both sides (`client/connector.go`, `server/service.go`), a bound
of about 60 MiB/s per stream at 100 ms RTT. With 16 MiB windows the bound is
about 160 MiB/s; `TestThroughputAt100msRTT` sends 512 MiB over a loopback
link with 50 ms added each way and requires at least 50 MiB/s on one stream
(measured: about 75 MiB/s). Window growth needs an RTT sample, so go-yamux
pings once at session start and then every 10 minutes; its keepalive is off.

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
