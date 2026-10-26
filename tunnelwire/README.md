# tunnelwire

Wire library for `seawise-tunnel/1`, shared by the edge and the agent. It is
a separate Go module so the edge can import it without the client's
dependencies; it depends only on the protobuf runtime, `hashicorp/yamux`
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

## Stream window

`hashicorp/yamux` has no window auto-tuning: a stream's receive window is
`MaxStreamWindowSize` from the moment it opens (`caps.TestYamuxWindowIsStatic`
shows 6 MiB buffered before any read). To keep a session's buffered bytes
within its budget, the window stays at the 256 KiB minimum and
`max_streams = budget / window` (128 for the agent's 32 MiB).

A static window bounds one stream's throughput at window / RTT. frp v0.67
uses the same library with a static 6 MiB window on both sides
(`client/connector.go`, `server/service.go`: `MaxStreamWindowSize = 6 * 1024 * 1024`),
a bound of about 60 MiB/s per stream at 100 ms RTT; 256 KiB gives about
2.5 MiB/s. Before this protocol replaces frp, a measurement must show
per-stream throughput at 100 ms RTT at least equal to frp v0.67's. If it is
lower, the multiplexer moves to `libp2p/go-yamux`, whose memory manager
grants window growth from a shared budget.

## Fuzzing

```
go test ./wire/ -run '^$' -fuzz '^FuzzControlFrame$' -fuzztime 10m -fuzzminimizetime 10s
```

Large control frames make minimization slow; a short `-fuzzminimizetime`
keeps minimization from running past `-fuzztime`.

## Mutation testing

`testdata/MUTATION_SURVIVORS.md` lists every mutant that survives and why
it is equivalent.
