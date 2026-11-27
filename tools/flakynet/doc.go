// Package flakynet runs the agent through a faulty network: packet loss,
// latency, link flaps, a dropped NAT mapping, raw TLS blocked in the middle
// of a session, and clocks that disagree with the edge. The agent, a test
// edge and the faults run in capped containers on a Docker network without
// internet access; run.sh builds and drives them. The tests need the
// flakynet build tag.
package flakynet
