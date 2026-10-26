# Mutation survivors

Mutants that `gremlins unleash --workers 1 --timeout-coefficient 40` leaves
alive, each with the reason it is equivalent (no input can tell it apart
from the original); `caps` and `httpwire` were last run after the gate and
trailer changes, on Go 1.26.10. Mutants reported as timed out make the
tests hang (a read loop never ends) and count as detected. Every other
mutant in `wire`, `caps`, `handshake`,
`httpwire`, `claims` and `ladder` is killed.

| Location | Mutation | Why it is equivalent |
|---|---|---|
| `wire/strict.go` `n < 0` after `ConsumeTag` | `<` to `<=` | `ConsumeTag` returns a negative error code or at least 1, never 0 |
| `wire/strict.go` `m < 0` after `ConsumeFieldValue` | `<` to `<=` | returns a negative error code or at least 1, never 0 |
| `wire/strict.go` `m < 0` after both `ConsumeVarint` calls | `<` to `<=` | `ConsumeVarint` never returns 0 |
| `wire/strict.go` `int(num) >= len(seen)` | `>=` to `>` | only reached for known fields, all numbered below 32 (`TestEveryFieldCapped`), so `num == 32` cannot occur |
| `wire/strict.go` enum range check, both bounds | `<`/`>` to `<=`/`>=` | `MinInt32` and `MaxInt32` are not enum values either, so both paths give `bad_value` |
| `wire/text.go` `len(s) >= 1` in `ValidAgentVersion` | `>=` to `>` | a 1-byte string never matches the semver pattern |
| `caps/caps.go` `budget <= 0` | `<=` to `<` | a budget of 0 gives 0 streams through the division as well |
| `caps/caps.go` `n > MaxStreamsLimit` | `>` to `>=` | at `n == 4096` both branches return 4096 |
| `httpwire/httpwire.go` `colon <= 0` | `<=` to `<` | a line starting with `:` is then refused by `net/http` as malformed, same result |
| `httpwire/httpwire.go` `int64(len(p)) > b.left` | `>` to `>=` | trimming `p` to its own length changes nothing |
| `httpwire/httpwire.go` `len(req.Trailer) > 0` | `>` to `>=` | assigns an empty or nil trailer; the summary is the same |
| `ladder/ladder.go` `d < cap` in `backoff` | `<` to `<=` | one extra doubling at the cap is clipped by `min(d, cap)` |

gremlins reports `switch` case expressions and constant declarations as
"not covered" because it maps coverage to case bodies. The case
expressions in `claims/device.go`, `claims/flags.go` and `ladder/ladder.go`
were mutated by hand (negation and boundary) and every mutant was killed.
Constant arithmetic (sizes such as `256 << 10`) is pinned by the tests
that check the derived values.
