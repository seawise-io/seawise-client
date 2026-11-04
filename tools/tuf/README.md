# TUF repository tool

`go run ./tools/tuf` maintains the [TUF](https://theupdateframework.io)
repository that `seawise-agent` uses to verify update notices and the
signing key set. It is a maintainer tool: it is not built into the agent
binary or image.

## Layout

The repository is static and uses consistent snapshots, so any static host
(GitHub Pages, an R2 or S3 bucket) can serve it with no server logic:

```
metadata/1.root.json ... N.root.json   every root version, kept forever
metadata/<v>.targets.json
metadata/<v>.snapshot.json
metadata/timestamp.json                the only file that changes in place
targets/[dir/]<sha256>.<name>
```

Every file except `metadata/timestamp.json` is immutable. Upload new files
first and `timestamp.json` last. The host must serve them without
redirects; the agent does not follow redirects.

Targets: `keyset.json` (signing keys the agent trusts) and
`release/stable.json`, `release/beta.json` (release manifests, same format
as `release/stable.json` described in `release/README.md`).

## Roles

| Role | Keys | Kept | Default expiry |
|---|---|---|---|
| root | three, threshold 2 (at least threshold + 1) | offline, apart | 365 days |
| targets | one | offline | 120 days |
| snapshot | one | SeaWise publishing job | 14 days |
| timestamp | one | SeaWise publishing job | 14 days |

Two of the three root keys sign every new root, so a single stolen root key
cannot, and losing one root key does not need a client release. The tool
and the agent refuse a root threshold below 2 and a root role without at
least one key more than its threshold. A new root must be signed by a
threshold of the current root keys and of its own root keys.

Expired metadata only stops update notices and signed instructions. It
never stops tunnels: the last verified key set stays in use, and nothing
stored is deleted.

## Commands

Offline machine (root and targets keys):

```
tuf keygen -out root-1.pem                    # also writes root-1.pem.pub; never overwrites
tuf init -production -allow-keys allowed-keys -dir repo \
  -root-key root-1.pem.pub -root-key root-2.pem.pub -root-key root-3.pem.pub \
  -targets-key targets.pem.pub -snapshot-key snapshot.pem.pub -timestamp-key timestamp.pem.pub \
  -sign root-1.pem -sign root-2.pem -targets-sign targets.pem
tuf sign-targets -dir repo -key targets.pem -add keyset.json=keyset.json -add release/stable.json=stable.json
tuf rotate-root -dir repo -sign root-2.pem -sign root-3.pem -role-key timestamp=timestamp2.pem.pub
```

Published repository:

```
tuf pull -url https://<host> -dir repo -root internal/updatecheck/root/production.json
tuf verify -metadata-only -dir repo -root internal/updatecheck/root/production.json
```

`init` needs `-production` and an allowlist file of the key IDs printed by
`keygen` (one per line), and refuses keys from a test key folder.

`pull` verifies the repository from the pinned root (`-root`) before
writing: the root chain, signatures, thresholds, versions, lengths and
hashes. Snapshot and timestamp metadata are signed only by the SeaWise
publishing job; this tool holds no online key. Versioned and
content-addressed files are created once and never replaced; only
`metadata/timestamp.json` is. Keys are files (`0600`) or `env:NAME` with
the PEM in an environment variable. Private keys are never printed.

`verify` runs the full client workflow from a trusted root and prints each
role's version and expiry.

## Test repositories

`tuf init-test -dir D` creates a throwaway repository with keys in
`D/keys`, marked with a `TEST-KEYS-DO-NOT-USE` file. Its root carries `"x-seawise-test-only": true` inside the signed
part; the agent refuses such a root outside its tests. Never publish a test
repository or pin its root.

## Production keys

Production keys are created in a key ceremony on an offline machine, with
the two root keys stored apart and a witness; the ceremony is repeated
yearly with a test restore that signs a dummy key set. Until then
`internal/updatecheck/root/production.json` is empty and the agent makes
no update checks. Hardware-token signing is not built in; sign on the
offline machine.
