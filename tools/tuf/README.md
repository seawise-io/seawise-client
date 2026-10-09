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
| root | two (primary and backup), threshold 1 | offline, apart | 365 days |
| targets | one | offline | 120 days |
| snapshot | one | CI environment `tuf-online` | 14 days |
| timestamp | one | CI environment `tuf-online` | 14 days |

Either root key can sign a new root, so losing one root key does not need
a client release. A new root must be signed by a threshold of the current
root keys and of its own root keys.

Expired metadata only stops update notices and actions the agent cannot
verify freshly. It never stops running tunnels.

## Commands

Offline machine (root and targets keys):

```
tuf keygen -out root-primary.pem              # also writes root-primary.pem.pub
tuf init -dir repo \
  -root-key root-primary.pem.pub -root-key root-backup.pem.pub \
  -targets-key targets.pem.pub -snapshot-key snapshot.pem.pub -timestamp-key timestamp.pem.pub \
  -sign root-primary.pem -targets-sign targets.pem
tuf sign-targets -dir repo -key targets.pem -add keyset.json=keyset.json -add release/stable.json=stable.json
tuf rotate-root -dir repo -sign root-backup.pem -role-key timestamp=timestamp2.pem.pub
```

Online (scheduled workflow, or by hand):

```
tuf pull -url https://<host> -dir repo
tuf refresh -dir repo -snapshot-key env:TUF_SNAPSHOT_KEY -timestamp-key env:TUF_TIMESTAMP_KEY
tuf verify -metadata-only -dir repo -root internal/updatecheck/root/production.json
```

`refresh` always signs a new timestamp and signs a new snapshot when
targets changed or the snapshot has less than 7 days left, so a weekly run
keeps a 14-day expiry valid. Keys are files (`0600`) or `env:NAME` with the
PEM in an environment variable. Private keys are never printed.

`verify` runs the full client workflow from a trusted root and prints each
role's version and expiry.

## Test repositories

`tuf init-test -dir D` creates a throwaway repository with keys in
`D/keys`. Its root carries `"x-seawise-test-only": true` inside the signed
part; the agent refuses such a root outside its tests. Never publish a test
repository or pin its root.

## Production keys

Production keys are created in a key ceremony on an offline machine, with
the two root keys stored apart and a witness; the ceremony is repeated
yearly with a test restore that signs a dummy key set. Until then
`internal/updatecheck/root/production.json` is empty and the agent makes
no update checks. Hardware-token signing is not built in; sign on the
offline machine.

## Scheduled refresh

`.github/workflows/tuf-refresh.yml` runs weekly and on dispatch, only when
the repository variable `TUF_REFRESH_ENABLED` is `true`. It needs the
environment `tuf-online` with secrets `TUF_SNAPSHOT_KEY` and
`TUF_TIMESTAMP_KEY` and the variable `TUF_REPO_URL`. The publish step
fails until a host is chosen.
