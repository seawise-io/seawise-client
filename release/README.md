# Release channels

| Tag | Image | Moved by |
|---|---|---|
| `:latest`, `:1.0`, `:1.0.x` | current client (`Dockerfile`) | a `v1.*` tag on `main` |
| `:1.0.x-rc.n` | current client pre-release | a `v1.X.Y-pre` tag on `main` |
| `:2.x.y`, `:2.x.y-beta.n` | client v2 (`Dockerfile.agent`) | a `v2.*` tag on `main` |
| `:2` | newest v2 release (not pre-releases) | a `v2.X.Y` tag on `main` |
| `:beta` | newest v2 release or pre-release | a `v2.*` tag on `main` |
| `:stable` | a v2 release chosen by the maintainer | `promote-stable.yml`, with a signed manifest |

Tags must be strict semver (`v1.X.Y[-pre]`, `v2.X.Y[-pre]`); others fail.
Pre-releases never move `:latest`, `:1.X` or `:2`. A `v2.*` tag never moves
`:latest` or any `:1.*` tag, and `:2` and `:beta` never move to a lower
version than the image they point at. v2 GitHub releases are never marked
as the latest release.

Every image is signed with cosign (keyless, GitHub OIDC) and carries an
SPDX SBOM attestation. v2 images also carry signed SLSA provenance for
each platform:

```
cosign verify ghcr.io/seawise-io/seawise-client:beta \
  --certificate-identity-regexp '^https://github.com/seawise-io/seawise-client/.github/workflows/release.yml@refs/tags/v2\.' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Promoting to stable

`:stable` moves only when `release/stable.json` on `main` is signed by the
release key. The release key is an ECDSA P-256 cosign key kept offline by
the maintainer (on a hardware token, or encrypted on removable media) and
used only to sign this manifest. It is never stored in CI or in repository
secrets and is separate from any key the service uses. Only its public key
is in this repository, at `release/keys/release.pub`, and its SHA-256 is
pinned in `promote-stable.yml` (`RELEASE_KEY_SHA256`), so swapping the key
also needs a workflow change. Both only hold if changes to `main` require
review: branch protection on `main` is required. Each signature is
also recorded in the public Sigstore transparency log, which the workflow
requires, so every use of the key is visible.

1. Write `release/stable.json`:

   ```json
   {
     "channel": "stable",
     "image": "ghcr.io/seawise-io/seawise-client",
     "version": "2.1.0",
     "digest": "sha256:<index digest of :2.1.0>",
     "expires": "2027-01-31T00:00:00Z"
   }
   ```

2. Sign it with the same cosign major version the workflow installs:
   `cosign sign-blob --key <release key> --bundle release/stable.json.bundle release/stable.json`
3. Merge both files to `main`, then run `promote-stable.yml` with the version.

The workflow verifies the signature, that the manifest has not expired and
names the dispatched version, that `:<version>` still points at the signed
digest, and that the digest was signed by `release.yml` for tag
`v<version>`. Only then does it move `:stable`. Rolling back is the same
procedure with an earlier version.

## Signed update metadata (TUF)

Update notices and the signing key set are published as a TUF repository
(`tools/tuf/README.md`). Root and targets keys stay offline like the
release key. The snapshot and timestamp keys are the only signing keys in
CI, as secrets of the `tuf-online` environment used by
`.github/workflows/tuf-refresh.yml`. Before any secret is added to it:

- limit `tuf-online` to the `main` branch (deployment branches: `main`
  only), and
- require a reviewer for it.

The workflow also refuses to run outside `main`, and stays off until the
repository variable `TUF_REFRESH_ENABLED` is `true`. Branch protection on
`main` is required for these checks to mean anything.
