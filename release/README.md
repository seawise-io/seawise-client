# Release channels

| Tag | Image | Moved by |
|---|---|---|
| `:latest`, `:1.0`, `:1.0.x` | current client (`Dockerfile`) | a `v1.*` tag on `main` |
| `:2.x.y`, `:2.x.y-beta.n` | client v2 (`Dockerfile.agent`) | a `v2.*` tag on `main` |
| `:2`, `:beta` | newest v2 release, including pre-releases | a `v2.*` tag on `main` |
| `:stable` | a v2 release chosen by the maintainer | `promote-stable.yml`, with a signed manifest |

A `v2.*` tag never moves `:latest` or any `:1.*` tag. v2 GitHub releases
are never marked as the latest release.

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
is in this repository, at `release/keys/release.pub`. Each signature is
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
