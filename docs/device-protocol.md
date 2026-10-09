# Device protocol

This document defines the formats the agent uses to prove its identity to the SeaWise control plane and edges, and to check what SeaWise sends back. It is normative for the agent (`internal/protocol`) and for any server that talks to it. Test vectors in `testdata/vectors/` cover every rule below; an implementation is conformant when it produces the expected result for every case.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conventions

**Base64url.** Every binary value is base64url without padding (RFC 4648 §5). Decoders MUST reject padding, characters outside the URL-safe alphabet, and encodings whose unused trailing bits are not zero.

**JSON.** Every JSON document is a UTF-8 object. Decoders MUST reject:
- invalid UTF-8;
- duplicate member names at any depth;
- members not listed for the format;
- missing required members;
- trailing data after the object.

Times are integer seconds since the Unix epoch, written as JSON integers (no fraction, no exponent) in the range 0 to 2^53-1.

**Identifiers.** `jti`, `run_id` and `ins_id` are 22 to 64 characters from the base64url alphabet; senders use 16 or more random bytes. `server_id` is a lower-case canonical UUID (`8-4-4-4-12` hex digits).

**Leeway.** Where a rule compares a time with the verifier's clock, the leeway is 300 seconds.

## 2. Keys

All signatures are Ed25519 (RFC 8032), pure mode.

**Public keys** are 32 bytes. Verifiers MUST reject a public key whose encoding is not canonical (the y coordinate is not below 2^255-19, or x is zero with the sign bit set) or that does not decode to a curve point, and a key of small order (eight times the point is the identity). Signatures MUST be 64 bytes, and verifiers MUST reject signatures whose scalar S is not below the group order L.

**JWK.** A public key is written as exactly `{"kty":"OKP","crv":"Ed25519","x":"<base64url key>"}`. A JWK with any other member, including the private `d`, MUST be rejected.

**Key ID.** The key ID is the RFC 7638 JWK thumbprint: base64url of SHA-256 over `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` with no whitespace. It is 43 characters and equals the `jkt` of RFC 9449.

**Fingerprint.** The fingerprint shown to people is `SW-` followed by the first two bytes of the thumbprint digest in upper-case hex, `-`, and the next two bytes, for example `SW-4F2A-91C0`. It carries 32 bits and is a comparison aid only: it is not unique and MUST NOT be used to identify or look up a key.

## 3. Signed tokens

Every signed format is a JWS in compact serialization (RFC 7515): three base64url segments, `header.payload.signature`, signed over the ASCII bytes of `header.payload`.

**Header.** The protected header has exactly these members:
- `alg`: MUST be `EdDSA` (RFC 8037). Any other value, including `none` and `HS256`, MUST be rejected before any key is used.
- `typ`: fixed per format (table below). It separates the formats: a token of one type MUST NOT be accepted as another.
- either `kid` (the signer's key ID) or `jwk` (only DPoP proofs), as the format says.

Any other header member (for example `crit`, `jku`, `x5u`, `b64`) MUST be rejected. A verifier takes the verification key from its own trusted source (pinned roots, the key set, the device registry), never from the token, except where a format says otherwise.

| Format | `typ` | Key member | Signed by |
|---|---|---|---|
| Request proof | `dpop+jwt` | `jwk` | device key |
| frp login token | `sw-frp+jwt` | `kid` | device key |
| Key rotation | `sw-rotate+jwt` / `sw-rotate-pop+jwt` | `kid` | old / new device key |
| Key set | `sw-keyset+jwt` | `kid` | root key |
| Instruction | `sw-instr+jwt` | `kid` | control key from the key set |
| Signed time | `sw-time+jwt` | `kid` | control key from the key set |

**Size.** A token longer than 4096 bytes (65536 for a key set) MUST be rejected before decoding.

## 4. Request proofs (DPoP)

HTTPS requests from the agent to the control plane carry a proof of possession of the device key, following RFC 9449 with the changes below. Freshness comes from server nonces, not from the agent's clock.

**Header:** `{"typ":"dpop+jwt","alg":"EdDSA","jwk":<device public JWK>}`.

**Claims** (all required, no others):

| Claim | Value |
|---|---|
| `jti` | Unique identifier for this proof |
| `htm` | The HTTP method, exactly as sent |
| `htu` | The request URL in canonical form (below) |
| `iat` | The agent's time. Required for compatibility; verifiers MUST NOT use it for freshness |
| `nonce` | The most recent `DPoP-Nonce` value from the server: 1 to 256 characters, `%x21 / %x23-5B / %x5D-7E` |
| `body_sha256` | base64url SHA-256 of the exact request body bytes; an empty body hashes the empty string |

**Canonical URL:** lower-case scheme and host, the port omitted when it is the scheme default, the path as sent (`/` when empty), no userinfo, query or fragment. The verifier computes the canonical form of the URL it received the request on and compares it byte for byte with `htu`.

**Verification order:** size; segments and base64url; header (`alg`, `typ`, `jwk`); signature with the `jwk`; claims; `htm`; `htu`; `body_sha256`; `nonce`; replay. Error codes in §10.

**Nonces.** The server issues a nonce in the `DPoP-Nonce` response header, valid for at most 5 minutes and rotated. A request whose nonce is missing, unknown or expired gets `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce`; the agent retries once with it. The agent always keeps the newest nonce it has seen.

**Replay.** The server records each accepted (key ID, `jti`) pair for the nonce lifetime and rejects a second use.

**Key.** The server identifies the device by the key ID of the `jwk` and checks it against its registry. During pairing the key is not yet registered; the pairing request binds it.

## 5. frp login token

The agent mints its own login token for the tunnel server. It is placed in the frp login metadata and verified by the edge against the device registry, so no control-plane call is needed to reconnect.

**Header:** `{"alg":"EdDSA","typ":"sw-frp+jwt","kid":<device key ID>}`.

**Claims** (all required, no others): `server_id`, `key_id` (equal to the header `kid`), `iat`, `run_id` (random per agent start).

**Verification.** The verifier looks up `server_id` in its registry (public key, status, `valid_from`) and:
1. rejects the token if the login names a different server (`wrong_server`);
2. rejects it if the registry has no key for the server or the key ID differs (`unknown_key`), or the key is not `active` (`key_revoked`);
3. verifies the signature;
4. rejects `iat` more than 300 seconds in the future (`not_yet_valid`), older than 30 days (`expired`), or more than 300 seconds before the key's `valid_from` (`before_key_valid`).

The agent re-mints the token when it passes half its life. Revoking a device is a registry change; tokens do not need to expire for it to take effect.

## 6. Key rotation

The agent may replace its device key at any time. A rotation is a JSON object with two tokens over the **same** payload segment:

```json
{"statement": "<JWS signed by the old key>", "pop": "<JWS signed by the new key>"}
```

**Headers:** `statement`: `{"alg":"EdDSA","typ":"sw-rotate+jwt","kid":<old key ID>}`; `pop`: `{"alg":"EdDSA","typ":"sw-rotate-pop+jwt","kid":<new key ID>}`.

**Claims** (all required, no others): `server_id`, `old_kid`, `new_jwk`, `iat`.

**Verification:** the payload segments are byte-identical; `old_kid` equals the statement `kid` and the server's registered key, which is `active`; the statement verifies with the old key; `new_jwk` is a valid key different from the old one; the `pop` `kid` is its key ID and the `pop` verifies with it. The request carrying the rotation is itself a request proof made with the old key. On success the old key is retired and the statement is kept as the rotation record.

The agent keeps the new key as pending until the server confirms, and uses the pending key's creation time as `iat`, so a retry produces the identical rotation.

## 7. Key set

The keys the agent trusts for SeaWise signatures are published as a key set signed by an offline root key. The agent pins two root public keys, a primary and a backup kept apart; a key set signed by either is valid.

**Header:** `{"alg":"EdDSA","typ":"sw-keyset+jwt","kid":<root key ID>}`.

**Claims** (all required, no others): `version` (integer from 1), `iat`, `keys` (1 to 256 entries).

**Key entry** members: `kid`, `role`, `x`, `status`, and `name` for edges.
- `kid` MUST equal the key ID of `x`; key IDs are unique within the set.
- `role` is one of `control` (instructions and signed time), `snapshot`, `visitor`, `edge`, `release`.
- `status` is `active`, `next` (announced ahead of use) or `revoked`.
- `name` is required for `edge` keys and not allowed for others: 1 to 63 characters of lower-case letters, digits and `-`, not starting or ending with `-`.

**Verification:** the header `kid` is a pinned root (`unknown_key`); the signature verifies; `version` is not lower than the last accepted version, and an equal version has an identical payload (`rollback`). The key set does not expire: update freshness is provided separately, and a running agent keeps its last key set through outages.

**Key lookup.** A token signed with a key from the set is accepted only if the key ID is in the set (`unknown_key`), its role matches the format (`wrong_key_role`), and its status is `active` or `next` (`key_revoked`).

## 8. Instructions

SeaWise asks the agent to do something it cannot undo (unpair, delete or disable an app, change visitor-token enforcement) only through a signed instruction. The agent never infers deletion from absence.

**Header:** `{"alg":"EdDSA","typ":"sw-instr+jwt","kid":<control key ID>}`.

**Claims** (all required, no others): `ins_id`, `server_id`, `op`, `args`, `iat`, `exp`, with `exp - iat` greater than 0 and at most 3600.

| `op` | `args` |
|---|---|
| `unpair` | `{}` |
| `delete_app` | `{"local_id": <1-64 characters>}` |
| `disable_app` | `{"local_id": <1-64 characters>}` |
| `set_visitor_enforcement` | `{"mode": "observe" \| "enforce"}` |

**Verification:** key lookup with role `control`; signature; `server_id` is this agent's (`wrong_server`); `iat` not more than 300 seconds ahead (`not_yet_valid`) and `exp` not more than 300 seconds behind (`expired`) the agent's corrected clock (§9); `ins_id` not already executed (`replayed`).

**Repetition.** The agent acts on an instruction only after it holds two valid copies with the same `ins_id`, `op` and `args` whose `iat` values are at least 600 seconds apart. It remembers executed `ins_id` values and ignores later copies.

## 9. Signed time

Many small devices have no real-time clock. The agent corrects its clock only from time signed by a control key, never from the edge or from TLS.

The agent sends a fresh `nonce` (an identifier as in §1) with each heartbeat. The response carries:

**Header:** `{"alg":"EdDSA","typ":"sw-time+jwt","kid":<control key ID>}`.

**Claims** (all required, no others): `server_id`, `time`, `nonce`.

**Verification:** key lookup with role `control`; signature; `server_id` is this agent's (`wrong_server`); `nonce` equals the one sent (`nonce_mismatch`). The agent applies the time only if the response arrived within 30 seconds of the request (by its monotonic clock), and never lowers its persisted time floor.

## 10. Error codes

Verifiers report the first failing rule with one of these codes. The vectors assert them.

| Code | Meaning |
|---|---|
| `too_large` | Token exceeds the size limit |
| `malformed` | Segments, base64url, JSON, members or value syntax |
| `bad_alg` | `alg` is not `EdDSA` |
| `bad_typ` | `typ` is not the one for this format |
| `bad_key` | A public key or JWK is invalid (encoding, small order, private member) |
| `bad_signature` | Signature does not verify |
| `unknown_key` | Signing key is not a pinned root, not in the key set, or not the registered device key |
| `key_revoked` | Signing key is revoked or not active |
| `wrong_key_role` | Key set entry has another role |
| `wrong_server` | Token names another server |
| `expired` | Past its lifetime |
| `not_yet_valid` | Issued in the future beyond the leeway |
| `before_key_valid` | frp token issued before the key was registered |
| `replayed` | `jti` or `ins_id` already used |
| `wrong_htm` / `wrong_htu` | Proof does not match the request method or URL |
| `body_mismatch` | Proof does not match the request body |
| `bad_nonce` | Proof nonce is missing, unknown or expired |
| `nonce_mismatch` | Signed time does not echo the agent's nonce |
| `rollback` | Key set older than the one already accepted |

## 11. Test vectors

`testdata/vectors/*.json` hold one file per format. **The keys in them are derived from published seeds and are for tests only.** Each file lists its keys (seed, public key, key ID, fingerprint) and its cases; each case has `name`, `input`, `context` (the verifier's state: request, registry, pinned roots, key set, time, seen identifiers), `expect` (`ok` or an error code) and, for valid cases, `result`. The Go tests regenerate the files and fail if they differ from the committed copies.
