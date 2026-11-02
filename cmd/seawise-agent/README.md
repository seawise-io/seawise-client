# seawise-agent (in development)

`seawise-agent` is the next version of the SeaWise client. The `:latest`
and `:1.x` images run `seawise serve`; `seawise-agent` has its own image,
published only under `:2`, `:2.x.y`, `:beta` and `:stable` (see
[Container image](#container-image)). Everything below applies only to
`seawise-agent`; none of it changes how `seawise serve` behaves.

It reads an existing client's data folder without modifying it and keeps
its own state in `<data folder>/v2`.

## What it enforces

- **Target policy.** Each app reaches its target through a forwarder on
  `127.0.0.1` that the agent owns; the tunnel never connects to the app
  directly. Every connection is checked against the address actually
  dialled, after DNS resolution:
  - cloud metadata, link-local, multicast and reserved addresses are always
    refused, including in IPv6 translation forms;
  - every other address is allowed, as in 1.x: no confirmation is needed on
    this machine for new or existing apps.

  The admin UI lists apps that reach this machine, a public address, a mail
  port, a management API (Docker, Kubernetes, kubelet, etcd) or the network
  gateway, for information. Whether an app is public is set in SeaWise, as
  in 1.x.
- **Admin UI** on the same port as before, over plain HTTP as in 1.x. With
  `SEAWISE_TLS=auto` it is served over HTTPS only, with a self-signed
  certificate whose fingerprint is logged at start; plain HTTP then answers
  only `/healthz` for local health checks.
- **First run.** As in 1.0.12, the admin password can be set in the admin
  UI only within 5 minutes of the client starting. After that, setup stays
  closed until the client is restarted. Anyone who can reach the admin
  port during those 5 minutes can set the password, so set it right after
  the first start. Installs that already have a password are not affected.
  A 1.x password is imported once, on the first start of 2.x; changing the
  old password file after that has no effect.
- **Listening address.** In a container the UI listens on all interfaces.
  Elsewhere it listens on `127.0.0.1` unless `SEAWISE_BIND_ADDR` is set.
- **Kill switch.** "Drop all tunnels" in the admin UI closes every
  forwarder and the tunnel session at once. It is saved, so it stays on
  across restarts until you restore the tunnels.

## Access log

Every connection forwarded to an app is recorded in
`<data folder>/v2/access-*.log`, one JSON line each: time, app, the local
address it came from, the address connected to, bytes in each direction,
duration and result (`ok`, `refused`, `unreachable`, `busy`). No request
data, headers or visitor identity is recorded. Files are readable only by
the client's user, start a new file daily or at 4 MiB, are deleted after
30 days, and are capped at 32 MiB in total. The admin UI shows the log,
newest first.

## Network

- **Tunnel.** The client connects out to `tunnel-us-east.seawise.dev`
  (`SEAWISE_TUNNEL_NAME`) on port 443 over TLS 1.3, and only to a name in
  the SeaWise-signed edge list. If raw TLS is blocked it carries the same
  protocol over an HTTPS WebSocket on 443, and tries raw TLS again from
  time to time. It reconnects on its own with backoff (at most 30 s
  between tries) and after network changes. When SeaWise or the edge says
  an update is required, the service is in maintenance, the device is
  revoked or the account suspended, the tunnel is put on hold, the reason
  is shown in the admin UI, and nothing on this machine is deleted.
- **HTTP proxy.** `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` (or their
  lower-case forms) apply to calls to SeaWise. The tunnel uses
  `HTTPS_PROXY` with `CONNECT` (`http://` or `https://` proxies). Loopback
  addresses and connections to your apps never use a proxy. A proxy that
  inspects TLS must exempt the tunnel name.
- **DNS fallback.** If DNS fails, the client connects to the last address
  the tunnel name resolved to within the past 7 days, still verifying the
  certificate against the name.
- **Memory.** A soft memory limit of 64 MiB applies to the agent unless
  `GOMEMLIMIT` is set. CI checks resident memory idle and under load.

## Update notices

The agent checks once a day whether a newer release is available on its
channel and shows it in the admin UI. It never updates itself; to update,
pull the image it names (by its signed digest, `image@sha256:...`) and
recreate the container.

Release information and the signing key set are verified with
[TUF](https://theupdateframework.io) against a root built into the agent
(at least two of three root keys sign any change to it), with rollback,
freeze and mix-and-match protection, HTTPS only, no redirects, size limits and
timeouts. Verified metadata is kept in `<data folder>/v2/tuf`, and no role
version below the highest one verified is accepted again. If the signed
metadata expires, update notices and signed instructions stop until it can
be refreshed. The key set (`<data folder>/v2/keyset`, signed by one of two
pinned roots, never rolled back) never expires: the last verified one stays
in use through outages of any length, and nothing stored is deleted.
Builds without a production root make no update checks (the status shows
`not_configured`). The repository layout and signing tool are described in
`tools/tuf/README.md`.

## Local connections to the forwarder

Each app's forwarder listens on a random port on `127.0.0.1`. Any program
running on the same machine can connect to it, and reaches the app through
the same target policy, so this exposes nothing beyond what the machine can
already reach. Each forwarder is limited in concurrent connections,
connection lifetime and idle time.

## Container image

`Dockerfile.agent` builds the image for this agent (`make image-agent`).
Images are published only under `:2`, `:2.x.y`, `:beta` and `:stable`
(pre-releases only under `:2.x.y-pre` and `:beta`); `:latest` and `:1.x`
stay on the current client.

- **Users.** The agent never runs as root. By default the container
  starts as root only to switch to `PUID`/`PGID` (default `1000`), so an
  install moving from the `:latest` image keeps its settings and data
  folder. It switches by number, so IDs that already exist in the image,
  such as GID 100, work as they are. Before switching it sets the data
  folder's owner and hands any root-owned files in it to that user
  (contents are not changed, symlinks are not followed) and warns if any
  remain. Started with `--user`, it runs the agent directly.
- **Recommended: start as the user.** All state is under `/config`, so the
  root filesystem can be read-only, and with `--user` no capabilities are
  needed. The data folder must already be owned by that user:

  ```
  docker run -d --name seawise --restart unless-stopped \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user 1000:1000 -v ./seawise:/config -p 8082:8082 \
    ghcr.io/seawise-io/seawise-client:beta
  ```

  Without `--user`, the entrypoint needs the `CHOWN`, `SETUID` and `SETGID`
  capabilities (`--cap-drop ALL --cap-add CHOWN --cap-add SETUID
  --cap-add SETGID`).
- **Health check.** `GET http://127.0.0.1:8082/healthz` (plain HTTP; with
  `SEAWISE_TLS=auto`, loopback only). If `SEAWISE_BIND_ADDR` is set to an address other than
  `0.0.0.0` or `127.0.0.1`, the image health check cannot reach it.
- **Platforms.** `linux/amd64`, `linux/arm64`, `linux/arm/v7`.

## Settings

| Variable | Meaning |
|---|---|
| `SEAWISE_DATA_DIR` | Data folder (default `/config` in the image, `~/.seawise` elsewhere) |
| `SEAWISE_PORT` | Admin UI port (default `8082`) |
| `SEAWISE_BIND_ADDR` | Admin UI listening address |
| `SEAWISE_ALLOWED_HOSTS` | Extra host names allowed to reach the admin UI |
| `SEAWISE_TLS` | `auto` serves the admin UI over HTTPS only, with a self-signed certificate |
| `SEAWISE_NAT64_PREFIXES` | Extra NAT64 prefixes used on this network, comma separated |
| `SEAWISE_CONTAINER` | `1` treats the process as running in a container |
| `SEAWISE_TUNNEL_NAME` | Tunnel name to dial (default `tunnel-us-east.seawise.dev`); must be in the signed edge list |
| `SEAWISE_UPDATE_CHANNEL` | `stable` (default) or `beta`: which releases update notices follow |
| `SEAWISE_UPDATE_CHECK` | `0` hides release notices; the signed metadata and the signing key set are still fetched |
