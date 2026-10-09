# seawise-agent (in development)

`seawise-agent` is the next version of the SeaWise client. It is built from
this repository but is **not** what the published image runs today: the
image still runs `seawise serve`, and moves to `seawise-agent` in a later
release. Everything below applies only to `seawise-agent`; none of it
changes how `seawise serve` behaves.

It reads an existing client's data folder without modifying it and keeps
its own state in `<data folder>/v2`.

## What it enforces

- **Target policy.** Each app reaches its target through a forwarder on
  `127.0.0.1` that the agent owns; the tunnel never connects to the app
  directly. Every connection is checked against the address actually
  dialled, after DNS resolution:
  - cloud metadata, link-local, multicast and reserved addresses are always
    refused, including in IPv6 translation forms;
  - a name that resolves to this machine's loopback is refused unless the
    app's host is itself `localhost` or a loopback address;
  - public addresses, mail ports on public addresses, loopback, management
    API ports (Docker, Kubernetes, kubelet, etcd) and the network gateway
    each need a confirmation on this machine.

  Apps set up before the upgrade keep working without confirmation, except
  on management API ports, and are listed for review in the admin UI.
  New apps not yet confirmed on this machine are not tunnelled.
- **Admin UI over HTTPS** on the same port as before, with a self-signed
  certificate whose fingerprint is logged at start. Plain HTTP redirects to
  HTTPS for 90 days after an upgrade, then shows a notice. `/healthz` stays
  plain HTTP for local health checks.
- **First run.** Setting the first password needs the one-time code in
  `<data folder>/v2/setup-code` (readable only by the client's user; the
  log names the file but never shows the code), or a password supplied with
  `SEAWISE_ADMIN_PASSWORD_FILE`.
- **Listening address.** In a container the UI listens on all interfaces.
  Elsewhere it listens on `127.0.0.1` unless `SEAWISE_BIND_ADDR` is set.

## Local connections to the forwarder

Each app's forwarder listens on a random port on `127.0.0.1`. Any program
running on the same machine can connect to it, and reaches the app through
the same target policy, so this exposes nothing beyond what the machine can
already reach. Each forwarder is limited in concurrent connections,
connection lifetime and idle time.

## Settings

| Variable | Meaning |
|---|---|
| `SEAWISE_DATA_DIR` | Data folder (default `/config` in the image, `~/.seawise` elsewhere) |
| `SEAWISE_PORT` | Admin UI port (default `8082`) |
| `SEAWISE_BIND_ADDR` | Admin UI listening address |
| `SEAWISE_ADMIN_PASSWORD_FILE` | File holding the admin password |
| `SEAWISE_ALLOWED_HOSTS` | Extra host names allowed to reach the admin UI |
| `SEAWISE_ALLOW_PUBLIC_TARGETS` | `1` lets new apps use public addresses (each still needs confirmation) |
| `SEAWISE_NAT64_PREFIXES` | Extra NAT64 prefixes used on this network, comma separated |
| `SEAWISE_CONTAINER` | `1` treats the process as running in a container |
| `SEAWISE_FRPC_PATH`, `SEAWISE_TRUSTED_CA_FILE` | frpc binary and CA bundle |
