<p align="center">
  <a href="https://seawise.io">
    <img src="https://assets.seawise.io/email/seawise-logo-black.png" alt="Seawise.io" width="300">
  </a>
</p>
<p align="center">
  <a href="https://github.com/seawise-io/seawise-client/releases/latest"><img src="https://img.shields.io/github/v/release/seawise-io/seawise-client" alt="Latest Release"></a>
  <a href="https://github.com/seawise-io/seawise-client/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/seawise-io/seawise-client/ci.yml?label=build" alt="Build Status"></a>
  <a href="https://github.com/seawise-io/seawise-client/blob/main/LICENSE"><img src="https://img.shields.io/github/license/seawise-io/seawise-client" alt="License"></a>
  <a href="https://ghcr.io/seawise-io/seawise-client"><img src="https://img.shields.io/badge/ghcr.io-seawise--client-blue" alt="Container Registry"></a>
</p>

# Seawise.io Client

Open the apps running on your machine from any browser, and share them with people through portals. Run one Docker container, connect it to your [Seawise.io](https://seawise.io) account, and pick which apps to make reachable. Nothing for the people you share with to install.

Works behind CGNAT, double NAT and firewalls. No port forwarding, no VPN, no DNS setup.

This README describes client 2.x (`seawise-agent`). Its image is published as `:2`, `:2.x.y`, `:beta` and `:stable`; `:latest` runs 1.x until 2.x is promoted to it. Moving from 1.x keeps your pairing, apps and password.

## Quick Start

```bash
docker run -d --name seawise \
  --restart unless-stopped \
  -p 127.0.0.1:8082:8082 \
  -v seawise-data:/config \
  ghcr.io/seawise-io/seawise-client:2
```

Open [http://localhost:8082](http://localhost:8082). To reach the web UI from other devices, publish the port on a LAN address instead of `127.0.0.1`. Hardened variants (read-only root, no capabilities) and NAS templates are in [`packaging/`](packaging/README.md).

Existing commands keep working: `serve`, `--port`/`-p` and the 1.x environment variables are accepted, and the 1.x templates run 2.x unchanged.

## Setup

1. Set a password for the web UI, 10 to 72 bytes. This has to happen within 5 minutes of the container starting. If the window passes, run `docker restart seawise` and open the page again. A password set under 1.x keeps working, whatever its length.
2. Click **Connect**, enter a name for this server, then type the code shown on the Seawise.io connect page and approve it.
3. Add apps by name, host and port.

Each app gets its own address on `seawise.dev`. Apps are private: only you can open them after signing in, until you add them to a portal and invite people. The settings menu (gear icon) has **Change Password** and **Lock**; **Disconnect** removes this server from your account and keeps your apps on this machine.

## Adding Apps

| Your app runs... | Host to use |
|------------------|-------------|
| In the same Docker Compose file or network | The service name, e.g. `grafana` |
| On the same machine | `host.docker.internal` (add `--add-host=host.docker.internal:host-gateway` on Linux) |
| On the same machine, client started with `--network host` | `localhost` |
| On another device on your network | Its IP, e.g. `192.168.1.50` |

Cloud metadata, link-local, multicast and reserved addresses can't be reached. Apps that reach this machine, a public address, a mail port, a management API or the network gateway are listed under **Apps to review**, for information.

An app deleted on the Seawise.io website stays here turned off, marked **Removed from account**; **Re-enable** publishes it again.

## Docker Compose

```yaml
services:
  seawise:
    image: ghcr.io/seawise-io/seawise-client:2
    container_name: seawise
    restart: unless-stopped
    ports:
      - "127.0.0.1:8082:8082"
    volumes:
      - seawise-data:/config

volumes:
  seawise-data:
```

## Security

- **Outbound only.** The client opens the connection to Seawise.io. Nothing on your network is opened to the internet.
- **This client decides what is reachable.** Apps are added and changed only here. The Seawise.io website and servers can't add apps or change where they point.
- **Verified tunnel and signed instructions.** The client connects only to Seawise.io names, checks TLS, and acts only on instructions signed by Seawise.io.
- **Device key.** Pairing makes a key that never leaves this machine; every call to Seawise.io is signed with it.
- **Protected web UI.** Password required, stored as a bcrypt hash, with a growing delay after failed attempts. The first-run password window closes after 5 minutes.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SEAWISE_PORT` | `8082` | Web UI port. `--port`/`-p` overrides it. |
| `SEAWISE_BIND_ADDR` | `0.0.0.0` in a container, else `127.0.0.1` | Web UI listening address |
| `SEAWISE_DATA_DIR` | `/config` | Persistent data directory |
| `SEAWISE_TLS` | _(unset)_ | `auto` serves the web UI over HTTPS only, with a self-signed certificate. |
| `SEAWISE_TRUST_PROXY` | `false` | `true` behind a reverse proxy: login limits count the address in the last `X-Forwarded-For` entry and `X-Forwarded-Proto: https` is honoured. Set it only when the web UI is reachable through the proxy alone, since anyone else can send these headers to dodge the per-address limits. |
| `SEAWISE_ALLOWED_HOSTS` | _(unset)_ | Comma-separated DNS names allowed to reach the web UI, e.g. `client.mycompany.com` behind an ingress. Not needed for localhost, LAN IPs or `*.local`. |
| `SEAWISE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `PUID` / `PGID` | `1000` | User and group ID to run as when the container starts as root |
| `SEAWISE_HOST_NETWORK` | _(unset)_ | Read by 1.x only; 2.x ignores it. |

More settings are listed in [`cmd/seawise-agent/README.md`](cmd/seawise-agent/README.md#settings).

## Health Checks

| Endpoint | Returns | Use for |
|----------|---------|---------|
| `GET /healthz` | 200 while the web server responds | Liveness. The image's built-in Docker `HEALTHCHECK` uses it. |
| `GET /readyz` | 200 when paired and the tunnel is up, otherwise 503 | Readiness. The body includes `paired`, `tunnel_up` and `version`. |

Both are unauthenticated. With `SEAWISE_TLS=auto`, plain HTTP answers them to the same machine only.

## Updating

```bash
docker pull ghcr.io/seawise-io/seawise-client:2
docker stop seawise && docker rm seawise
# Run the same docker run command again. Pairing, apps and password are kept in the volume.
```

With Compose: `docker compose pull && docker compose up -d`. The client never updates itself; the web UI says when a signed new version is available.

## Platform Support

- **Images:** Linux amd64, arm64 and armv7 (Raspberry Pi, most NAS devices)
- **Hosts:** Linux, macOS and Windows with Docker, Unraid, Synology, TrueNAS
- **Requirements:** Docker 20+, outbound HTTPS (port 443)

## Documentation

- [Quick start](https://docs.seawise.io/getting-started/quick-start)
- [Apps](https://docs.seawise.io/apps)
- [Portals and sharing](https://docs.seawise.io/dashboards)
- [Client configuration](https://docs.seawise.io/client/configuration)
- [Security](https://docs.seawise.io/security)

## License

MIT.
