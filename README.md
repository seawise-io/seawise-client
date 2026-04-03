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

Share your local apps with anyone through secure dashboards. Run one Docker container, connect it to your [Seawise.io](https://seawise.io) account, and share access with specific people — no networking required.

Works behind CGNAT, double NAT, and firewalls. No port forwarding, no VPN, no DNS setup.

## Quick Start

```bash
docker run -d --name seawise \
  --restart unless-stopped \
  -p 8082:8082 \
  -v seawise-data:/config \
  ghcr.io/seawise-io/seawise-client:latest
```

Open [http://localhost:8082](http://localhost:8082) to get started.

## How It Works

1. Run the container on your server
2. Set a password to protect the web UI
3. Click **Connect to Seawise.io** — your browser opens the authorization page
4. Approve the connection
5. Add apps by name, host, and port
6. Each app gets a public URL on `seawise.dev`

The client creates an outbound tunnel to Seawise.io. Traffic flows through the tunnel to your local apps. Your network is never exposed directly. Tunnels are powered by [FRP](https://github.com/fatedier/frp) (Fast Reverse Proxy).

## Docker Compose

```yaml
services:
  seawise:
    image: ghcr.io/seawise-io/seawise-client:latest
    container_name: seawise
    restart: unless-stopped
    ports:
      - "8082:8082"
    volumes:
      - seawise-data:/config

volumes:
  seawise-data:
```

## Adding Apps

In the web UI, add an app by entering a name, host, and port:

| Your app runs... | Host to use |
|-----------------|-------------|
| In the same Docker Compose file | Service name (e.g., `grafana`) |
| In a separate container or directly on the server | `host.docker.internal` |
| On another device on your network | Device IP (e.g., `192.168.1.50`) |

## Features

- **One-command install** — single Docker container
- **Web UI** — manage apps, connect servers, set passwords
- **Outbound-only** — no ports to open, no firewall rules
- **Dashboard sharing** — organize apps into dashboards, share by email with per-user access control
- **Works anywhere** — CGNAT, double NAT, IPv6, corporate firewalls
- **Multi-platform** — Linux amd64 and arm64 (Raspberry Pi, NAS devices)
- **Password protection** — required on first run, bcrypt-hashed with rate limiting
- **Auto-reconnect** — exponential backoff, survives network interruptions

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SEAWISE_PORT` | `8082` | Web UI port |
| `SEAWISE_BIND_ADDR` | `127.0.0.1` | Bind address |
| `SEAWISE_DATA_DIR` | `/config` | Persistent data directory |
| `PUID` / `PGID` | `1000` | Run as specific user/group ID |

## Updating

```bash
docker pull ghcr.io/seawise-io/seawise-client:latest
docker stop seawise && docker rm seawise
# Re-run the docker run command above — config is preserved in the volume
```

The client checks for updates automatically and shows a banner when a new version is available.

## Platform Support

- **Linux:** amd64, arm64
- **Docker:** Any host that runs Docker (Linux, macOS, Windows, Unraid, Synology, TrueNAS)
- **Requirements:** Docker 20+, outbound HTTPS (port 443)

## Documentation

- [Getting Started](https://docs.seawise.io/getting-started/quick-start)
- [Apps](https://docs.seawise.io/apps)
- [Dashboards & Sharing](https://docs.seawise.io/dashboards)
- [Security](https://docs.seawise.io/security)

## License

MIT
