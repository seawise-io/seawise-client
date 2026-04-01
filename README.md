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

Expose local apps to the internet through secure outbound tunnels. Run one Docker container, pair it with your [Seawise.io](https://seawise.io) account, and get public URLs for any app on your network.

Works behind CGNAT, double NAT, and firewalls. No port forwarding, no VPN, no DNS setup.

## Features

- **One-command install** — single Docker container, no dependencies
- **Web UI** — manage apps, pair servers, set passwords from the browser
- **CLI** — script and automate with built-in commands
- **Outbound-only** — no ports to open, no firewall rules, no DNS changes
- **Works anywhere** — CGNAT, double NAT, IPv6, corporate firewalls
- **Multi-platform** — Linux amd64 and arm64 (Raspberry Pi, NAS devices)
- **Password protection** — optional, bcrypt-hashed with rate limiting
- **Auto-reconnect** — exponential backoff, survives network interruptions

## Quick Start

```bash
docker run -d --name seawise \
  --restart unless-stopped \
  --network host \
  -v seawise-data:/config \
  ghcr.io/seawise-io/seawise-client:latest
```

Open [http://localhost:8082](http://localhost:8082) to pair your server and start adding apps.

## How It Works

1. Run the container on your server
2. Open the web UI and set a password
3. Click **Pair** — a code appears
4. Go to [seawise.io/connect](https://seawise.io/connect) and enter the code
5. Add apps by name, host, and port (e.g., Jellyfin at `localhost:8096`)
6. Each app gets a public URL like `https://cool-fish-wave-bay.seawise.dev`

The client creates an outbound tunnel to Seawise.io. Traffic flows through the tunnel to your local apps. Your network is never exposed directly.

## Docker Compose

```yaml
services:
  seawise:
    image: ghcr.io/seawise-io/seawise-client:latest
    container_name: seawise
    restart: unless-stopped
    network_mode: host
    volumes:
      - seawise-data:/config

volumes:
  seawise-data:
```

## Adding Apps

In the web UI, add an app by specifying where the client can reach it:

| Your app is... | Host | Port |
|----------------|------|------|
| On this machine | `localhost` | App port |
| On another device on your LAN | Device IP (e.g., `192.168.1.50`) | App port |

Common apps: Jellyfin (8096), Plex (32400), Home Assistant (8123), Nextcloud (8080), Overseerr (5055).

## CLI

The client includes a CLI for scripting and debugging. When the server is running, CLI commands route through it automatically.

```
seawise serve             Start the web UI and tunnel service
seawise pair              Pair with your Seawise.io account
seawise unpair            Disconnect and remove configuration
seawise status            Show connection status and app count
seawise services list     List all apps
seawise services add      Add an app
seawise services remove   Remove an app
seawise password set      Set a password for the web UI
seawise password remove   Remove the password
```

## Password Protection

Password is optional. Set one in the web UI under Settings if you want to restrict access. The client works fully without a password.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SEAWISE_PORT` | `8082` | Web UI port |
| `SEAWISE_API_URL` | `https://api.seawise.io` | API endpoint |
| `SEAWISE_WEB_URL` | `https://seawise.io` | Dashboard URL |
| `SEAWISE_BIND_ADDR` | `127.0.0.1` | Bind address (use `0.0.0.0` for LAN access) |
| `SEAWISE_DATA_DIR` | `/config` | Persistent data directory |
| `PUID` / `PGID` | `1000` | Run as specific user/group ID |

## Updating

```bash
docker pull ghcr.io/seawise-io/seawise-client:latest
docker stop seawise && docker rm seawise
# Re-run the docker run command above — config is preserved in the volume
```

The client checks for updates automatically and shows a notification in the web UI when a new version is available.

## Platform Support

- **Linux:** amd64, arm64
- **Docker:** Any host that runs Docker (Linux, macOS, Windows, Unraid, Synology, TrueNAS)
- **Requirements:** Docker 20+, outbound HTTPS (port 443)

## Documentation

- [Getting Started](https://docs.seawise.io/getting-started/quick-start)
- [App Setup Guides](https://docs.seawise.io/guides) (Plex, Jellyfin, Home Assistant, Nextcloud)
- [Troubleshooting](https://docs.seawise.io/troubleshooting)
- [Security](https://docs.seawise.io/security/overview)

## License

MIT
