# Packaging templates (unpublished)

Starting points for Docker and for NAS and home-server app stores. None of
these are submitted or published anywhere yet. They all use the client v2
image on the `:beta` channel (`ghcr.io/seawise-io/seawise-client:beta`).
v2 is published only as `:2.x.y`, `:2`, `:beta` and `:stable` (a signed
promotion of a `:2.x.y` release); `:latest` stays on v1.

| Folder | Platform | Format |
|---|---|---|
| `compose/` | Docker Compose | Compose YAML, starts as a user |
| `unraid/` | Unraid Community Applications | container template XML |
| `truenas/` | TrueNAS SCALE custom app | Compose YAML |
| `synology/` | Synology Container Manager project | Compose YAML |
| `homeassistant/` | Home Assistant add-on | add-on `config.yaml` stub |

## Hardening

Every template except the Home Assistant stub runs with a read-only root
filesystem, all capabilities dropped and `no-new-privileges`. All state
lives in the data folder (`/config`).

Started as a user (`--user`, `user:`), the container needs no capabilities:

```
mkdir -p config && sudo chown 1000:1000 config
docker run -d --name seawise --restart unless-stopped \
  --user 1000:1000 --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD/config:/config" -p 127.0.0.1:8082:8082 \
  ghcr.io/seawise-io/seawise-client:beta
```

Started as root with `PUID`/`PGID` (the NAS templates, and installs
upgraded from v1), the entrypoint hands root-owned files in the data folder
to `PUID:PGID` and then runs the agent as that user, so it needs `CHOWN`,
`SETUID` and `SETGID` and nothing else. Existing IDs such as GID 100
(`users`) are fine. The agent never runs with user or group 0: `PUID=0`,
`PGID=0`, IDs out of range and `--user` with group 0 are refused, and the
agent always runs with `no_new_privs`.

The data folder must be `/config` or `/data` (or a folder inside them), and
it must be empty or already hold SeaWise client data; any other folder is
refused rather than handed over, so mapping a parent folder such as
`/mnt/user/appdata` by mistake changes nothing. Mounts inside the data
folder are left alone.

- The compose template and the example above publish the admin UI on
  127.0.0.1 only. Docker inserts its own firewall rules for published
  ports, so `-p 8082:8082` (all interfaces) is reachable from the network
  even when a host firewall such as ufw blocks the port. Publish on a LAN
  address only if you mean to, and keep the UI off the internet.
- Keep the default bridge network. With host networking the admin UI
  listens on every host interface and the agent can reach services bound to
  the host's loopback.
- The templates hold no secrets. To set the admin password up front, mount
  a file and point `SEAWISE_ADMIN_PASSWORD_FILE` at it rather than putting
  the password in the environment.

The admin UI is HTTPS on port 8082 with a self-signed certificate. On first
start, read the setup code from `v2/setup-code` in the data folder (or set
`SEAWISE_ADMIN_PASSWORD_FILE`).

## Tests

```
make test-packaging
```

builds the agent image and runs it the way each template does (no
network), checking the settings above, health, the agent's user, groups and
capabilities, the read-only root, the handover of root-owned files, and that
every way of running the agent as root is refused.
