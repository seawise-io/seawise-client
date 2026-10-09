# Packaging templates (unpublished)

Starting points for NAS and home-server app stores. None of these are
submitted or published anywhere yet. They all use the client v2 image on
the `:beta` channel (`ghcr.io/seawise-io/seawise-client:beta`) and run it
hardened: read-only root filesystem, all capabilities dropped except the
three the entrypoint needs to switch to `PUID`/`PGID` (`CHOWN`, `SETUID`,
`SETGID`), and `no-new-privileges`.

| Folder | Platform | Format |
|---|---|---|
| `unraid/` | Unraid Community Applications | container template XML |
| `truenas/` | TrueNAS SCALE custom app | Compose YAML |
| `synology/` | Synology Container Manager project | Compose YAML |
| `homeassistant/` | Home Assistant add-on | add-on `config.yaml` stub |

The admin UI is HTTPS on port 8082 with a self-signed certificate. On first
start, read the setup code from `v2/setup-code` in the data folder (or set
`SEAWISE_ADMIN_PASSWORD_FILE`).
