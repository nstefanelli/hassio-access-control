# nstefanelli's Home Assistant Add-ons

Home Assistant add-on repository.

## Add-ons

### [Access Control](./access_control/)

[![Latest Version](https://img.shields.io/github/v/tag/nstefanelli/hassio-access-control?sort=semver&label=version)](https://github.com/nstefanelli/hassio-access-control/releases)
[![Supports amd64](https://img.shields.io/badge/amd64-yes-green.svg)](./access_control/build.yaml)
[![Supports aarch64](https://img.shields.io/badge/aarch64-yes-green.svg)](./access_control/build.yaml)

Unified access control bridging **UniFi Access + Protect** with
**Home Assistant** locks and alarm panels. Built around the G6 Entry Pro +
HA-controlled smart lock workflow, but works with any UniFi Access
deployment plus any HA `lock.*` and `alarm_control_panel.*` entities.

**Features**

- Dual deduplicated event paths (Protect WebSocket fast-path + Access
  WebSocket standard-path) for instant lock response to face / PIN / NFC /
  fingerprint authentications
- Authorization engine with groups, per-user rules, schedules, and alarm
  gating
- Persistent re-lock manager that survives add-on restarts
- HA REST client wrapped in a circuit breaker
- WebSocket clients with supervised reconnect, jittered backoff, and
  zombie watchdog
- Visitor / guest API integration with PIN management
- API key authentication with three scopes (`full`, `read_only`,
  `locks_only`)
- Web dashboard (HTMX + Tailwind) — mobile-first, auto-refreshing

See [`access_control/README.md`](./access_control/README.md) for installation
and configuration.

## Installation

### Add this repository to Home Assistant

In Home Assistant: **Settings → Add-ons → ⋮ → Repositories**, paste:

```text
https://github.com/nstefanelli/hassio-access-control
```

> If the repository is private, the Supervisor "Add repository" UI will
> not be able to clone it. See **Manual install** in
> [`access_control/README.md`](./access_control/README.md).

### Install an add-on

After adding the repository, the add-on appears in the store. Install,
configure, and start it.

## Development

Each add-on has its own folder containing:

- `config.yaml` — add-on manifest (slug, version, ports, options, schema)
- `Dockerfile` — image build
- `build.yaml` — per-arch base images
- `rootfs/` — files copied into the container filesystem at build time
- `apparmor.txt` — AppArmor profile
- `README.md` / `DOCS.md` / `CHANGELOG.md`

Multi-arch images are built via the
[`home-assistant/builder`](https://github.com/home-assistant/builder)
GitHub Action and published to `ghcr.io`.

## License

MIT — see [LICENSE](./LICENSE).
