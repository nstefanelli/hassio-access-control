# Home Assistant Add-on: Access Control

[![GitHub Release][release-shield]][releases]
[![License: MIT][license-shield]](LICENSE)
[![Supports amd64][amd64-shield]][arch-list]
[![Supports aarch64][aarch64-shield]][arch-list]

A Home Assistant add-on that bridges **UniFi Access** and **UniFi Protect**
to **Home Assistant** locks and alarm panels. Built around the G6 Entry Pro
+ HA-controlled smart lock workflow, but works with any UniFi Access
deployment plus any HA `lock.*` and `alarm_control_panel.*` entities.

> **Status:** v1.1.0 — first ingress-enabled release. The add-on installs as
> a standard HA add-on and lives in the HA sidebar; admin-only via HA SSO.

---

## Features

- **Dual deduplicated event paths** — Protect WebSocket fast path
  (`doorAccess`) + Access WebSocket standard path (`access.logs.add`) for
  instant lock response to face / PIN / NFC / fingerprint authentications.
  Same physical tap delivered on both paths is collapsed to one action.
- **Authorization engine** — groups, per-user rules, day/time schedules,
  alarm gating (block when armed; auto-disarm on grant), per-lock individual
  rule overrides.
- **Persistent re-lock manager** — buzz/remote-unlock/device-auth relocks
  survive add-on restarts. Past-due deadlines fire immediately on restart;
  future deadlines re-arm for the remaining time.
- **HA Ingress + SSO** — accessed through the HA sidebar; admin status
  comes from HA's own user database. No second password to manage. Cookies
  and CSRF tokens are scoped to the ingress URL so they don't leak across
  the HA host.
- **Supervisor-proxied HA API** — `http://supervisor/core` + the per-run
  `SUPERVISOR_TOKEN`. No long-lived token to create.
- **Circuit-broken HA client** — opens after 3 network failures, probes
  after 60 s, closes on first success. Trips on `aiohttp.ClientError` only,
  not HTTP 4xx/5xx (HA is still reachable).
- **Supervised background loops** — HA health (30 s), Protect cold-start
  (60 s + 240 s backoff), topology resync (15 min), WebSocket zombie
  watchdog (5 min), log retention (24 h), visitor reconciliation (60 s).
  Any crashed loop is automatically restarted.
- **WebSocket reliability** — jittered backoff, login lock to serialize
  concurrent re-auths, zombie-socket watchdog (forces reconnect after 4 h
  of silence on a TCP-open socket).
- **Visitor/guest API integration** — time-windowed visitors with PIN
  codes, native UniFi Visitor API.
- **API key auth** — `Authorization: Bearer` on `/api/*`, three scopes
  (`full`, `read_only`, `locks_only`), keys stored as SHA-256 hashes only.
- **Dashboard** — mobile-first, HTMX-powered, auto-refreshing.

## Installation

### Option 1 — Add this repository to your HA Add-on Store (recommended)

In Home Assistant: **Settings → Add-ons → ⋮ → Repositories** and paste:

```text
https://github.com/nstefanelli/hassio-access-control
```

Then install **Access Control** from the add-on store. After it starts,
look for **Access Control** in the HA sidebar (admin only).

### Option 2 — Manual install

Useful if the repository is still private or you want to track a feature
branch.

```bash
# On HAOS via the Advanced SSH & Web Terminal add-on (Protection Mode off)
cd /addons
git clone https://github.com/nstefanelli/hassio-access-control.git
```

Then **Settings → Add-ons → Add-on Store → ⋮ → Reload**. The add-on
appears under **Local add-ons**.

## First-run configuration

1. Click **Access Control** in the HA sidebar (you must be an HA admin).
2. The setup wizard asks for:
   - **UniFi Console host** + a local service account (Super Admin on both
     Access and Protect; see [DOCS.md](access_control/DOCS.md) for
     specifics).
   - **Home Assistant URL + long-lived token** — *skip* by default; the
     add-on uses the Supervisor proxy automatically. Only fill these in if
     you want the add-on to talk to a different HA instance.
   - Optional split-console: Access and Protect running on different
     consoles.
3. Wire up locks on the **Locks** page (HA lock entities ↔ physical doors
   / readers).
4. Create user groups, schedules, alarm panel mappings on the **Groups**
   and **Settings** pages.

## Add-on options

| Option | Default | Description |
|--------|---------|-------------|
| `log_level` | `info` | One of `trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal` |
| `use_supervisor_api` | `true` | Auto-configure HA URL + token from `SUPERVISOR_TOKEN`. Set to `false` if you want to point the add-on at a different HA instance entirely. |

UniFi credentials and all other settings are entered through the in-app
**Settings** page (encrypted in the SQLite DB on `/data`). They're
intentionally *not* exposed in the add-on options to keep them out of
Supervisor's plaintext configuration.

## Networking

The add-on needs to reach your UniFi Console (UDM / UNVR / etc.) on
TCP/443. Home Assistant is reached via the Supervisor proxy, so no extra
network plumbing is needed for HA. If your UniFi system is on a VLAN that
firewall-blocks the HA host's container network, you'll need to allow that
traffic.

## Persistence

All state lives in `/data/access_control.db` (SQLite + WAL). The volume
survives add-on restarts and updates. Supervisor backups include `/data`
automatically.

## Architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│                          UniFi Console                                │
│  ┌────────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │  Access REST + WS   │  │  Protect WS      │  │  Visitor API     │ │
│  │  access.logs.add    │  │  doorAccess /    │  │  /visitor (CRUD) │ │
│  │  remote_unlock      │  │  ring / NFC      │  │                  │ │
│  └─────────┬──────────┘  └────────┬─────────┘  └────────┬─────────┘ │
└────────────┼─────────────────────┼──────────────────────┼────────────┘
             │                     │                       │
             ▼                     ▼                       ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │             Access Control add-on (FastAPI + HTMX)                │
   │                                                                   │
   │  ┌─────────────────┐  ┌─────────────────┐                        │
   │  │  access_client  │  │ protect_client  │  WS with jittered      │
   │  │  (supervised)   │  │ (supervised)    │  backoff + zombie wd   │
   │  └────────┬────────┘  └────────┬────────┘                        │
   │           └──────────┬──────────┘                                 │
   │                      ▼                                            │
   │          ┌───────────────────────┐  Semaphore(5) — bounds         │
   │          │ _is_duplicate dedup   │◄─  concurrent process_event     │
   │          └──────────┬────────────┘                                │
   │                     ▼                                             │
   │          ┌───────────────────────┐                                │
   │          │   auth_engine         │  user → groups →              │
   │          │                       │  schedule → alarm → lock      │
   │          └──────────┬────────────┘                                │
   │                     ▼                                             │
   │          ┌───────────────────────┐  circuit breaker:              │
   │          │   ha_client           │  CLOSED → OPEN(3) →            │
   │          │                       │  HALF_OPEN(60s) → CLOSED       │
   │          └──────────┬────────────┘                                │
   └─────────────────────┼────────────────────────────────────────────┘
                         │
                         ▼
              ┌────────────────────────┐
              │   Home Assistant        │
              │   lock.* / alarm_*      │
              │   (Supervisor proxy)    │
              └────────────────────────┘
```

## Repository layout

```text
.
├── access_control/                    # The add-on
│   ├── config.yaml                    # HA manifest
│   ├── Dockerfile / build.yaml        # Multi-arch image
│   ├── apparmor.txt                   # Security profile
│   ├── README.md / DOCS.md / CHANGELOG.md
│   └── rootfs/
│       ├── run.sh                     # bashio entrypoint
│       └── opt/access_control/        # FastAPI app + tests
├── .github/workflows/ci.yaml          # Lint + multi-arch build + GHCR publish
├── docs/specs/                        # Design notes
├── repository.yaml                    # Add-on repository manifest
└── README.md                          # ← you are here
```

## Building from source

The add-on image is built and published to GitHub Container Registry by CI
on every push to `main`. To build locally:

```bash
cd access_control
docker build \
  --build-arg BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.12-alpine3.21 \
  --build-arg BUILD_ARCH=amd64 \
  --build-arg BUILD_VERSION=dev \
  -t access-control:dev .
```

Run the tests (~1 second):

```bash
cd access_control/rootfs/opt
python -m venv .venv && .venv/bin/pip install -r access_control/requirements-dev.txt
.venv/bin/pytest access_control/tests -q
```

## Security model

- **HA admin only.** `panel_admin: true` keeps the sidebar entry out of
  non-admins' view; the middleware enforces the same on every request by
  reading `X-Remote-User-Is-Admin` from Supervisor.
- **Header-injection defense.** `X-Remote-User-*` headers are *only*
  trusted when accompanied by a Supervisor-signed `X-Ingress-Path` (strict
  regex match). Other add-ons on the same Docker bridge can't forge their
  way to admin.
- **Cookie scoping.** Session cookies are written with `Path=/api/hassio_ingress/<token>/`
  so they never leak across add-ons or to HA's own pages.
- **Always-on CSRF.** SSO doesn't replace CSRF; cross-site form
  submissions are blocked independently.
- **Per-IP rate limiting** on login (5 / 5 min) and API auth (10 / 5 min).
- **API keys** stored as SHA-256 hashes only — raw value shown once at
  creation.
- **Encrypted credentials** at rest. Fernet symmetric encryption,
  PBKDF2-SHA256 key derivation.
- **AppArmor profile** scoped to TCP inet/inet6 + the add-on's own
  filesystem.

## Contributing

Issues and pull requests welcome. Please:

1. Open an issue first for larger changes.
2. Run `pytest` before submitting.
3. CI runs yamllint, hadolint, shellcheck, pytest, and the multi-arch build
   on every PR.

## License

MIT — see [LICENSE](LICENSE).

## Related

- [HA Add-on developer documentation](https://developers.home-assistant.io/docs/add-ons/)
- [UniFi Access](https://www.ui.com/access)
- [UniFi Protect](https://www.ui.com/cloud-gateways/uxg-fiber)

---

[release-shield]: https://img.shields.io/github/v/release/nstefanelli/hassio-access-control?style=flat-square
[releases]: https://github.com/nstefanelli/hassio-access-control/releases
[license-shield]: https://img.shields.io/github/license/nstefanelli/hassio-access-control?style=flat-square
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg?style=flat-square
[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg?style=flat-square
[arch-list]: access_control/build.yaml
