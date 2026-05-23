# Changelog

All notable changes to this add-on are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-23

Initial public release. Forked from an internal homelab deployment.

### Added
- Home Assistant Add-on packaging (Supervisor-managed Docker container)
- Multi-arch builds for `amd64` and `aarch64` via `home-assistant/builder`
- Watchdog wired to `/health/live`
- Supervisor-proxied Home Assistant API: HA URL + long-lived token are
  auto-configured from `SUPERVISOR_TOKEN` when `use_supervisor_api: true`
- AppArmor profile (defense in depth)
- Persistent SQLite database at `/data/access_control.db`
- Pre-built images published to `ghcr.io`

### Core features (carried from internal version)
- UniFi Access REST API + WebSocket integration (G6 Entry Pro, Hub, older locks)
- UniFi Protect WebSocket integration (doorbell ring + NFC + fingerprint)
- Home Assistant REST client with circuit breaker (3 failures → OPEN, 60s probe)
- Authorization engine: groups, schedules, alarm gating, per-lock individual rules
- Persistent re-lock manager (survives add-on restart; rehydrates on HA reconnect)
- Cross-path event dedup (Protect fast-path vs Access standard-path)
- Visitor / guest API integration with PIN management
- API key auth (full / read-only / locks-only scopes), CSRF, rate limiting, session timeout
- Web dashboard (HTMX + Tailwind CDN, mobile-first)
- Supervised background loops: HA health, Protect cold-start, topology resync,
  WS zombie watchdog, log retention, scheduled reboot

### Known limitations
- HA Sidebar / Ingress integration is not yet implemented — use the
  "OPEN WEB UI" button from the add-on page or visit
  `http://<ha-host>:8080`
- Private GitHub repos cannot be installed via the Supervisor "Add repository"
  UI; manual install via `/addons/` on HAOS is required until the repo is
  made public
- Migration from a standalone VM install is not automated (export `.db` and
  drop it in `/data/` if needed — schema is compatible)
