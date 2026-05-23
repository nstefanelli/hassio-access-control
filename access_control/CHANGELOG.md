# Changelog

All notable changes to this add-on are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-05-23

### Added
- **Home Assistant Ingress** — the add-on now appears as an admin-only
  sidebar entry in HA and is accessed through the Supervisor's ingress
  proxy. The "Open Web UI" button on the add-on page also routes through
  ingress.
- **SSO via HA auth** (`auth_api: true`) — HA admins are logged in
  automatically; no separate username/password to manage. Non-admin HA
  users hitting the ingress URL directly get a 403 with a clear
  "admin-only" message.
- **`<base href>`-based URL prefixing** in templates plus
  `window.__INGRESS_PREFIX__` for JS — all in-app URLs resolve correctly
  whether accessed via ingress or directly during local development.
- **Cookie Path scoping** — session cookies are scoped to the per-session
  ingress URL prefix so they don't leak across add-ons or to HA pages.
- **Header-injection defense** — `X-Remote-User-*` headers are only
  trusted when accompanied by a Supervisor-signed, strictly-validated
  `X-Ingress-Path`. Other add-ons on the same Docker bridge can't forge
  admin status.
- New `ingress.py` module with isolated middleware and 10 dedicated unit
  tests covering admin/non-admin/missing-header/forged-header paths.

### Changed
- **Breaking — access pattern.** The direct `http://<ha-host>:8080`
  endpoint is no longer exposed. All access goes through the HA sidebar
  or the add-on's "Open Web UI" button (which uses ingress). Existing
  bookmarks to the direct port will stop working after upgrading from
  v1.0.0.
- `config.yaml`: added `ingress`, `ingress_port`, `auth_api`, `panel_*`
  fields; removed the host-side `ports` mapping and the `watchdog` URL
  (Supervisor's process-death watchdog handles container restart on
  exit; `/health/live` is still available via ingress for in-HA probes).
- `_redirect()` helper now always prefixes absolute Location URLs with
  the active ingress prefix.
- Logout link is hidden from the sidebar under SSO — logging out only
  affects the legacy cookie session, which doesn't apply when accessing
  via ingress.
- Session/CSRF cookies now carry `Path=<ingress-prefix>` instead of `/`.

### Fixed
- A subtle Python regex pitfall caught by the new ingress tests: `$`
  matches before a trailing newline by default, so a header value with
  an injected `\n` could have bypassed the path-format check. The
  regex now uses `\A`/`\Z` anchors.

### Migration notes
- No DB migration is required. The existing `admin_username` row is
  reused; the first SSO request is logged with `actor="ha:<X-Remote-User-Name>"`
  in the audit log so you can tell ingress sessions from any legacy
  cookie sessions.
- If you had set bookmarks to the direct-port URL (`:8080`), replace
  them with the HA sidebar entry or the add-on page's "Open Web UI"
  button.

## [1.0.0] - 2026-05-23

Initial public release. Forked from an internal homelab deployment.

### Added
- Home Assistant Add-on packaging (Supervisor-managed Docker container)
- Multi-arch builds for `amd64` and `aarch64` via
  `home-assistant/builder`
- Pre-built images published to `ghcr.io`
- AppArmor profile (defense in depth)
- Persistent SQLite database at `/data/access_control.db`

### Core features (carried from internal version)
- UniFi Access REST API + WebSocket integration (G6 Entry Pro, Hub, older
  locks)
- UniFi Protect WebSocket integration (doorbell ring + NFC + fingerprint)
- Home Assistant REST client with circuit breaker (3 failures → OPEN,
  60 s probe)
- Authorization engine: groups, schedules, alarm gating, per-lock
  individual rules
- Persistent re-lock manager (survives add-on restart; rehydrates on HA
  reconnect)
- Cross-path event dedup (Protect fast-path vs Access standard-path)
- Visitor / guest API integration with PIN management
- API key auth (full / read-only / locks-only scopes), CSRF, rate
  limiting, session timeout
- Web dashboard (HTMX + Tailwind CDN, mobile-first)
- Supervised background loops: HA health, Protect cold-start, topology
  resync, WS zombie watchdog, log retention, scheduled reboot
