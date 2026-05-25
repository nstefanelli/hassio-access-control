# Changelog

All notable changes to this app are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.6] - 2026-05-25

### Fixed

- **Runtime initialization still failed under the Supervisor proxy**
  with `HA credentials are incomplete in the database` even though
  1.2.5's setup correctly skipped persisting them. `main.py`'s
  `initialize_configured_state` read `ha_url`/`ha_token` from the
  DB and raised *before* it consulted the env-var fallback —
  effectively requiring a DB-stored copy on top of the env vars.
  Env-var resolution now happens first, with the DB used only as a
  fallback (preserving the direct-port path). A clearer error
  message names both lookup paths if neither yields creds.

  **Existing 1.2.5 installs that hit this error:** the prior setup
  wrote everything except the HA creds to the DB and the addon is
  already in `configured` state from the DB side. Updating to
  1.2.6 and restarting the addon completes the runtime init from
  the Supervisor env vars — no need to re-run `/setup`.

## [1.2.5] - 2026-05-25

### Fixed

- **Setup form demanded HA URL + long-lived token even under the
  Supervisor proxy.** `run.sh` exports
  `ACCESS_CONTROL_HA_URL=http://supervisor/core` and
  `ACCESS_CONTROL_HA_TOKEN=$SUPERVISOR_TOKEN` whenever
  `use_supervisor_api: true` (the default), and `main.py` already
  honored those as env-var fallbacks — but the setup form still
  required the user to type a URL + token, then persisted them to
  the DB (shadowing the env vars and breaking after Supervisor
  rotated the token). The `Home Assistant` section is now hidden
  when the Supervisor proxy is active; the POST handler skips the
  user-credential branch, tests the Supervisor URL instead, and
  does not write `ha_url`/`ha_token` to the DB so the env-var
  fallback stays authoritative across token rotations.

## [1.2.4] - 2026-05-25

### Fixed

- **HA admins still rejected after 1.2.3 — root cause: Supervisor
  doesn't send an admin header at all.** The diagnostic logging in
  1.2.3 proved it: current HAOS Supervisor sends `X-Ingress-Path`,
  `X-Hass-Source`, `X-Remote-User-Id`, `X-Remote-User-Name`, and
  `X-Remote-User-Display-Name` — but no `X-Remote-User-Is-Admin`
  and no `X-Hass-Is-Admin`. HA's own addon docs confirm that admin
  gating is delegated to the `panel_admin: true` flag in
  `config.yaml`, which hides the sidebar entry from non-admins.
  The middleware now trusts any well-formed ingress request that
  arrives with a user id. If a future Supervisor version
  reinstates an admin header, an explicit non-admin value still
  rejects the request.

## [1.2.3] - 2026-05-25

### Fixed

- **HA admins were rejected by the SSO middleware with "Admin access
  required".** The ingress middleware only treated the literal string
  `"true"` as admin and only read `X-Remote-User-*` headers — but HA
  Supervisor has shipped both `"1"`/`"0"` and `"true"`/`"false"` for
  the admin flag across versions, and Core ingress uses `X-Hass-*`
  header names rather than `X-Remote-User-*`. The middleware now
  accepts both header schemes and any of `"1"`, `"true"`, `"yes"`
  (case-insensitive). When a request is rejected, it logs the actual
  header set received so future Supervisor header churn is debuggable
  without code spelunking.

## [1.2.2] - 2026-05-25

### Fixed

- **AppArmor profile blocked s6-overlay init.** v1.2.1's profile only
  allowed execution from `/bin/**`, `/sbin/**`, `/usr/bin/**`,
  `/usr/sbin/**`, and `/usr/lib/**`. The HA base image's container
  entrypoint is `/init` (s6-overlay), so AppArmor denied execve and
  the container died at startup with
  `/bin/sh: can't open '/init': Permission denied` looping forever.
  Profile now uses `file,` (matching every official HA addon) while
  retaining the inet-only network restriction.

## [1.2.1] - 2026-05-25

### Fixed

- **CI: container image was never actually published.** Two bugs in
  `.github/workflows/ci.yaml` combined to make every v1.x install
  fail with `403 denied` from `ghcr.io`:
  1. The HA builder received both `--image "ghcr.io/..."` and
     `--docker-hub ghcr.io`, producing a doubled
     `ghcr.io/ghcr.io/nstefanelli/...` push target that GHCR
     silently rejected.
  2. The image name was templated from `slug` (`access_control`,
     underscore) while `config.yaml`'s `image:` field uses
     `hassio-access-control-{arch}` (hyphens) — so even a
     successful push would have landed at a name Supervisor
     never tries to pull.
  Both build steps now derive `--image` and `--docker-hub` by
  parsing `config.yaml`'s `image:` field, making it the single
  source of truth.

## [1.2.0] - 2026-05-24

A consolidation release covering the post-v1.1.0 hardening work: a full
security audit closed 22 dependency CVEs and two Medium-severity code
issues; a codebase-wide quality + security review fixed 19 more
findings (3 Critical, 7 High, 9 Medium); CI gained Bandit + pip-audit
gates; the in-app UI got several SSO-aware refinements.

### Security

- **CRITICAL**: `/setup` POST now hard-refuses (HTTP 404) once
  first-run is complete. Previously, anyone able to reach the
  dashboard URL could re-submit `/setup` and overwrite admin
  credentials + rotate the encryption salt, orphaning every
  previously-encrypted UNVR/HA token and visitor PIN. Under HA Ingress
  this was reachable by any HA admin via the new SSO auto-admin flow;
  under direct-port deployments by anyone on the LAN.
- **CRITICAL**: `/setup` POST is now rate-limited (3 attempts /
  5 min per IP, 5 min lockout). Closes brute-forcing UNVR or HA
  credentials by repeated setup submissions.
- **CSRF middleware now trusts SSO identity.** Before this release,
  the middleware looked only at the session cookie — under HA Ingress
  (where there is no cookie) it was effectively a no-op, leaving
  per-route `Depends(require_csrf)` as the sole defense. Now binds to
  the same `ha:<X-Remote-User-Name>` identity that `require_login`
  returns.
- **CSRF middleware caps body at 1 MiB** and rejects chunked
  Transfer-Encoding without a `Content-Length` header. Previously,
  `await request.body()` would buffer an arbitrarily-large POST,
  enabling OOM via an authenticated session.
- **WebSocket 401 storm protection.** Both `access_client` and
  `protect_client` now count consecutive WS-upgrade 401s; after 5 in
  a row, `_auth_permanently_failed` is set and reconnect stops.
  Closes a credential-replay storm against a stuck (or
  attacker-echoing) WS endpoint.
- **`/api/health` now enforces an explicit API-key scope guard.**
  Previously implicit "any valid key" — including narrow `locks_only`
  keys — could read connection state, user count, and lock count.
- **`uvicorn --forwarded-allow-ips`** locked to `127.0.0.1` +
  Supervisor's `hassio` bridge IP. Was previously `*`, which let
  X-Forwarded-For spoofing evade the login (5/5 min) and API (10/5
  min) rate-limit lockouts in direct-port deployments.
- **Sanitized upstream error surfaces** — UniFi Access, UniFi Protect,
  and Home Assistant connection failures no longer echo raw exception
  strings to the Settings page. Full text is logged at warning level
  for diagnostics.
- **TLS-validation trade-off documented inline** on both WebSocket
  clients. UNVR self-signed certs mean cert verification is OFF;
  rationale + mitigations (LAN trust assumption, WS-401 storm cap)
  documented in `access_client.py` / `protect_client.py`.
- **22 dependency CVEs closed** via version bumps:
  - `fastapi` 0.115.0 → 0.136.3 (transitively bumps `starlette` to
    1.1.0, closing PYSEC-2026-161 Host-header path bypass +
    CVE-2024-47874, CVE-2025-54121, CVE-2025-62727)
  - `aiohttp` 3.10.0 → 3.13.4 (6 CVEs)
  - `jinja2` 3.1.4 → 3.1.6 (3 CVEs)
  - `python-multipart` 0.0.9 → 0.0.27 (4 CVEs)
  - `cryptography` 43.0.0 → 46.0.7 (4 CVEs incl. PYSEC-2026-35/36)
  - `uvicorn` 0.30.0 → 0.32.1
  - `pytest` (dev) 8.3.3 → 9.0.3 (CVE-2025-71176)

### Added

- **`docs/API.md`** — full reference for the `/api/*` Bearer-token
  REST surface: scope model, rate limits, all 6 endpoints with
  request/response schemas, error codes, three worked HA REST sensor
  + automation examples, versioning policy.
- **`docs/SECURITY-AUDIT.md`** — formal audit report with methodology,
  findings table, fixes applied, accepted risks, threat model.
- **`docs/REVIEW-PUNCH-LIST-2026-05-24.md`** — items deferred from the
  codebase-wide review, each with documented rationale and a trigger
  to revisit.
- **`docs/social-preview.png`** — repo OpenGraph image.
- **`SECURITY.md` / `CODE_OF_CONDUCT.md` / `CONTRIBUTING.md`** —
  GitHub community-files baseline; SECURITY documents the data-at-
  rest "treat `/data/access_control.db` as keychain" guidance and the
  direct-port first-run setup-race mitigation.
- **GitHub issue forms + PR template** in `.github/`.
- **Dependabot configuration** in `.github/dependabot.yml` — weekly
  updates for GitHub Actions, Docker base image, and Python deps with
  minor+patch grouped.
- **Auto-release workflow** in `.github/workflows/release.yaml` —
  detects version bumps in `config.yaml` on push to main, extracts
  the matching CHANGELOG section, creates the tag + GitHub Release.
- **Bandit + pip-audit gating jobs** in CI. The build matrix won't
  run if either finds an actionable finding.
- **Credential-label Jinja filter** — Activity Log and per-lock
  history render `NFC` / `PIN` / `Remote (UniFi app)` instead of
  `Nfc` / `Pin_code` / `Remote_through_uah`.
- **Repository topic tags + description** for GitHub discoverability.

### Changed

- **Setup wizard hides admin username/password fields under HA SSO.**
  The admin row is auto-created from `X-Remote-User-Name` with a
  random unguessable password (`secrets.token_urlsafe(48)`). Direct-
  port deployments still see the fields.
- **In-app "Restart Service" button hidden under ingress.** Replaced
  with a one-liner pointing to Supervisor's restart control.
  `RESTART_COMMAND=/bin/true` already neutered the button under the
  app, but the UI now reflects that.
- **`auth_engine`'s `can_disarm` override now honors group schedules.**
  Previously a user with an out-of-schedule "can disarm" group still
  bypassed an alarm-armed block from a separate blocking group.
- **Circuit breaker now reserves the HALF_OPEN probe slot.** Two
  concurrent callers can no longer both probe simultaneously. The
  follow-up fix in this release also catches `asyncio.TimeoutError`
  alongside `aiohttp.ClientError` so the new slot never gets stuck.
- **Timestamp format consistency in SQLite.** New `_utc_now_sqlite()`
  helper produces space-separated `YYYY-MM-DD HH:MM:SS` matching the
  schema-default `datetime('now')`. Previously Python writes used
  `T`-separated ISO format, breaking lexical range queries in
  `prune_logs` and the `since` filter.
- **README** rewritten for public consumption with 12 in-place
  screenshots, use cases, full settings reference, architecture
  diagram, security model, build-from-source.
- **All user-facing docs** swept to the current HA terminology
  ("app" instead of "add-on", "Settings → Apps" UI navigation).
  Schema field names (`hassio_*`) kept unchanged for back-compat.
- **`mark_deleted_users([])`** now logs a warning and returns 0
  instead of mass-marking every local user as `deleted_upstream`.
  Closes an operational footgun where a UniFi sync returning an empty
  list would silently delete every user.
- **Input validation:** date / time strings (`add_visitor`,
  `extend_visitor`, `create_group`, `update_group`,
  `update_schedule`) now reject malformed input with a friendly error
  redirect instead of a 500. `set_group_locks` drops non-integer
  values with a logged warning.

### Fixed

- **`protect_client.py`** runtime `NameError` on every Protect 401
  (the sanitized "rejected the credentials" branch used `logger`
  where the module defines `_LOGGER`).
- **License badge** in the top-level README — was using shields.io's
  dynamic-fetch endpoint which cached "repo not found" from when the
  repo was private. Now a static `License: MIT` badge.
- **Removed unused imports**: `auth_engine.HAClientError`,
  `main.FormData`.
- **Mypy-flagged type mismatches:** `delay` / `max_delay` now
  correctly annotated as `float` in both WebSocket reconnect loops.

### Internal

- Repo flipped public; Private Vulnerability Reporting enabled.
- Custom OpenGraph social preview image uploaded.
- 6 Bandit B608 false positives in `database.py` suppressed inline
  with documented rationale (every flagged f-string assembles
  fragments from hardcoded literals or `?`-placeholder strings;
  values bound via aiosqlite parameter lists).
- **3 new regression tests** locked in for the security-critical
  fixes: setup-re-execution refusal, circuit-breaker concurrent-probe
  blocking, circuit-breaker probe slot release on failure.

### Migration notes

- No DB schema migration required.
- API-key scopes are unchanged. Holders of `read_only` /
  `locks_only` keys retain their access — `/api/health` is in their
  scope set (per the new explicit guard).
- The setup wizard's behavior change (hiding admin fields under SSO)
  is forward-only; existing admin rows are untouched.

## [1.1.0] - 2026-05-23

### Added
- **Home Assistant Ingress** — the app now appears as an admin-only
  sidebar entry in HA and is accessed through the Supervisor's ingress
  proxy. The "Open Web UI" button on the app page also routes through
  ingress.
- **SSO via HA auth** (`auth_api: true`) — HA admins are logged in
  automatically; no separate username/password to manage. Non-admin HA
  users hitting the ingress URL directly get a 403 with a clear
  "admin-only" message.
- **`<base href>`-based URL prefixing** in templates plus
  `window.__INGRESS_PREFIX__` for JS — all in-app URLs resolve correctly
  whether accessed via ingress or directly during local development.
- **Cookie Path scoping** — session cookies are scoped to the per-session
  ingress URL prefix so they don't leak across apps or to HA pages.
- **Header-injection defense** — `X-Remote-User-*` headers are only
  trusted when accompanied by a Supervisor-signed, strictly-validated
  `X-Ingress-Path`. Other apps on the same Docker bridge can't forge
  admin status.
- New `ingress.py` module with isolated middleware and 10 dedicated unit
  tests covering admin/non-admin/missing-header/forged-header paths.

### Changed
- **Breaking — access pattern.** The direct `http://<ha-host>:8080`
  endpoint is no longer exposed. All access goes through the HA sidebar
  or the app's "Open Web UI" button (which uses ingress). Existing
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
  them with the HA sidebar entry or the app page's "Open Web UI"
  button.

## [1.0.0] - 2026-05-23

Initial public release. Forked from an internal homelab deployment.

### Added
- Home Assistant App packaging (Supervisor-managed Docker container)
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
- Persistent re-lock manager (survives app restart; rehydrates on HA
  reconnect)
- Cross-path event dedup (Protect fast-path vs Access standard-path)
- Visitor / guest API integration with PIN management
- API key auth (full / read-only / locks-only scopes), CSRF, rate
  limiting, session timeout
- Web dashboard (HTMX + Tailwind CDN, mobile-first)
- Supervised background loops: HA health, Protect cold-start, topology
  resync, WS zombie watchdog, log retention, scheduled reboot
