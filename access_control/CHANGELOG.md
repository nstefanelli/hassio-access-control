# Changelog

All notable changes to this app are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.2] - 2026-07-12

### Fixed (security / physical-access correctness)

Three door-safety defects from an end-to-end review, each with a
regression test that fails on the pre-fix code:

- **Schedules now evaluate in the site's timezone.** All rule and group
  schedule checks ran in a hardcoded `America/New_York`, so "cleaner,
  Mon–Fri 9–5" meant Eastern time everywhere — a Los Angeles install
  actually granted 06:00–14:00 local (and denied 14:00–17:00). The
  auth engine now uses Home Assistant's configured `time_zone`
  (fetched at startup and refreshed on HA recovery), falling back to
  the `TZ` env var / container-local time until HA is reachable. The
  scheduled-reboot hour follows the same zone.
- **Remote-unlock auto-relock now covers entry-device-paired locks.**
  The `remote_through_uah` relock path resolved locks with the bare
  DB location-column lookup, missing locks paired via Entry Devices —
  the only pairing method the UI offers. Result: "Auto re-lock on
  remote unlock" silently never fired and the door stayed unlocked
  indefinitely. The path now resolves through the auth engine's
  canonical `get_locks_for_location()` (entry devices included).
- **Protect NFC/fingerprint events are deduplicated and flood-gated.**
  A single tap on a G6 doorbell arrives via BOTH the Protect WS and
  the Access WS log path; the Protect nfc/fingerprint branch bypassed
  the 10s dedup window and the event semaphore entirely, so one tap
  unlocked — and auto-disarmed the alarm — twice. The branch now
  records the camera's mapped door location in the shared dedup
  window (falling back to camera id) and runs under the same
  semaphore as every other event path.

### Tests / harness

- 6 new regression tests: schedule-timezone behavior (day boundary
  across zones + invalid-zone rejection) and lifespan-driven WS
  dispatch tests (Protect redelivery dedup, cross-path dedup against
  the Access WS, camera-id fallback, remote-relock entry-device
  resolution).

## [1.4.1] - 2026-07-06

### Changed (CI only — no runtime/app changes)

- **Migrated CI off the deprecated monolithic `home-assistant/builder`
  action** to the composable
  `home-assistant/builder/actions/build-image` action (2026.06.0). The
  legacy action's container image is no longer published, which broke
  builds with `manifest unknown` (Dependabot PR #32). Per-arch images are
  still published separately as
  `ghcr.io/nstefanelli/hassio-access-control-amd64` and `-aarch64` with
  the same version + `latest` tags, so Supervisor pulls are unaffected.
- aarch64 images now build natively on GitHub's `ubuntu-24.04-arm`
  runners instead of under QEMU emulation.
- All third-party GitHub Actions in CI and Release workflows are now
  pinned to full commit SHAs (Dependabot keeps them current);
  `actions/checkout` bumped v6 → v7.
- Behaviour note: pushes to `main` now rebuild and re-push the current
  version tag and move `latest` on every build (the legacy
  `--docker-hub-check` skip-if-already-published behaviour is gone).
  Pull requests build both architectures without pushing.

## [1.4.0] - 2026-07-05

### Fixed (security / physical-access correctness)

From a full end-to-end review. Three door-safety defects, each with a
regression test that fails on the pre-fix code:

- **Auto-relock is now retried while HA stays connected.** A relock that
  exhausted its two retries (e.g. the lock entity was momentarily
  `unavailable` — a routine Z-Wave/Zigbee hiccup) previously left its
  `pending_relocks` row to be retried only on the next HA
  disconnected→connected transition or restart. If HA never dropped, the
  door stayed physically unlocked indefinitely with only an ERROR log. The
  HA health loop now calls `RelockManager.sweep_overdue()` every tick while
  connected, retrying any past-due row that has no live task, and an
  `access_control_relock_failed` HA event is fired when a relock first
  exhausts its retries so automations can alert.
- **Alarm-armed access block now covers `armed_night`, `arming`, and
  `pending`.** `_get_alarm_state()` ranks these as armed, but the block gate
  only recognised `triggered`/`armed_away`/`armed_home`/`unknown`, so a
  user flagged blocked-when-armed could enter during night-arm or the
  exit/entry-delay windows (and auto-disarm on a single tap). The gate now
  fires for any non-disarmed state, and auto-disarm reuses the same guarded
  `can_disarm` predicate rather than a bare `any(can_disarm)` — a group
  that is blocked for the current state can no longer trigger a disarm.
- **Lockdown mode now persists across restarts.** Lockdown was in-memory
  only; a scheduled reboot, Supervisor watchdog, or HAOS update silently
  cleared it mid-incident. It is now written to the `config` table via
  `AuthEngine.set_lockdown()` and restored on startup via
  `load_persisted_lockdown()`.

### Fixed (resilience)

- **Supervisor token rotation no longer wedges the HA client.** `HAClient`
  captured the token at construction; when Supervisor rotated
  `SUPERVISOR_TOKEN`, every lock/unlock 401'd until an add-on restart (the
  circuit breaker treats 401 as "HA responded", so it never opened). The
  token is now resolved env-first on every request.
- **Request timeouts on all UniFi REST calls.** `access_client` and
  `protect_client` set no `aiohttp` timeout, so a half-open socket to the
  UNVR could hang `login()`/`_request()` indefinitely — and because
  `login()` holds `_login_lock`, one hung call stalled every door event.
  All REST calls now use a 15s total timeout; `login()` clears half-set
  auth state on timeout so the next call re-authenticates cleanly. The
  WebSocket keeps its existing `heartbeat` + backoff for liveness.
- **`protect_client.get_cameras` guards against a non-list response** —
  an error object or `{"data": [...]}` wrapper no longer crashes the loop.

### Tests / harness

- 14 new regression tests (auth-engine restrictive alarm states + lockdown
  persistence; relock overdue-sweep + failure-event; HA client env-first
  token). Suite: **84 passed, 0 skipped**.
- **Fixed the test harness running against fakes.** A new `conftest.py`
  imports the real dependencies before the stub-injecting unit modules, so
  the suite no longer silently shadows fastapi/aiohttp with mocks and the
  end-to-end `TestClient` tests no longer skip. The CSRF end-to-end test
  now uses an `https` base URL so the `Secure` session cookie round-trips
  (it previously asserted a code path it never reached).

### Security (dependencies)

- Bumped `aiohttp` 3.13.4 → 3.14.1, `cryptography` 46.0.7 → 48.0.1, and
  `python-multipart` 0.0.27 → 0.0.31 to clear 15 disclosed CVEs
  (`pip-audit --strict` is green again on both requirements files).

## [1.3.1] - 2026-05-26

### Fixed (setup robustness)

Round-2 fixes from the same code-review pass that produced 1.3.0:

- **Setup form ignores user-submitted HA creds under Supervisor proxy.**
  When the Supervisor proxy is active, `setup_post` now refuses to
  persist any `ha_url`/`ha_token` submitted in the form (regardless
  of whether they're empty) — autofill, bookmarklet, or curl
  resubmission can no longer poison the DB with values that would
  shadow the env-var path. Logs a warning if non-empty values were
  submitted.
- **`admin_username` now keys on HA UUID instead of HA username.**
  Usernames are mutable (admin rename, backup restore against a
  different HA instance) and would collide on the existing config
  row. The HA user UUID is stable — fixes the collision case the
  reviewer flagged. Display name still surfaces via
  `request.state.ingress_user["name"]` on every request.
- **Initial API key generated AFTER `init_runtime()` succeeds.**
  Setup previously persisted the hashed API key before runtime
  initialization. If `init_runtime()` failed, the raw key was never
  shown to the user but the hash sat in the DB — orphan key,
  unrecoverable. API key now lands only on the success path; the
  failure path leaves credentials persisted (so the next-boot
  env-var-fallback can recover) but no orphan key.
- **Setup error message branches on `persist_ha_creds`.** Under
  Supervisor proxy, an HA test failure no longer tells the user to
  "check URL and token" they never entered — instead names the
  Supervisor URL, the `homeassistant_api: true` requirement, and
  the `ACCESS_CONTROL_HA_*` env vars.
- **`ingress.py` logs a warning when `X-Remote-User-Id` and
  `X-Hass-User-Id` arrive with different values.** Divergence is a
  strong signal that something upstream is wrong (proxy chain, a
  sibling addon attempting to spoof one half). Defense-in-depth
  visibility — the `X-Ingress-Path` regex is still the real spoof
  barrier.

### Changed

- **`_resolve_ha_creds()` extracted to module level** in `main.py`.
  Previously embedded in `initialize_configured_state`'s body and
  untestable in isolation; now a pure helper with a `decrypt`
  callable parameter for test stubbing. No behavior change in
  production code paths.

### Tests

- 4 new `setup_post` tests: Supervisor install, Supervisor + ignored
  user input, Supervisor HA-failure error message, `init_runtime`
  failure does not generate API key.
- 7 new `_resolve_ha_creds` tests: env-only, db-only, env preferred
  over db, partial-env (URL-only / token-only) falls back to db,
  partial-env + no db raises, neither source raises.
- 2 new ingress tests: whitespace/case admin value pinned to
  accept; conflicting user-id headers warns and uses
  `X-Remote-User-Id`.

## [1.3.0] - 2026-05-26

### Fixed (safety hardening — "fail loud, not silent")

Post-1.2.6 code review surfaced a stack of three soft-fallback paths
that together could let a misconfigured Supervisor env injection
produce an addon that boots, looks healthy in the panel, and silently
does nothing for HA integration. Each layer now fails loud:

- **`_supervisor_proxy_active()` now XOR-checks the env vars.** When
  exactly one of `ACCESS_CONTROL_HA_URL` / `ACCESS_CONTROL_HA_TOKEN`
  is set (broken Supervisor injection, typoed env-export, or a
  workflow that strips one), we log `ERROR` once and return False
  rather than silently treating it as direct-port mode.
- **`initialize_configured_state` requires env vars as a pair.** A
  stale env URL can no longer pair with a DB-stored long-lived token
  (which would 401 every HA call against `http://supervisor/core`).
  Sources are env-only, db-only, or a logged-error fallback to DB on
  partial env injection. The selected source is logged at INFO so
  startup diagnostics are explicit.
- **`app.state.ha_unhealthy` now surfaces the boot-time HA test
  result.** Previously the `test_connection()` failure path only
  emitted a `WARNING` and continued; supervisor loops and health
  endpoints had no flag to react to. Set to `True`/`False`/`None`
  (initial) so downstream code can degrade gracefully.

### Fixed (CI fail-fast)

- **`.github/workflows/ci.yaml`** now refuses to publish on parser
  garbage. `yq '.image'` returns the literal string `"null"` if the
  field is missing, empty input slides through `${IMAGE_FULL##*/}`
  unchanged, and a bare image name (no `/`) duplicates into both
  `--image` and `--docker-hub`. Added explicit guards plus a doubled
  `ghcr.io/ghcr.io/` regression check in the same workflow that
  introduced the 1.2.0 publish-failure bug. The job now errors
  before the builder action runs if config.yaml's `.image` field is
  malformed.

### Security

- **Rolled back `fastapi==0.136.3` → `0.136.1`.** OSV advisory
  [MAL-2026-4750](https://osv.dev/MAL-2026-4750) (published
  2026-05-23, picked up by pip-audit 2026-05-26) reports that
  `fastapi 0.136.3` added an undocumented `fastar>=0.9.0` dependency
  to its `[standard]` extras group — a typosquat / dependency-
  confusion vector against `fastapi`'s installed namespace. We don't
  use `fastapi[standard]` in `requirements.txt`, so the typosquat
  was never actually pulled in, but pip-audit (correctly) flags any
  install of 0.136.3 as the affected release. 0.136.1 still
  transitively pulls starlette 1.1.0 (no regression on
  PYSEC-2026-161). Will revisit once upstream ships a clean
  successor.

### Changed

- `ingress.py` module docstring and reject-log message cleaned up:
  dropped the HAOS-version anchor (the behavior has been stable for
  years and the anchor invited needless re-verification), corrected
  the rejection-log phrasing which previously claimed "or missing"
  for a branch that never sees a missing value.

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
