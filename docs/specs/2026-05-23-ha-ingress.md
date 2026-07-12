# HA Ingress integration — design

> **Historical design note.** This proposal targeted v1.1.0 and is preserved
> for design context. The current manifest, middleware, restart/watchdog
> behavior, and security model have evolved. Do not implement or operate from
> this file; use [Configuration](../CONFIGURATION.md),
> [Architecture](../ARCHITECTURE.md), and
> [Security model](../SECURITY-MODEL.md).

**Date:** 2026-05-23
**Target version:** 1.1.0
**Status:** historical — implemented for v1.1.0 and subsequently evolved

## Goal

Make HA Ingress the only access path for the addon. Replace the existing
direct-port + in-app-login model with Supervisor-proxied access + HA SSO.

## Why

- Best-practice for HA addons whose primary UI is a web dashboard
- SSO via HA auth = no second password to manage
- One auth model, not two (today's "ingress + direct port" hybrid forces
  CSRF/cookies to span two scopes)
- Sidebar entry in HA puts the addon where users expect it

## Config (`access_control/config.yaml`)

```yaml
ingress: true
ingress_port: 8080
auth_api: true                       # gives us X-Remote-User-* headers
panel_admin: true                    # admin-only sidebar entry
panel_icon: mdi:door-closed-lock
panel_title: Access Control
# ports: removed entirely
# watchdog: removed (Supervisor's process-death watchdog is sufficient)
```

Everything else (image, arch, homeassistant_api, apparmor, options/schema) unchanged.

## App-side changes

### `IngressMiddleware` (new, in `main.py`)

Runs before session-cookie auth. Per request:

1. Read `X-Ingress-Path`. Validate against regex `^/api/hassio_ingress/[A-Za-z0-9_-]+$`.
   - If invalid or missing → request did NOT come via Supervisor's ingress
     proxy; do NOT trust any `X-Remote-User-*` headers. Fall through.
2. If valid:
   - Set `request.scope["root_path"] = X-Ingress-Path` so Starlette generates correctly-prefixed URLs.
   - Read `X-Remote-User-Is-Admin`. If `!= "true"` → return 403 with a polite "admin-only addon" message.
   - If admin → set `request.state.ingress_user = {id, name}` and `request.state.ingress_active = True`.

### `web_auth.py`

`require_login` dependency: if `request.state.ingress_user` present, return it as the User (bypassing the session-cookie path). Otherwise existing cookie auth.

Cookie setters: set `Path=request.scope["root_path"] or "/"` so cookies don't leak across the HA host when accessed via ingress. Single helper function used by both session and CSRF setters.

### First-boot bootstrap

When the addon first starts and DB has no `admin_username`:
- If an HA-admin SSO request arrives → auto-create the admin record using `X-Remote-User-Name` (no password, marked as `auth_method="sso"`)
- The `/setup` wizard then proceeds to UNVR/HA-creds step
- If no SSO and no admin → legacy `/setup` admin-creation step runs (kept as fallback for non-ingress deployments)

### Templates (audit)

All HTML templates: convert hardcoded `/foo` URLs to either:
- `{{ url_for('endpoint_name') }}` (preferred, type-checked via FastAPI route names)
- Relative path (e.g. `foo` instead of `/foo`)

Categories to fix:
- `<a href="/...">`, `<form action="/...">`
- `<link href="/static/...">`, `<script src="/static/...">`
- `hx-get="/..."`, `hx-post="/..."`, etc.
- Any `<img src="/...">`

`base.html`:
- Add `<base href="{{ root_path }}/">` as safety net
- Add `<script>window.__INGRESS_PREFIX__ = "{{ root_path }}";</script>` for JS fetch
- Wrap logout button in `{% if not ingress_active %}` (hides under SSO)

### Python redirects

All `RedirectResponse("/...")` → `RedirectResponse(request.url_for("endpoint_name"))`. Audit `web_routes.py` and `web_auth.py`.

### Tests (new)

`tests/test_ingress.py`:

1. Valid ingress headers + admin → `request.state.ingress_user` populated, root_path set
2. Valid ingress headers + non-admin → 403
3. Missing X-Ingress-Path → SSO headers ignored, falls through to cookie auth (no exception)
4. Forged X-Ingress-Path (wrong format) → SSO headers ignored
5. X-Ingress-Path present but no SSO headers → root_path set, no auto-login
6. Cookie Path scoping — Set-Cookie includes the ingress prefix when ingress active

## Out of scope

- Per-HA-user role mapping (all HA admins = in-app admin in v1.1.0; can layer roles later)
- WebSocket via ingress (`ingress_stream: true`) — not needed; HTMX polls
- CSP tightening (pre-existing Tailwind/CDN `unsafe-inline` concern, separate workstream)
- VM 107 → addon migration tooling

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| Missed hardcoded `/foo` URL in templates | `<base href>` safety net + grep audit + manual smoke test |
| Cookie Path subtle bug across HA addons | Path = `X-Ingress-Path` explicit; covered by test #6 |
| Ingress token format changes upstream | Regex is permissive; loose match `/api/hassio_ingress/[A-Za-z0-9_-]+$` |
| `auth_api: true` triggers HA permission prompt that surprises users | Documented in CHANGELOG + DOCS.md |
| Watchdog removal hides slow hangs | `/health/live` endpoint kept; users can wire external probe via HA REST sensor |

## Version + migration

- v1.0.0 → v1.1.0 (breaking change in access path)
- CHANGELOG.md: prominent BREAKING note that `http://<ha-host>:8080` no longer works; use HA Sidebar
- No DB migration needed; existing `admin_username` field reused for SSO-created admin
