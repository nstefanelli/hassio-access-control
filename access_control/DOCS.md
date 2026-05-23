# Access Control — Documentation

Shown to the user in the add-on's **Documentation** tab inside Supervisor.

## First-time setup

After starting the add-on:

1. Click **OPEN WEB UI** on the add-on page.
2. The on-screen setup wizard guides you through:
   - Creating the local admin account (username + password — stored as
     PBKDF2-SHA256, not recoverable)
   - Pointing the app at your UniFi Console
   - (Optional) Adjusting the HA URL / token if you don't want to use the
     Supervisor proxy

## Connecting to UniFi Access

The add-on uses a UniFi local service account that has access to **both**
the Access and Protect applications on your console.

1. In the UniFi Console, go to **Settings → Admins & Users → Add Admin**.
2. Create a local-only user (e.g. `homeassistant`). Grant **Super Admin** on
   both Access and Protect *(Owner is unnecessary; user-create works at
   Super Admin)*.
3. Use those credentials in the add-on's Settings page.

> **Note:** Some user-management actions (delete / disable users) require
> the **Owner** rank that only one admin per console has. The add-on works
> around this with app-level "disable" (removes group memberships +
> disables rules + sets status=disabled).

## Connecting to Home Assistant

By default, the add-on talks to HA through the Supervisor proxy
(`http://supervisor/core`) using a per-restart `SUPERVISOR_TOKEN`. You
don't need to create a long-lived token unless you turn
`use_supervisor_api` off.

The token is granted access to the HA REST API; the add-on uses it to:

- Lock / unlock `lock.*` entities
- Arm / disarm `alarm_control_panel.*` entities
- Read entity state for the in-memory lock-state cache
- Fire events into the HA event bus (custom event name configurable)

## Re-lock behavior

Each lock has three independent re-lock toggles on the Locks page:

- **Buzz button** — manual UI button always does timed unlock+relock
- **Remote relock** — auto-relock after an unlock via the UniFi mobile app
- **Device auth relock** — auto-relock after a successful face / PIN / NFC /
  fingerprint authentication

All three share a single configurable timer. Pending re-locks are
persisted to SQLite and re-armed on add-on restart, so a re-lock scheduled
just before a restart still fires.

## Visitors / guests

The **Visitors** page creates time-windowed visitors via the UniFi Visitor
API. UniFi enforces the start/end times natively; the add-on writes the
PIN (encrypted) so admins can look it up later.

Names get " - Visitor" appended in UniFi so they're easy to identify in
the UniFi UI.

## Groups & schedules

Groups carry the access policy. A user can be in 0..N groups. The auth
engine grants access if **any** active group permits the unlock at the
event time.

Per-group settings:
- `all_locks` vs specific lock assignments
- `can_disarm` — auto-disarm the alarm if it's armed
- `blocked_when_armed_away` / `blocked_when_armed_home`
- `schedule_enabled` + days + start/end time

Per-user-per-lock **individual rules** override groups for the listed lock
(useful for one-off "this user can use this lock only on Tuesdays" cases).

## Health checks & observability

- `GET /health/live` — unauthenticated liveness probe (used by the
  Supervisor watchdog)
- `GET /api/health` — Access / Protect / HA connection state, circuit
  breaker state, last HA error
- `GET /api/debug` — closed-connection counts, seconds since last event
  per client, live vs DB re-lock task divergence

Both authenticated endpoints require an `Authorization: Bearer <key>`
header. Generate keys on the Settings page.

## Backups

`/data/access_control.db` is the sole stateful file. Supervisor backups
include `/data` automatically.

## Troubleshooting

**HA connection fails on startup**: check that
`http://supervisor/core/api/` is reachable inside the container.
The add-on logs the exact failure message and surfaces it on the home
page status badge.

**WebSocket keeps disconnecting**: this is usually a UniFi session
expiry after a UNVR restart. The add-on handles that — its WS clients
log a single "session expired" and reconnect. If you see continuous
401s, double-check the service account credentials.

**Scheduled reboot didn't fire**: check the date on the home page
("Last reboot fire date"). The add-on suppresses a reboot if a door
event arrived in the last 5 minutes (so it can't kick users mid-tap).

## Logs

- Add-on logs (uvicorn + app): visible in the Supervisor add-on log tab
- Access events: visible in the **Activity** page; retained 90 days
- Admin actions: visible on the **Settings** page (audit log)
