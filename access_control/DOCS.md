# Access Control — Documentation

Shown to the user in the app's **Documentation** tab inside Supervisor.

## First-time setup

After starting the app, click **Access Control** in the HA sidebar (you
must be an HA admin) or **Open Web UI** on the app page.

The setup wizard guides you through:

1. **UniFi Console host** + a local service account with **Super Admin**
   on both Access and Protect. See "Connecting to UniFi Access" below.
2. **(Optional)** Home Assistant URL + long-lived token. By default the
   app uses the Supervisor proxy (`use_supervisor_api: true`) and you
   can leave these blank. Only fill them in if you want the app to
   talk to a different HA instance.
3. **(Optional)** Split console: Access and Protect running on different
   UniFi consoles.

After setup, visit **Locks** to wire HA `lock.*` entities to physical
doors / readers.

## Connecting to UniFi Access

The app uses a UniFi local service account that has access to **both**
the Access and Protect applications on your console.

1. In the UniFi Console, open **Settings → Admins & Users → Add Admin**.
2. Create a local-only user (e.g. `homeassistant`). Grant **Super Admin**
   on both Access and Protect. Owner is not required for normal
   operation.
3. Enter those credentials in the app's Settings page.

> **Note:** Some user-management actions (delete / disable users) require
> the **Owner** rank that only one admin per console has. The app works
> around this with app-level "disable" (removes group memberships +
> disables rules + sets status=`disabled`).

## Authentication

The app integrates with HA's authentication via **HA Ingress** and
`auth_api: true`. When you click the sidebar entry:

- You're already authenticated by HA — no second password.
- Your HA admin status is what gates access. Non-admin users hitting the
  ingress URL get 403 with a clear message.
- The legacy in-app login is hidden under SSO.

If you'd like family members to access the dashboard, give them the
**Administrator** role in HA's user settings.

## Re-lock behavior

Each lock has three independent re-lock toggles (Locks page):

- **Buzz button** — manual UI button; always does timed unlock+relock.
- **Remote relock** — auto-relock after an unlock via the UniFi mobile
  app (`remote_through_uah` event).
- **Device-auth relock** — auto-relock after a successful face / PIN /
  NFC / fingerprint authentication.

All three share a single configurable timer. Pending re-locks are
persisted to SQLite and re-armed on app restart — a re-lock scheduled
just before a restart still fires.

## Visitors / guests

The **Visitors** page creates time-windowed visitors via the UniFi
Visitor API. UniFi enforces the start/end times natively; the app writes
the PIN (encrypted) so admins can look it up later.

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

**Individual rules** per user / per lock override groups (useful for
one-off "this user can use this lock only on Tuesdays" cases).

## Health & observability

- `GET /health/live` — unauthenticated liveness probe (Supervisor probe).
- `GET /api/health` — Access / Protect / HA connection state, circuit
  breaker state, last HA error.
- `GET /api/debug` — closed-connection counts, seconds since last event
  per client, live vs DB re-lock task divergence.

Both authenticated endpoints require an `Authorization: Bearer <key>`
header. Generate keys on the Settings page.

## Backups

`/data/access_control.db` is the sole stateful file. Supervisor backups
include `/data` automatically. To make an out-of-band copy:

```bash
# From HAOS
cp /usr/share/hassio/addons/data/<slug>_access_control/access_control.db \
   /backup/access_control-$(date +%F).db
```

## Troubleshooting

**Sidebar entry doesn't appear.** Confirm you're logged in as an HA admin
— `panel_admin: true` hides the sidebar from non-admins. Also reload the
HA frontend (Ctrl+F5) after first install.

**"Admin access required" 403 page.** You're logged into HA as a
non-admin user. Give your HA user the **Administrator** role and
re-load.

**Bookmarks to `http://<ha-host>:8080` stopped working after upgrade.**
The direct port was removed in v1.1.0. Use the HA sidebar or the app
page's "Open Web UI" button instead.

**WebSocket keeps disconnecting.** Usually a UniFi session expiry after a
UNVR restart. The app handles that — its WS clients log a single
"session expired" and reconnect. If you see continuous 401s, double-check
the service-account credentials.

**HA connection fails on startup.** Check that
`http://supervisor/core/api/` is reachable from inside the container.
The app logs the exact failure message and surfaces it on the home page
status badge.

## Logs

- **App logs (uvicorn + app):** Supervisor app log tab.
- **Access events:** in-app **Activity** page; retained 90 days.
- **Admin actions:** in-app **Settings** page (audit log). Sessions
  authenticated via HA SSO show up as `ha:<HA-display-name>` so you can
  tell them apart from any legacy cookie sessions.
