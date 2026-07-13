# Access Control operator guide

This page is rendered in Home Assistant's app **Documentation** tab. The
canonical, versioned guide set starts at the
[documentation index](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/README.md).

## First run

1. Start the app and open **Access Control** from the HA sidebar as an
   administrator.
2. Enter the primary UNVR/Protect console and dedicated local account. If
   Access runs elsewhere, fill all three optional separate Access console
   fields. The accounts need the capabilities used by your deployment; use the
   narrowest roles that work.
3. Leave `use_supervisor_api: true` for the standard deployment. Supervisor
   supplies the HA URL/token and the form hides long-lived-token fields.
4. Create a token under **Access → Settings → General → Advanced → API Token**
   with `view:space` and `edit:space`, and enter it during setup or later under
   Settings. It enables the official local API's schedule-aware commands and
   authoritative state readback.
5. Add HA-external locks on **Locks**, associate each with the correct Access
   reader/location or Protect doorbell, and verify manual state reads.
6. Create groups, assign locks and members, then verify schedules/alarm flags
   before testing credential access.

The setup endpoint closes permanently after configuration to prevent a second
caller from taking over or rotating encryption metadata.

## Single and split UniFi consoles

By default the primary console supplies both Access and Protect. For a split
deployment, enter the Protect host in the primary first-run fields and complete
all three optional Access host/user/password fields. Setup tests both targets
before saving. Secret metadata and related credential fields are committed as
one serialized configuration bundle rather than partially.

First setup also persists a hash of a stable Access site identifier. The app
matches that namespace against every stable console/site identifier exposed at
login and falls back to stable Access-building IDs when required by the UniFi
firmware. It verifies the binding before publishing every initial, replacement,
REST-reauthenticated, or WebSocket-reconnected Access session. Settings can
publish new Access credentials/hosts or change which single/split target
supplies Access only when the candidate is the same verified site. A different
Access site requires a fresh initialization so its site-scoped user and door
IDs cannot inherit existing grants. This is not a TLS certificate pin: UniFi
TLS peers remain unverified and require a trusted management network.

## Authentication and HA connection

The standard app uses HA Ingress and is restricted to HA administrators. It
does not expose a host port. State-changing forms use CSRF protection in
addition to SSO.

With `use_supervisor_api: true`, the runtime HA source is
`http://supervisor/core` plus Supervisor's rotating token. Disable that option
only to configure a different HA instance with a long-lived token.

The Access API token is different from this app's own Bearer API keys. It is
sent only to the selected Access host's official local HTTPS API on port
`12445`, is encrypted in SQLite, and is never rendered after saving. A custom
deployment may set `ACCESS_CONTROL_ACCESS_API_TOKEN`; that runtime value takes
precedence over the encrypted database value. If a configured token is
invalid, expired, or under-scoped, the operation fails rather than silently
falling back to the private username/password session path. With no token,
compatibility mode remains available, but private-API rule/state readback is
firmware-dependent and cannot give the same assurance after every `reset`.

## Locks and re-locks

Access Control supports UniFi-native doors and HA `lock.*` entities. For an HA
lock, configure a 1–300 second re-lock duration and independently choose:

- dashboard buzz (timed unlock);
- re-lock after a matching UniFi remote-unlock event;
- re-lock after an authorized face/PIN/NFC/fingerprint event.

For timed unlocks, the new pending re-lock is persisted and armed **before**
the physical HA unlock. A failure or timeout is ambiguous, so the earliest of
the prior and new deadlines remains armed; a sole new intent is never removed.
Pending rows survive restart, retry after HA recovery, and surface
`access_control_relock_failed` when immediate retries fail. Manual overrides
that do not create a new timer similarly preserve the earlier safety timer on
failure. An accepted manual/retry lock service call is not treated as complete
until bounded state reads report exactly `locked`; otherwise the durable timer
remains available for another attempt.

Native Access locks absent from a valid non-empty topology snapshot are marked
upstream-missing and excluded from normal dashboard, authorization, API-count,
and pairing lookups. Their local row and history remain dormant, and the same
location revives them automatically if it returns. An empty or malformed
snapshot cannot mass-retire an existing native-door inventory.

Native dashboard actions have distinct rule semantics:

- **Unlock** applies `keep_unlock` and holds the door open persistently;
- **Lock** applies `lock_now`, terminating the current unlock schedule and any
  temporary unlock instead of misusing `reset` as a lock command;
- **Follow Schedule** applies `reset` and returns control to Access-native
  behavior. If the native schedule is currently active, the confirmed result
  can be unlocked immediately.

Official-API writes require a strict success response and bounded follow-up
rule/relay reads. A transport success alone is not logged as a completed door
state change.

Application unlocks, re-locks, hub commands, and lockdown changes share a
physical-command barrier. Once enabling lockdown completes, an application
unlock that started under the older state cannot issue afterward.

## Optional bidirectional hub sync

For a mapped HA-external lock, **Sync Access hub & door to this lock's state**
reconciles the HA entity and Access door in both directions. An HA-only change
is applied to Access; an Access-only rule/relay change—including activation or
deactivation of an Access unlock schedule—is applied to HA. Newer Access rule
events wake the reconcile immediately, but are hints only: the app performs
authenticated readback before acting. The five-second poll is authoritative
and catches dropped events, firmware without those events, and external drift.

Normal opening uses `keep_unlock`; a normal lock uses `lock_now`. Fail-safe
directions such as lockdown, unreadable state, or an origin conflict use
`keep_lock` so restoring a native schedule cannot reopen the door during the
incident. Outside lockdown, removing the opt-in restores the native Access rule
when sync owns a persistent override or had applied an unlocked baseline; a
normally locked `lock_now` pair simply drops tracking. Explicit **Follow
Schedule** uses `reset`, but is rejected during lockdown. After an incident, an
existing synced pair replaces its app-owned `keep_lock` with confirmed
`lock_now`; it does not use `reset` as proof of a lock.

The last fully confirmed HA/Access observation is persisted so a restart can
distinguish a new change from stale disagreement. On first observation, a
mismatch resolves locked unless authenticated readback proves that an active
Access schedule and the relay are both unlocked. Later, an HA-only change wins
on Access, an Access-only change wins on HA, equal simultaneous changes are
accepted, and opposing/simultaneous or unreadable changes resolve locked.
Every commanded side is read back before convergence is persisted.

For bidirectional sync, the app normally records the persistent override type
and hub/door/location identity before sending `keep_unlock` or `keep_lock`. A
failed write blocks `keep_unlock`; during active lockdown, the app still
attempts the safer `keep_lock`, leaves enforcement unresolved, and retries the
ownership write. After an uncertain restart, either recorded override is first
replaced with confirmed `keep_lock`; once the incident is over and both sides
are confirmed locked, `lock_now` replaces it so future native schedules remain
eligible. An unconfirmed replacement stays queued and observable. On clean
non-lockdown shutdown, owned overrides and applicable unlocked baselines return
to native Access ownership; during lockdown, managed ownership remains
`keep_lock`. Pairing changes close removed hubs before opening replacements. If
independent HA entities resolve to one physical hub, every
involved pairing is locked and suppressed with `reason=shared_hub_conflict`
until the mapping is one-to-one. Backoff and flap damping bound repeated
commands.

Complete bidirectional behavior should be operated with the official Access
API token. Tokenless compatibility mode can parse known private rule shapes,
but some firmware cannot report an unambiguous physical state after returning
to native behavior; that limitation is surfaced as an unconfirmed operation.
This feature makes both HA and Access state part of the physical-door path and
is off by default.

## Groups, alarms, and schedules

An active group grants all or selected locks. An individual rule is a fallback
grant when no group covers that lock; it is not a deny override.

Group alarm flags can block armed-home/armed-away access or permit auto-disarm.
Unknown, mixed, triggered, night-armed, pending, and transitional alarm states
are treated conservatively when armed-state blocks apply.

Schedules use HA's configured timezone and support days-only, time-only,
combined, and overnight windows. Enabled schedules with no restriction or one
missing time bound fail closed. For an overnight window, the after-midnight
portion belongs to the prior selected day.

## Visitors

The Visitors page creates UniFi visitor windows with an optional door, 4–8
digit PIN, and notes. Times use the HA site timezone; daylight-saving gaps and
ambiguous repeated-hour values are rejected. The current UI does not reveal a
submitted PIN later, so retain it securely if the visitor needs it.

## Monitoring

- Dashboard home: connection state, alarms, lockdown, recent activity, locks.
- `GET /health/live`: unauthenticated process liveness only.
- `GET /api/health`: authenticated Access/Protect/HA/component state.
- `GET /api/debug`: full-scope reconnect, event-age, circuit, and pending
  re-lock diagnostics.
- HA events: `access_control_relock_failed` and
  `access_control_hub_sync_failed` are alert-worthy.

API keys are created under Settings and shown once. The API has monitoring,
reporting, diagnostics, confirmed lock/unlock/follow-schedule operations, local
authorization schedule updates, and a full-scope lockdown setter. `locks_only`
keys never auto-disarm alarm panels, and momentary buzz is intentionally absent.
Lockdown requires an explicit desired state, such as
`POST /api/lockdown?enabled=true`, and repeating that request cannot toggle it
off. A startup read error restores lockdown fail-closed. If persistence or
physical hub enforcement is incomplete, the setter returns `503` while the
safer in-memory state remains enabled; `/api/health` exposes unresolved entity
IDs in `lockdown_enforcement_pending`. See the
[API contract](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/API.md).

## Restart and updates

Use Home Assistant's app page for ordinary restarts. Under Ingress, Settings
shows that instruction instead of an in-app manual-restart button. The optional
scheduled restart remains available because it requests restart through
Supervisor; it runs in HA's site timezone and skips when a door event occurred
in the previous five minutes. In direct-host mode, the manual control and its
"Restarting service" reload banner appear only when a restart mechanism is
available; otherwise Settings explains that restart is unavailable. The
watchdog's liveness URL checks only the web process, not upstream health.

Before updating, read the
[changelog](https://github.com/nstefanelli/hassio-access-control/blob/main/access_control/CHANGELOG.md)
and create a verified backup.

## Safe backups

Prefer a Home Assistant full/partial backup that includes Access Control. The
database uses SQLite WAL while running; never `cp` only the live
`access_control.db` file. Outside Supervisor, either stop the app before
copying a closed database or use SQLite's online `.backup` command, then run
`PRAGMA integrity_check` on the copy.

Treat the database and backups as secrets. In environment-key mode, the exact
`ACCESS_CONTROL_SECRET_KEY` is not stored in the database and must be backed up
separately. See the full
[backup and recovery runbook](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/OPERATIONS.md#backup).

## Common problems

**Sidebar missing / 403:** the panel is HA-admin-only. Refresh the frontend and
verify the current HA user has Administrator access.

**HA disconnected:** in default mode, verify Supervisor is healthy and provides
its token. In remote mode, replace the configured long-lived token. A partial
HA environment URL/token pair is invalid.

**Secret key mismatch:** restore the exact environment key used at first setup
with its matching database. A new key cannot decrypt old values. A database-key
installation intentionally ignores a key injected later.

**Access/Protect 401 loop:** re-enter the correct dedicated local credentials,
verify application permissions, and check single/split host assignment.
Repeated WebSocket authentication failures stop rather than replay forever.

**Access API token rejected:** verify TCP `12445` is reachable from the app,
the token is not expired, and it has `view:space` plus `edit:space`. Saving a
token performs read-only doors/rule validation. A configured token error never
falls back to compatibility mode; replace or explicitly clear it. Clearing the
token removes authoritative official-API confirmation, so re-test native Lock,
Unlock, Follow Schedule, and every bidirectionally synced pair.

**Access site identity mismatch:** the proposed host authenticated as a
different Access namespace, or UniFi did not expose enough stable identity data
to verify the persisted binding. Restore the same site/endpoint or reinitialize
deliberately with a fresh database for a different site; do not copy the old
grants into the new namespace. Any TLS certificate fingerprint observed
internally by the client is diagnostic only and is not the site binding.

**Unexpected denial:** inspect the Activity reason, user status, device mapping,
group/individual grant, schedule and HA timezone, all alarm block flags, and
lockdown state. Unknown alarm state and corrupt schedule data fail
conservatively.

**Hub sync not moving:** confirm the lock is visible, HA-external, opted in,
mapped to a location with a native hub, and reports exactly `locked` or
`unlocked`. Confirm the Access API token and port `12445` before relying on
schedule synchronization. Unknown/unavailable state, Access readback failure,
HA loss, or simultaneous disagreement resolves locked instead of being
ignored. Check logs/failure events for
`no_paired_hub`, `shared_hub_conflict`, backoff, or flapping.

For full recovery steps and a bug-report checklist, use the
[operations guide](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/OPERATIONS.md).
