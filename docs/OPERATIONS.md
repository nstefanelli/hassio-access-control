# Operations

This runbook covers a standard Home Assistant Supervisor deployment. Commands
that use `sqlite3` apply to a standalone host or a maintenance environment with
filesystem access; they are not assumed to exist inside the app image.

## Routine checks

The dashboard home page is the first operational view. It shows Access,
Protect, Home Assistant, and WebSocket connection state, recent activity,
lockdown, alarm state, and lock actions.

For automation and monitoring:

- `GET /health/live` is an unauthenticated process-liveness probe. It returns
  200 while FastAPI can serve requests, even when every upstream is down.
- `GET /api/health` requires any API-key scope and reports Access, Protect, HA,
  circuit-breaker, WebSocket, count, lockdown state, and unresolved hub-safety
  enforcement in `lockdown_enforcement_pending` (the field name is retained
  for API compatibility; enforcement now uses a safe locked override).
  `hub_sync_fail_safe` lists any HA entity IDs whose bidirectionally synced pair
  is currently held by the locked-wins fail-safe latch: while listed, unlocks on
  that lock are reverted until both sides confirm locked, so a persistently
  non-empty entry is a stuck sync that needs attention.
- `GET /api/debug` requires `full` and reports reconnect counters, last-event
  ages, and live-versus-durable pending re-lock counts.

See [REST API](API.md) for the exact fields. Do not interpret
`{"status":"ok"}` alone as proof that a door path is healthy; inspect the
individual connection booleans.

Useful Home Assistant events are:

| Event | Meaning |
|---|---|
| `access_control_granted` | An authorization event unlocked at least one configured lock. |
| `access_control_doorbell_ring` | A mapped Protect doorbell/ring event was received. |
| `access_control_relock_failed` | A durable HA re-lock exhausted its immediate retries. While the re-lock stays overdue it re-fires on a bounded per-lock cadence (roughly every 10 minutes), so a stranded door does not go quiet after one missed event. |
| `access_control_hub_sync_failed` | An optional hub-sync apply/release failed or was suspended for flapping. |

Build alerts around the two failure events and around prolonged degraded health.

Under **Settings → Access API Token**, confirm the status is **Configured** for
deployments that use native schedules or bidirectional hub sync. This token is
an upstream UniFi credential, not one of this app's `/api/*` monitoring keys.

## Logs and retention

- **Process logs:** Home Assistant **Settings → Apps → Access Control → Log**.
- **Access decisions:** dashboard **Activity** page and `GET /api/log`.
- **Administrative actions:** the `admin_log` table; HA SSO actors are recorded
  with an `ha:` prefix.

Access and admin logs are pruned daily to 90 days. Process logs are managed by
the container/Supervisor logging layer and are not stored in the SQLite audit
tables.

Use `debug` temporarily for client, topology, or authorization diagnosis. Do
not post full debug logs publicly without removing console hosts, user names,
entity IDs, tokens, PINs, and other household details.

## Restart behavior

For an ordinary restart, use **Settings → Apps → Access Control → Restart**.
The packaged app can also request its own restart through Supervisor for the
scheduled-restart feature. Supervisor's watchdog uses `/health/live` to recover
an unresponsive process; application-level upstream degradation does not make
that endpoint fail.

When the dashboard is opened through HA Ingress, its Service Control card
shows the Home Assistant app-page instruction instead of a manual restart
button. Scheduled restart is still shown because Supervisor provides the
restart mechanism. In direct-host mode, a manual **Restart Service** control is
shown only when Supervisor restart or an explicit trusted `RESTART_COMMAND` is
available. After that direct control is submitted, the yellow “Restarting
service…” banner polls liveness and reloads when the process returns. If no
mechanism is available, Settings says so and does not offer the control or
schedule.

The optional schedule is evaluated in Home Assistant's configured timezone. It
can run daily or on one weekday at a selected hour. The scheduler:

1. skips while disabled or outside the selected local hour;
2. skips when an Access or Protect event occurred in the previous five minutes;
3. persists the date before requesting restart so a restart within that hour
   does not loop;
4. records an administrative audit entry.

If a recent event causes a skip, the loop retries within the same hour. For a
standalone container without Supervisor integration, `RESTART_COMMAND` is the
trusted deployment fallback.

Hub-rule recovery depends on how the process stopped. On clean non-lockdown
shutdown, owned persistent overrides and applicable unlocked baselines return
to native Access rules; during lockdown, managed ownership remains `keep_lock`.
After an unclean restart, either durable `keep_unlock` or `keep_lock` ownership
is treated as uncertain and first driven to confirmed `keep_lock`. Failed
confirmation remains durable and retries rather than being reported as
converged.

## Updates

Before a significant update:

1. Read the current and target sections of
   [the changelog](../access_control/CHANGELOG.md).
2. Create and verify a backup, including the environment key when applicable.
3. Confirm no maintenance work is holding a door open.
4. Update from Home Assistant's app page.
5. Reopen the dashboard and verify Access, Protect, HA, WebSocket, lock state,
   timezone-sensitive schedules, the Access API-token status, native Lock /
   Unlock / Follow Schedule actions, and any split-console configuration.

Database migrations are applied at startup and are intended to be idempotent.
Rollback still requires a pre-update backup; an older binary is not guaranteed
to understand a newer schema.

First-run and multi-field Settings changes persist related configuration as a
single serialized bundle, and replacement upstream clients are tested before
publication. A failed bundle remains at its prior values rather than leaving a
mixed host/user/password or encryption-key set. This does not replace the need
for a backup before migration or update.

Access replacements are also checked against the persisted Access site
namespace before publication. A hostname or single/split-console change is an
endpoint migration only when the authenticated candidate proves it is the same
site; a different site needs a fresh initialization and policy review.

## Backup

`/data/access_control.db` is the durable application store. It uses SQLite WAL
while the process is running, so a raw copy of only `access_control.db` can omit
committed pages still present in `access_control.db-wal`.

The database and its backups are sensitive. They contain household topology,
audit history, the encrypted Access API token and other credentials/PINs,
and—in database-key mode—the key material needed to decrypt them.

### Preferred: Home Assistant backup

Use Home Assistant's backup UI to create a full backup or a partial backup that
includes Access Control. Supervisor captures the app's `/data` volume as a
coherent unit and restores it with the app.

After creation:

- download or replicate the backup to protected storage;
- keep it encrypted and restrict access;
- periodically test restore into an isolated Home Assistant instance;
- if the installation uses environment-key mode, back up
  `ACCESS_CONTROL_SECRET_KEY` separately. It is intentionally absent from the
  database and may not be included in a Supervisor backup.

### Standalone online backup

When the source database must remain online, use SQLite's backup API rather
than `cp`:

```bash
sqlite3 /path/to/access_control.db \
  ".backup '/secure/backups/access-control-$(date +%F).db'"
```

Then validate the copy:

```bash
sqlite3 /secure/backups/access-control-YYYY-MM-DD.db \
  "PRAGMA integrity_check;"
```

The expected output is `ok`. Protect the resulting file as a secret.

### Offline filesystem backup

If the SQLite backup API is unavailable:

1. Gracefully stop the Access Control app.
2. Confirm the process has exited and no writer has the database open.
3. Copy the closed `access_control.db` to protected storage. If WAL sidecars
   remain because shutdown was not clean, preserve the database, `-wal`, and
   `-shm` files together and recover with SQLite before treating it as a valid
   backup.
4. Restart the app and verify health.

Never take a live `cp` of only the main database file.

## Restore and disaster recovery

Restoring replaces current state. Keep the failed/current database until the
recovery is verified.

1. Stop Access Control.
2. Save the current database and any sidecars under a quarantine name.
3. Validate the backup with `PRAGMA integrity_check` where possible.
4. Restore the backup as `/data/access_control.db` with the ownership and mode
   expected by the app.
5. Remove stale sidecars only while the app is stopped and only when the
   restored backup is a known-consistent standalone database.
6. For environment-key mode, restore the exact matching
   `ACCESS_CONTROL_SECRET_KEY` before startup.
7. Start the app, inspect the log for migrations/decryption errors, and verify
   every upstream connection and a non-destructive state read.
8. Verify group/schedule mappings before testing a physical grant.

If the key and database do not match, do not keep trying different values
against the live store. Preserve both, restore a known pair, or rebuild the
installation and rotate all upstream credentials and visitor PINs.

## Troubleshooting

### The sidebar item is missing or returns 403

- Confirm the app is running and Ingress is enabled in its manifest.
- Refresh the Home Assistant frontend after installation.
- The panel is admin-only. A non-admin HA user receives 403 even with the
  direct Ingress URL.
- Do not bookmark the per-session `/api/hassio_ingress/...` path; open the
  sidebar item or **Open Web UI**.

### Startup says setup is incomplete

Open the dashboard as an HA admin and finish first run. If a previous setup
failed after credentials were saved, restart once and inspect the log before
deleting anything. The presence of `admin_username` closes the setup endpoint
to prevent a second caller from taking over or rotating encryption metadata.

### Startup reports a missing or mismatched secret key

The database was initialized in environment-key mode. Inject the exact original
`ACCESS_CONTROL_SECRET_KEY`. If it is unavailable, restore a matched database
and key backup. Adding a new key cannot decrypt old ciphertext.

If the log says the environment key is being ignored, the database is in the
default database-key mode; remove the late override rather than editing key
metadata.

### Home Assistant is disconnected

- With `use_supervisor_api: true`, confirm Supervisor is healthy and provides
  `SUPERVISOR_TOKEN`. The runtime pair must be
  `http://supervisor/core` plus that token.
- With it disabled, test the configured remote HA URL from the same network and
  replace the long-lived token if revoked.
- A partial HA environment pair is invalid and is never mixed with stored
  credentials.
- Inspect `ha_last_error` and `ha_circuit_state`. After repeated failures the
  circuit opens, then admits a bounded recovery probe.

### Access or Protect repeatedly returns 401

- Re-enter the dedicated local UniFi account under Settings.
- Confirm the account can access the correct application on that console.
- For split deployments, verify the separate Access host did not get replaced
  by the primary Protect host.
- Check console time, account lockout, and recent UniFi updates.
- Repeated WebSocket authentication failures are intentionally stopped rather
  than replayed forever; saving correct credentials or restarting reinitializes
  the client.

### Access API token validation or door confirmation fails

The official Access Open API is local HTTPS on TCP port `12445`, separate from
the console UI/session endpoint.

1. Confirm the selected Access host is reachable from the app on TCP `12445`.
2. In Access, create or replace the token under **Settings → General → Advanced
   → API Token** with `view:space` and `edit:space`.
3. Save it under this app's **Settings → Access API Token**. Saving performs
   read-only doors and rule validation; the first write also proves
   `edit:space`.
4. Re-test a native **Lock**, **Unlock**, and **Follow Schedule** while watching
   the physical door and Activity/log result.

A configured-token error never falls back to the private session API. This is
intentional: silent downgrade could change schedule semantics and turn an
unconfirmed operation into a false success. Explicitly clearing the token
enables compatibility mode, but that is a capability reduction, not a repair.
Some Access firmware cannot expose an unambiguous rule/relay state after
`reset` through the private API, so Follow Schedule or reverse synchronization
may remain unconfirmed without a token. On the official Open API, a door with
no active override reports an empty rule type, which the client normalizes to
`reset`; this is native behavior, and state is always confirmed through relay
readback rather than inferred from the rule. Legacy (private-API) rule parsing
stays strict and does not accept an empty type.

`ACCESS_CONTROL_ACCESS_API_TOKEN`, when non-empty in a custom deployment,
overrides the encrypted database value. If replacing the Settings token appears
to have no effect, inspect the runtime environment without printing the secret.
Never include the token or an upstream error body in a bug report.

### Access reports a site identity mismatch

Access authenticated, but the stable console/site/building identifiers do not
match the namespace enrolled in this database. This is deliberately permanent
for that candidate session: it prevents reused UniFi user/location/device IDs
on a different site from inheriting local grants.

- Verify DNS, IP/hostname, single/split assignment, and that a reverse proxy
  still targets the original Access site.
- A same-site host move is accepted automatically after identity verification.
- If UniFi no longer returns enough stable identity/topology data, restore the
  original endpoint and inspect the app log before changing anything.
- To adopt a genuinely different site, preserve the old database as a secret,
  initialize a fresh data store, and recreate/review mappings and policy. Do not
  edit `access_console_identity` or transplant the old site-scoped rows.

The certificate fingerprint observed internally by the client is not the
identity binding and is not a TLS pin; an on-path impersonator remains an
accepted-network risk.

### Protect is degraded after startup

Protect startup is retried in the background. Verify that Protect runs on the
primary console and that the primary credentials can log in to it. Access can
remain operational through a separately configured Access console while
Protect is unavailable.

### A credential is denied unexpectedly

Check the Activity reason, then verify:

- the UniFi user status is active;
- the reader/camera maps to the intended Access location and lock;
- at least one active group or individual rule grants that lock;
- the enabled schedule has days and/or a complete time range;
- HA's configured timezone is correct;
- alarm state and every group membership's blocking flags;
- lockdown is disabled.

Unknown or mixed alarm state and incomplete schedules fail conservatively.

### A lockdown request returns 503

The desired in-memory incident state remains fail-closed when persistence or
immediate safe hub lock reports an error. Startup also treats an unreadable
persisted lockdown value as enabled. Inspect the process log and
`lockdown_enforcement_pending` from `GET /api/health`; a non-empty list contains
HA entity IDs whose paired hubs are not yet confirmed locked. Restore Access/DB
availability, correct pairing conflicts, and retry the idempotent
`POST /api/lockdown?enabled=true`. Do not clear lockdown merely to hide the
error. A failed `enabled=false` persistence write likewise leaves lockdown on.

### A visitor time is rejected

The form uses the HA site timezone. A local time can be nonexistent during the
spring-forward gap or ambiguous during the fall-back repeated hour; both are
rejected. Pick an unambiguous time. An extension must be after both the original
start and the current time.

### A pending re-lock is stuck

Start with the surfaces built for this: `GET /api/health` reports
`pending_relocks` counts (`total` and `overdue`), the Locks page badges
affected cards with "re-lock pending" or "re-lock overdue", and the
`access_control_relock_failed` event re-fires on a bounded per-lock cadence
(roughly every 10 minutes) while the re-lock stays overdue. For deeper
diagnosis, compare `pending_relocks_live` and `pending_relocks_db` in
`/api/debug` and inspect HA connectivity. A durable row with no live task is
retried on HA recovery and by the overdue sweep. Do not delete the row to
silence the symptom while a door may still be unlocked.

Timed unlock paths persist and arm their new deadline before issuing the HA
unlock. If that call fails or times out, the earliest applicable intent stays
armed because the request may already have executed. Therefore a row after a
failed command can be deliberate fail-safe recovery, not stale data.

An HA lock service response alone does not clear the row. Manual and scheduled
re-locks use bounded follow-up reads and require the entity to report exactly
`locked`; otherwise the operation is recorded as an error and the row remains
for recovery. This verifies HA's observed entity state, not an independent
physical lock sensor.

Remote-unlock scheduling work is treated as critical because the door was
already opened upstream. Shutdown and live-client swaps await that work before
closing Access/HA/SQLite. If timer persistence fails, the app attempts an
immediate lock and emits `access_control_relock_failed` unless `locked` is
observed.

### A native Access lock disappeared

A valid non-empty topology refresh retires native doors that Access no longer
reports. The app preserves their local rows, mappings, and history but excludes
them from normal lists, counts, authorization, and hub-pairing resolution. If
the same location returns, the next refresh revives the row. An empty/malformed
snapshot is rejected while native locks exist; if many doors disappear after a
real site change, investigate the Access site-identity warning rather than
reusing the old policy.

### Hub sync does nothing

- The lock must be an HA-external `lock.*`, visible, and opted in.
- It needs a resolvable Access reader/location or Protect doorbell mapping and
  a native hub at that location.
- For authoritative schedule/reverse behavior, the Access API token must be
  configured, valid, and able to reach port `12445` with `view:space` and
  `edit:space`.
- HA must report exactly `locked` or `unlocked`, and Access must return a known
  rule plus `locked`/`unlocked` relay state. A disconnect, malformed read, or
  disagreement that cannot be attributed resolves locked and never opens.
- A verified active Access schedule can establish an unlocked startup baseline;
  every other fresh mismatch is locked-wins. Later HA-only changes flow to
  Access and Access-only changes flow to HA. Opposing simultaneous changes
  resolve locked.
- Access schedule/temporary-rule events trigger immediate reconciliation, but
  the periodic five-second readback remains authoritative and repairs missed
  events or drift. Check that the Access WebSocket is connected, then wait at
  least one poll interval before diagnosing a missed event.
- During lockdown, an unlocked value on either side cannot hold the hub open;
  fail-safe control uses `keep_lock`, not `reset`, so an active native schedule
  cannot reopen it.
- Bidirectional-sync ownership of persistent `keep_unlock` and `keep_lock`,
  including the hub/door/location identity, is normally written before the
  command. Failure blocks opening; during active lockdown, the app still
  attempts `keep_lock`, reports enforcement unresolved, and retries persistence.
  On startup, either recorded override is driven to confirmed `keep_lock`
  before live convergence; an unconfirmed result remains durable and retries.
- After lockdown or another fail-safe incident, reconciliation first confirms
  both sides locked, then replaces app-owned `keep_lock` with confirmed
  `lock_now` so future native schedules remain eligible.
- A pairing change makes removed hubs safe before applying hold-open to a new hub.
  If multiple HA entities resolve to one physical hub, all involved pairings
  are locked/suppressed until the mapping is one-to-one.
- Check for `reason=no_paired_hub`, `shared_hub_conflict`, backoff, or flapping
  in logs and the `access_control_hub_sync_failed` event.

### A bidirectionally synced lock re-locks itself immediately

Symptoms: repeated `Hub sync … failed` errors mentioning "legacy Access API
endpoint not found", HTTP 404 on the legacy `lock_rule` readback
(`/proxy/access/api/v2/device/{id}/lock_rule`), and — most visibly — a
bidirectionally synced lock that re-locks itself seconds after every physical
or HA-side unlock. The Access side cannot be read, so the locked-wins
fail-safe latches the hub closed until both sides confirm locked.

Cause: recent UniFi Access firmware removed the private per-device
`lock_rule` API. A deployment without a configured Access API token is pinned
to that legacy path (token presence is the only API selector), so every
legacy read/write on that door now 404s.

Fix: create a token **inside the Access application** — not a UniFi OS
Control-Plane/Network/Site-Manager key — with `view:space` and `edit:space`
permissions, then save it under this app's **Settings → Access API Token**.
As a temporary mitigation, "Sync this lock & Access door bidirectionally" can
be disabled per lock until the token is in place.

Behavior while unresolved: after 3 consecutive identical hard rejections, the
locked-direction hub drive is spaced onto a ~30 second retry cadence — it
never stops retrying, only slows down; lockdown enforcement is never spaced
and always drives at full cadence. The failure logs once at full volume, then
at debug level until the condition clears.

Second cause (slow relay confirmation, fixed in 1.5.12): some current UniFi
Access firmware accepts a rule write immediately but only reports the door
relay state several seconds later, and self-clears a momentary `lock_now` to
`reset` while the relay is still actuating. Before 1.5.12 the confirmation
window was under a second, so ordinary unlock/lock commands frequently could
not be confirmed. A lock command that failed to confirm left the locked-wins
fail-safe latch engaged even though both sides were in fact locked, and every
subsequent unlock was reverted within one poll (~5 s) until the add-on was
restarted. Symptoms differ from the endpoint-removed case: logs mention
`... command was not confirmed (observed rule=reset ...)` or `rule accepted but
relay did not report ... within Ns` rather than HTTP 404, and the affected HA
entity appears in `hub_sync_fail_safe` in `GET /api/health`. The fix widened
the rule-write confirmation and relay observation to a bounded progressive
window (~5 s), taught the confirmation that a post-`lock_now` `reset` rule is
the documented momentary state (with the relay reading providing the positive
evidence), and made the fail-safe latch release as soon as a poll observes both
sides locked. If you see a lock listed in `hub_sync_fail_safe` for more than a
few minutes, confirm the console is reachable and current; a restart clears a
latch immediately but the 1.5.12 changes stop it from re-wedging.

### Rate limit responses appear

Setup, login, API authentication failures, and sensitive dashboard actions use
separate persisted rate-limit buckets. Stop automated retries, correct the
credential or request, and wait for the stated lockout. Successful API calls do
not consume an action quota.

## Collecting a useful bug report

Include the app version, HA version, install method, console topology
(single/split), affected lock type, exact UTC/local time and timezone, steps,
expected result, sanitized Activity reason, and relevant process logs. Never
include API keys, HA/UniFi tokens, passwords, PINs, cookies, database files, or
the environment secret key.
