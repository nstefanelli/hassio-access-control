# Configuration

This guide covers a standard Home Assistant Supervisor installation and the
advanced direct-container path used for development. The standard app is
Ingress-only and uses Home Assistant SSO.

## Requirements

- Home Assistant OS or Home Assistant Supervised with the app store and
  Supervisor. Home Assistant Container does not provide the required app and
  Ingress services.
- A UniFi console running Access. Protect is used for G6 Entry/doorbell event
  support and can run on the same or a separate console.
- A dedicated local UniFi account able to read Access users/locations, manage
  visitors, operate doors, and receive the required Access/Protect events.
  UniFi roles differ by product/version; first-run verifies login, not every
  later action. Use the narrowest role that passes your workflows. Super Admin
  is a broad fallback, not a least-privilege recommendation.
- For complete native-door and bidirectional-sync behavior, a UniFi Access API
  token with `view:space` and `edit:space`. The token API must be reachable from
  the app over HTTPS/TCP `12445`.
- A Home Assistant administrator for the dashboard.
- For HA-external locks, one or more controllable `lock.*` entities. Alarm
  panels are optional.

## Install

In Home Assistant, open **Settings → Apps → App store → ⋮ → Repositories** and
add:

```text
https://github.com/nstefanelli/hassio-access-control
```

Install **Access Control**, leave the default options in place, start the app,
then open its sidebar item as an HA administrator.

For a local checkout or private fork, clone the repository into the app/add-on
share exposed by your Home Assistant installation, reload the app store, and
install the entry shown under **Local apps**. The exact host path is deployment
specific; do not assume a path from a different HAOS release.

## App options

`access_control/config.yaml` exposes two Supervisor options:

| Option | Default | Meaning |
|---|---:|---|
| `log_level` | `info` | `trace`, `debug`, `info`, `notice`, `warning`, `error`, or `fatal`. `notice` maps to uvicorn `info`; `fatal` maps to `critical`. |
| `use_supervisor_api` | `true` | Inject `http://supervisor/core` and the rotating Supervisor token as a complete HA credential pair. Disable only to use a different HA instance with a long-lived token. |

The UI listens on container port `8080`. There is no host port in the supplied
manifest. The manifest enables Ingress, HA authentication, the HA Core API, and
an admin-only sidebar panel.

## First-run setup

The setup form is available only while the database has no configured admin.
It is rate limited and cannot be replayed after setup completes.

1. Open the sidebar panel as an HA administrator. In direct mode, choose a
   separate local dashboard username and password.
2. Enter the primary UNVR/Protect host and credentials. If Access runs on a
   different console, complete all three optional Access host/user/password
   fields; otherwise leave all three blank. Setup tests the primary login,
   Access login at the selected target, and the selected HA connection.
3. With `use_supervisor_api: true`, HA URL/token fields are hidden and the
   Supervisor proxy is tested. With it disabled, supply an HA URL and a
   long-lived token.
4. Create an Access token under **Access → Settings → General → Advanced → API
   Token**, select `view:space` and `edit:space`, and paste it into the optional
   Access API Token field. Existing installations can add it later under
   Settings.
5. Finish setup, then add HA locks, entry devices, groups, schedules, alarms,
   and API keys from the dashboard.

Protect can recover asynchronously if it is unavailable during startup; its
status remains degraded until a later retry succeeds.

### Split Access and Protect consoles

Enter the Protect/primary console in the required first-run fields and the
Access console in the optional separate-console fields. The optional set is
all-or-none; a partial host/user/password set is rejected before persistence.

The separate Access client handles Access users, locations, visitors, door
commands, and Access events. The primary console handles Protect events. When
the separate fields are cleared, Access falls back to the primary console.
Credential changes are tested before the live clients are replaced. The same
split fields remain available later under Settings, subject to the Access-site
binding below.

### Access site identity binding

First setup enrolls a hashed, stable identifier for the authenticated Access
namespace and persists it as `access_console_identity`. Depending on the UniFi
firmware, the candidate set can come from console, site, host-ID, or unique-ID
fields; stable Access building IDs from the authenticated topology are the
fallback. On later logins, the persisted value is matched against every stable
candidate currently exposed, so a firmware-added preferred field does not
silently change an existing installation's identity.

The check runs before an Access session becomes live on initial startup,
Settings replacement, REST reauthentication, and WebSocket reconnect, and is
revalidated before each topology refresh can publish identifiers. Changing an
Access hostname, credentials, or switching between single/split-console mode is
allowed only when the candidate proves it is the same enrolled site. This
prevents a different site's reused user, location, and device IDs from
inheriting local rules, groups, visitors, mappings, or hub ownership.

There is no supported in-place Access-site migration. To control a different
site, preserve the old database as a sensitive backup, initialize a fresh data
store, and recreate/review the site-scoped policy and mappings. Do not bypass
the binding by editing `access_console_identity`.

This is application namespace binding, not TLS peer verification. The Access
client still accepts the console's self-signed/unverified certificate; a
network attacker able to impersonate the enrolled namespace is outside this
check. Keep console management traffic on a trusted network.

### Official Access API token

The Access API token is separate from both the UniFi local username/password
and this app's own `/api/*` Bearer keys. It is used only with the selected
Access console's official local API:

```text
https://<access-host>:12445/api/v1/developer/...
```

The token needs `view:space` for doors/rules/state and `edit:space` for door
rule changes. Saving it performs read-only doors and lock-rule validation
before the live client is replaced. The token is encrypted with the same
installation Fernet key as other upstream secrets and is never shown again.
The dedicated Settings form requires either a non-blank replacement token or
the explicit **Clear Token** action; submitting that form blank is rejected and
does not change the active client. **Clear Token** deliberately returns to
compatibility mode.

A configured token selects the official path exclusively. An expired token,
missing permission, unreachable port, malformed response, or confirmation
failure is surfaced as an error and does **not** fall back to the private
session endpoint. This prevents a security or capability failure from silently
changing command semantics. A custom deployment may set
`ACCESS_CONTROL_ACCESS_API_TOKEN`; when non-empty it overrides the encrypted
database value at runtime and must be protected like a password.

Without a token, compatibility mode continues to use the historical private
console-session API. It uses hub device IDs rather than official door/location
IDs and accepts only known response shapes. `keep_unlock`, `keep_lock`, and
`lock_now` can be confirmed when the firmware exposes their rule values, but
some versions cannot expose an unambiguous relay state after `reset`. The app
reports such work as unconfirmed rather than guessing. Do not rely on native
schedule synchronization or claim authoritative physical confirmation from a
tokenless deployment until it has been tested against that exact Access
version and hardware.

## Secret-key mode

The installation chooses one encryption/session key source exactly once during
first-run setup.

### Database-key mode (default)

If `ACCESS_CONTROL_SECRET_KEY` is absent during setup, the app generates a
random key and stores it in `/data/access_control.db`. A copy of the database
therefore contains the material required to decrypt stored credentials. If an
environment variable is injected later, it is ignored and a warning is logged.
This prevents a late configuration change from silently making existing
ciphertext unreadable.

### Environment-key mode (advanced)

If `ACCESS_CONTROL_SECRET_KEY` is present during first-run setup, the key is
not stored in the database. The database stores only the source marker and a
SHA-256 fingerprint. Every later start requires the exact same environment
value. A missing or mismatched value stops initialization with an explicit
error; the app does not guess or fall back.

Environment-key mode is intended for a custom/standalone deployment capable of
injecting secrets. It is not an option in the supplied Supervisor schema.
Choose a high-entropy secret, store it in a secrets manager, and back it up
separately from the database. Losing it makes encrypted values unrecoverable.

There is no supported in-place switch or rotation between modes. To change the
key, export/recreate configuration through a deliberate migration or perform a
new setup. Do not edit `secret_key_source`, `secret_key`, the fingerprint, or
`encryption_salt` by hand.

Databases created before the source marker existed migrate to database-key mode
on first startup. A newly injected environment key is deliberately ignored for
those installations.

## Home Assistant connection

In the default Supervisor mode, `run.sh` injects these as one pair:

```text
ACCESS_CONTROL_HA_URL=http://supervisor/core
ACCESS_CONTROL_HA_TOKEN=<SUPERVISOR_TOKEN>
```

Both values must be present. A partial pair is treated as a configuration
error; startup never combines an environment URL with a database token or the
reverse. When the Supervisor pair is active, in-app HA credentials are not the
runtime source.

With `use_supervisor_api: false`, first-run stores the remote HA URL and token
encrypted. The HA identity behind that token must be able to:

- read and control the configured `lock.*` entities;
- read, arm, and disarm configured `alarm_control_panel.*` entities;
- read HA configuration, including `time_zone`;
- fire Home Assistant events.

## Locks and entry devices

Native Access doors are synchronized automatically. Add an HA-external lock by
selecting a valid `lock.*` entity and choosing a relock duration from 1 to 300
seconds.

When a valid non-empty Access topology refresh no longer contains a previously
known native door, the app retains its row/history but marks it upstream-
missing. Such a row is excluded from normal lock lists, counts, authorization,
and location/entry-device pairing resolution. If the same Access location
reappears, synchronization revives and refreshes the row. An empty or malformed
snapshot is rejected while native locks exist, so a transient upstream failure
cannot retire the entire inventory.

An entry device maps a lock to the physical reader that generated an event:

- `access_reader`: an Access location/reader identifier;
- `protect_doorbell`: a Protect camera/doorbell identifier mapped to its Access
  location.

The association determines which locks an event can affect. Removing an entry
device removes only that association, not the lock or upstream device.

Per-lock controls include:

| Setting | Behavior |
|---|---|
| Buzz enabled | Shows the timed-unlock action in the dashboard. |
| Relock duration | Delay for dashboard buzz, remote-unlock relock, and device-auth relock; 1–300 seconds. |
| Relock after remote unlock | Arms a timer after the matching UniFi remote-unlock event. |
| Relock after device authentication | Arms a timer after an authorized face, PIN, NFC, or fingerprint event. |
| Sync hub state | Opt-in bidirectional reconciliation between an HA lock and its paired Access door. |
| Auto re-lock after external unlocks | Only shown when hub sync is on. Arms a timer when a synced lock is unlocked from Home Assistant's side (thumb-turn or HA automation). App-initiated unlocks are excluded: a manual dashboard Unlock, a credential tap on a lock whose auto re-lock is off (both are chosen hold-opens), and a buzz/device-auth/remote unlock that already owns a timer. Off by default. |
| Hidden | Removes the card from normal lists without deleting mappings. |

Pending HA re-locks survive restarts. Manual unlock/lock commands replace or
cancel a timer only after the HA operation succeeds. In particular, a manual
lock or automatic re-lock is complete only after bounded HA state reads report
exactly `locked`; an accepted service call without that physical-state
confirmation remains an error and retains/restores the durable timer. A timed
unlock persists its intent before the unlock request and, after success,
atomically moves the deadline to success-time plus the configured duration. If
that extension cannot persist, the earlier write-ahead deadline remains armed.

Native Access lock buttons intentionally have different meanings:

| Action | Access rule | Result |
|---|---|---|
| Unlock | `keep_unlock` | Persistent hold-open, confirmed by rule and relay readback. |
| Lock | `lock_now` | Immediately ends the current unlock schedule and any temporary unlock, then confirms locked. |
| Follow Schedule | `reset` | Clears the temporary override and returns control to Access. The door can become unlocked immediately if its native schedule is active. |
| Fail-safe/lockdown lock | `keep_lock` | Persistent locked override used while reopening through a native schedule would be unsafe; ownership remains durable during the incident and is later replaced by confirmed `lock_now`. |

`reset` is never used as a synonym for Lock. A successful HTTP write is also
not enough: official-mode actions use bounded rule and relay reads before the
dashboard reports success.

### Optional bidirectional hub sync

When enabled for an HA-external lock with a paired Access hub, the app observes
both HA state and the Access rule/relay:

- an HA-only `locked`/`unlocked` change is applied and confirmed on Access;
- an Access-only lock/unlock or native schedule transition is applied and
  confirmed on HA;
- Access schedule/temporary-rule events trigger an immediate readback pass;
  they are wake-up hints, not trusted state assertions;
- the normal five-second poll detects missed events, older firmware without
  those events, and out-of-band drift;
- the last fully confirmed states, Access-rule fingerprint, origin, and pairing
  signature survive restart to prevent echo loops.

Conflict handling is locked-wins. A fresh mismatch locks both sides unless
Access proves an active `schedule` and an unlocked relay. Thereafter, one-sided
changes win, matching simultaneous changes converge, and opposing simultaneous
changes lock. HA/Access disconnects, read exceptions, unknown states, multi-hub
disagreement, and expired momentary-unlock ownership also lock rather than
open. Lockdown uses `keep_lock`, refuses every open command under the shared
barrier, and remains unresolved/observable until the safe direction is
confirmed.

For bidirectional sync, durable ownership normally records the persistent
override type and hub/door/location identity before `keep_unlock` or
`keep_lock`. A failed write blocks `keep_unlock`; during active lockdown, the
app still attempts the safer `keep_lock`, reports enforcement unresolved, and
retries persistence. An uncertain restart first replaces either recorded
override with confirmed `keep_lock`. Once the incident ends and both HA and
Access are confirmed locked, `lock_now` replaces the fail-safe override so
future native schedules remain eligible; ownership is cleared only after
rule/relay confirmation. On clean non-lockdown shutdown, owned overrides and
applicable unlocked baselines return to the native Access rule; during
lockdown, managed ownership remains `keep_lock`. Removed hubs are made safe
before replacements can open. If independent HA entities resolve to one
physical hub, all involved pairings lock and remain suppressed with
`reason=shared_hub_conflict` until the mapping is one-to-one. Failures back off
and emit `access_control_hub_sync_failed`; pathological flapping is damped and
eventually suspended.

Use the official Access API token for authoritative bidirectional behavior.
Compatibility mode is retained for upgrades, but its firmware-dependent
readback limitation can leave a transition unconfirmed and pending. This
option makes both HA and Access state part of the physical-door path; leave it
off unless that is the behavior you intend.

## Alarm panels and policy

Add only `alarm_control_panel.*` entities. A numeric disarm code, when needed,
is encrypted in the database.

Groups provide positive access grants and alarm behavior:

- all locks or an explicit lock set;
- `can_disarm` after a successful grant;
- block when armed away;
- block when armed home;
- an optional schedule.

An active group grants a covered lock. An enabled individual rule is a fallback
grant when no group covers that lock; it does not revoke a group grant.

Alarm blocking is deny-first across group memberships. A scheduled, currently
active `can_disarm` group can override a block only when that group is not also
blocked for the current alarm state. Unknown, unavailable, mixed, transitional,
night-armed, pending, and triggered states are treated conservatively when a
user has either armed-state block flag.

## Schedules and timezone

Schedules use Home Assistant's configured IANA `time_zone`. Until HA is
reachable, the app falls back to a valid `TZ` environment value or the
container's local timezone (normally UTC). The HA health loop refreshes the
zone after recovery.

Supported schedule shapes are:

- selected days, no times: all day on those days;
- start and end, no days: that window every day;
- selected days plus start and end: that window on those days;
- overnight window such as `22:00–06:00`: the after-midnight portion belongs
  to the previous selected day.

An enabled schedule with neither a day nor a complete time range is rejected
at the form boundary and fails closed if corrupt data reaches the engine. A
single time bound is never interpreted as unrestricted access.

## Visitors

The Visitors page creates a UniFi visitor with a start/end window, optional
door, optional 4–8 digit PIN, and local notes. UniFi enforces the upstream
visitor window. The app stores the visitor record and optional PIN encrypted,
but the current UI does not reveal a submitted PIN later; retain it through an
appropriate secure channel if the visitor needs it.

Every five minutes, status-1 rows are checked locally. A timezone-aware end
time in the past is marked expired and logged without an upstream request;
UniFi is queried only when unexpired active rows remain. Historical visitor
rows therefore do not create permanent polling traffic.

Visitor wall times use the same HA-configured timezone as schedules. Times in a
daylight-saving gap and ambiguous repeated-hour times are rejected instead of
silently choosing an offset. An extension must remain after the original start
as well as after the current time. The page shows the site timezone so the
operator can resolve cross-zone ambiguity.

## API keys

Create keys under **Settings → API Keys**. The generated value is shown once;
only its SHA-256 hash is retained. Store it in a secrets manager and revoke it
when no longer required. The accepted scopes are `full`, `read_only`, and
`locks_only`; see the exact [REST API contract](API.md).

## Deployment environment variables

These are advanced runtime inputs, not Supervisor options:

| Variable | Behavior |
|---|---|
| `ACCESS_CONTROL_SECRET_KEY` | Selects environment-key mode only when present at first setup; thereafter must match that mode's fingerprint. Ignored by database-key installs. |
| `ACCESS_CONTROL_HA_URL` + `ACCESS_CONTROL_HA_TOKEN` | Complete pair overrides database HA credentials. A partial pair is rejected/falls back only to a complete DB pair. |
| `ACCESS_CONTROL_UNVR_HOST`, `_USERNAME`, `_PASSWORD` | Override the decrypted primary-console values at runtime. Stored values must still be present and decryptable; when this is also the Access target, the enrolled Access site identity must still match. |
| `ACCESS_CONTROL_ACCESS_HOST`, `_USERNAME`, `_PASSWORD` | Override a configured separate Access console. They do not create split mode when no separate-console rows exist, and the enrolled Access site identity must still match. |
| `ACCESS_CONTROL_ACCESS_API_TOKEN` | Non-empty runtime override for the encrypted Access Open API token. It is sent only to the selected Access host on HTTPS port `12445`; invalid configured-token operations never downgrade to compatibility mode. |
| `TZ` | Startup schedule fallback before HA's configured timezone is available. |
| `DATA_DIR` | Database directory; `/data` in the packaged app. |
| `APP_LOG_LEVEL` | Python application log level; exported from `log_level` by `run.sh`. |
| `RESTART_COMMAND` | Direct-container/service fallback used when Supervisor restart integration is unavailable. Treat as trusted deployment configuration. |
