# Architecture

Access Control is a single-process FastAPI application packaged as a Home
Assistant app. It connects UniFi Access and Protect events to an authorization
engine, then drives either UniFi-native doors or Home Assistant `lock.*`
entities. The dashboard and the external REST API are two authenticated views
over the same runtime and SQLite database.

## System context

```text
UniFi Access session API + WebSocket ─┐
UniFi Access Open API :12445 ─────────┼─> event normalization + deduplication
UniFi Protect WebSocket ──────┘                  │
                                                v
                                      authorization engine
                                       │              │
                               UniFi native door   HA lock/alarm
                                       │              │
                                       └──────┬───────┘
                                              v
                                    SQLite audit + state

HA Ingress/SSO ──> dashboard ──────────────────┘
Bearer API key ──> /api/* ─────────────────────┘
```

The standard deployment has no host port. Home Assistant Supervisor proxies
the dashboard through Ingress and supplies the Home Assistant user context.
The process listens on port `8080` inside its container.

## Runtime components

| Component | Responsibility |
|---|---|
| `main.py` | Lifespan, client startup, event dispatch, background supervision, topology sync, health loops, and shutdown |
| `access_client.py` | UniFi Access login/site binding, private compatibility API, token-authenticated Open API, lock-rule/state confirmation, WebSocket events, retry, and reauthentication |
| `protect_client.py` | UniFi Protect login and WebSocket events |
| `auth_engine.py` | User, rule, schedule, alarm, lockdown, and unlock decisions |
| `ha_client.py` | Home Assistant REST calls and circuit breaking |
| `relock_manager.py` | Durable timed re-locks, retry, rehydration, and failure events |
| `hub_sync.py` | Optional bidirectional, origin-aware convergence between an HA lock and its paired Access door |
| `database.py` | Schema, migrations, transactions, audit logs, rate limits, and durable runtime state |
| `ingress.py` / `web_auth.py` | Ingress identity, direct-mode sessions, CSRF, and cookie handling |
| `web_routes.py` | Operator dashboard and setup/settings actions |
| `api_routes.py` / `api_auth.py` | Bearer-key API and scope enforcement |

## Startup sequence

1. Open `/data/access_control.db`, enable SQLite's configured pragmas, create
   the schema, and apply idempotent migrations.
2. Determine whether first-run setup is complete from `admin_username`.
3. Resolve the installation's fixed secret-key mode and derive the Fernet key.
4. Decrypt stored credentials and the optional Access API token, applying
   documented runtime overrides.
5. Connect Access only after its authenticated namespace matches the persisted
   site identity (or enroll that identity on a legacy/first run), connect Home
   Assistant, and start Protect when its console is reachable.
6. Atomically synchronize the current UniFi user and native-door topology.
7. Restore persisted lockdown, pending re-locks, confirmed sync origins, and
   app-owned persistent Access rules (`keep_unlock` or `keep_lock`); fail-safe
   uncertain door state with `keep_lock` before normal convergence.
8. Start supervised loops for connection health, hub sync, topology refresh,
   log retention, visitor status, WebSocket liveness, and scheduled restart.

Protect startup can be degraded without preventing the dashboard from coming
up. Connection state is visible through the dashboard and authenticated health
API.

## Event and authorization flow

Access and Protect can report the same credential event. The dispatcher keeps
short-lived keys for both the user/location pair and upstream event identifier,
then limits concurrent event processing. A duplicate does not issue a second
physical command.

For each event, the authorization engine:

1. Finds the UniFi user and requires an active status.
2. Denies immediately if lockdown is active.
3. Reads the configured alarm panels and evaluates group alarm restrictions.
4. Finds every configured lock associated with the event's Access location.
5. Evaluates schedule-active group grants, then a per-user/per-lock rule when
   no group grants that lock.
6. Enters the shared physical-command barrier, rechecks lockdown, and only then
   issues each physical unlock command.
7. Logs each grant, denial, or command error.
8. Fires an `access_control_granted` event in Home Assistant and, when permitted,
   disarms configured alarm panels.

For a native momentary unlock, the private Access endpoint issues the pulse and
the official Open API relay must then report `unlocked` before step 7 becomes a
grant. If the write was accepted but relay confirmation is unavailable, the
result is audited as `accepted_unconfirmed`, the native-door cache becomes
`unknown`, and the app does not fire the grant event or auto-disarm. This
separates the command's possible physical side effect from confirmed-success
side effects.

An unknown, unavailable, transitional, triggered, night-armed, or mixed alarm
state is handled conservatively when any armed-state blocking flag applies.
An enabled but incomplete schedule is inactive rather than an all-day grant.

## Lock models

`access_native` locks are discovered from UniFi and driven through the Access
API. A native row absent from a valid non-empty snapshot is marked upstream-
missing and excluded from normal lists/counts, authorization, and pairing
resolution without deleting its history or associations. A later snapshot for
the same location revives it. Empty/malformed door snapshots cannot mass-retire
an existing native inventory. `ha_external` locks are explicitly added from
Home Assistant and driven through HA's REST API. Entry-device associations map
an HA lock to an Access reader/location or Protect doorbell/camera.

The preferred native-door control plane is UniFi's official local Open API on
HTTPS port `12445`. It uses a separately configured Bearer token and the Access
door/location ID. The private console-session API uses a hub device ID and is
retained only as tokenless compatibility mode. A configured token selects the
official path exclusively: authentication, permission, transport, or schema
failure never falls back to the private endpoint. Official responses require a
strict `SUCCESS` envelope, and persistent native lock-mode commands complete
only after bounded rule and relay-state readback. Because current firmware can
report relay state several seconds after it accepts a rule write, that readback
runs on a bounded progressive window (~5 s total) rather than a fixed
sub-second loop; a read that returns no usable state mid-window is retried. A
momentary `lock_now` self-clears its rule to `reset` right after it executes, so
confirmation accepts the documented post-execution rule only when the relay
provides positive `locked` evidence — a rule echo alone is never success. Once
a strict write response has been accepted, an exhausted readback raises a
typed accepted-unconfirmed result rather than pretending the mutation did not
happen.

Momentary credential/dashboard buzz uses the private console-session mutation
for firmware compatibility even when a token is configured. Its acceptance is
validated separately, the global command barrier is released, and official
Open API relay polling must observe `unlocked` to confirm the grant. Without a
token, or when a brief pulse is not observed inside the bounded window, the
operation remains accepted-unconfirmed. A short pulse that falls between polls
therefore produces a conservative false-negative, not a guessed success.

Native actions map to distinct Access rules. `keep_unlock` is a persistent
hold-open; `keep_lock` is a persistent fail-safe lock; `lock_now` terminates an
active unlock schedule and temporary unlock; and `reset` returns the door to
its Access-native rule. Consequently **Follow Schedule** may immediately
produce an unlocked relay when the native schedule is active. `reset` is not a
lock command. Compatibility mode recognizes known private response envelopes,
but firmware that cannot expose physical state after `reset` produces an
unconfirmed operation instead of a guessed success. On the official Open API
only, a door with no active override reports an empty rule type, which the
client normalizes to `reset` (native behavior); this normalization does not
change how state is confirmed — always through relay readback, never inferred
from the rule — and legacy envelope parsing stays strict.

An accepted-unconfirmed persistent mutation is not automatically inverted:
`keep_unlock` may already be holding open, `lock_now` may already have ended a
schedule, or `reset` may already have resumed one. The app publishes unknown
and requires operator/controller inspection rather than issuing a blind
compensating mutation.

Timed re-locks apply to HA-external locks. Four sources arm one: a timed buzz,
a device-auth credential unlock, a remote unlock, and — when the per-lock
`relock_on_ha_origin` option is enabled — an observed HA-origin unlock on a
bidirectionally synced lock. For a timed buzz or device-auth unlock, the
replacement deadline is stored and armed before the physical HA unlock. The
returned generation token snapshots the exact predecessor. Since a timeout can
occur after HA executes the request, ambiguous failure retains the earliest
applicable deadline and never removes a sole new intent. A late recovery cannot
overwrite a newer schedule. On a synced lock, a buzz, device-auth, or remote
timed unlock also leases a momentary Access hold so the hub poller does not echo
HA's temporary unlocked state back as a persistent `keep_unlock` rule. The
durable deadline is authoritative wall-clock time for cross-restart recovery; a
live timer additionally carries a monotonic bound captured when it is armed and
fires at whichever bound is nearer, so a backward clock step can only re-lock
sooner and never extend an open-door window. Restart rehydration, HA recovery,
and an overdue sweep keep retrying durable rows, and an overdue row re-fires its
failure event on a bounded cadence until it clears. Manual overrides
that create no new timer pause and restore the prior safety row on failure.
An HA `lock` call returning success is provisional: manual and scheduled
re-lock paths perform bounded state reads and remove the safety row only after
HA reports exactly `locked`. Confirmation waits release the global command
barrier, and every retry revalidates durable generation ownership. “Confirmed”
here means the HA entity state, not an independent mechanical-position sensor.

Optional hub sync is bidirectional when an HA-external lock is opted in. Each
pass reads HA plus every paired Access rule/relay, compares them with the last
fully confirmed origin snapshot, and changes only the side that drifted. HA-
only `locked`/`unlocked` changes propagate to Access. Access-only changes,
including a verified unlock-schedule activation/deactivation, propagate to HA.
The Access WebSocket's schedule/temporary-rule events only mark a location
dirty and trigger an early pass; they are never accepted as proof of an open
door. The regular five-second poll performs authenticated readback and catches
dropped/unsupported events and out-of-band changes.

On a fresh mismatch, locked wins unless the Access rule is an active
`schedule` and the relay is also confirmed unlocked. After a baseline, one-
sided changes win, matching simultaneous changes converge normally, and
opposing simultaneous changes resolve locked. Any malformed/unreadable side,
multi-hub disagreement, HA loss, or expired momentary-unlock lease also resolves
in the safe locked direction. Fail-safe operations use `keep_lock`; they do not
use `reset`, which could reactivate a schedule. Lockdown takes the same path and
a lockdown-state read exception behaves as enabled. Backoff and flap damping
bound command volume on both the legacy poll path and the bidirectional
reconcile path; only the hold-open (unlock) direction is ever damped, so a
failed lock retries on every poll. The one exception is a permanent hard
rejection — a removed legacy endpoint or an explicit legacy-rule rejection —
which, after 3 consecutive identical failures, is spaced onto the existing
~30 second failure backoff; it is never suppressed indefinitely, only spaced.
Lockdown enforcement always bypasses this damping and drives at full cadence.

When the incident clears, reconciliation first confirms both HA and Access are
locked, then replaces app-owned `keep_lock` with confirmed `lock_now`. This
preserves the current closed interval without allowing the persistent fail-safe
override to suppress future native schedules. The locked-wins fail-safe latch
(which forces the pair locked and reverts any unlock until it clears) is
released through one shared helper on either of two conditions: a fully
confirmed locked convergence, or a poll that independently observes HA locked
and every Access hub's **raw official-API relay** locked even though the
cosmetic `lock_now` release could not be confirmed. The latter prevents a
permanent wedge on firmware whose momentary `lock_now` self-clears to `reset`.
A private rule-derived `locked` value, including a successfully written
`keep_lock`, is never independent relay evidence. Any unknown, unreadable,
legacy-derived, or unlocked side keeps the latch, and durable `keep_lock`
ownership remains queued for a later confirmed `lock_now`. Latched entities
are surfaced in `hub_sync_fail_safe` in authenticated health.

Pairing resolution is snapshotted per convergence pass. When a mapping changes,
removed hubs enter the confirmed-safe queue before the newly paired hub may be
held open, and any expansion invalidates the old applied-state cache so new
hubs converge. If multiple independent HA entity owners resolve to one physical
Access hub, every involved pairing is locked and suppressed. The manager emits
`access_control_hub_sync_failed` with `reason=shared_hub_conflict` until the
mapping becomes one-to-one.

Persistent Access overrides created by bidirectional sync use write-ahead
ownership. Before `keep_unlock` or fail-safe `keep_lock`, the app normally
commits the HA `entity_id`, Access device and door/location IDs, hub name, and
override type to `hub_sync_holds`; a stale row can cause only an extra safe
close. Failure blocks `keep_unlock`. During active lockdown only, a failed
ownership write still permits the safer `keep_lock`, leaves enforcement
unresolved, and queues persistence for retry. An uncertain restart first
replaces any possible open override with confirmed `keep_lock`. That closed
ownership row is retained until Access proves a later `lock_now`/native-rule
replacement or an authenticated external rule change supersedes it, preventing
a crash from silently disabling future schedules. On graceful non-lockdown
shutdown, owned overrides and applicable unlocked baselines return to native
schedule ownership; during lockdown, managed ownership remains `keep_lock`.
Unavailable or unconfirmed commands keep durable ownership queued for retry.
`hub_sync_state` separately stores last fully confirmed HA/Access states,
origin, Access-rule fingerprint, and pairing signature; Access-origin schedule
state is never confused with an app-owned override.

One app-wide command barrier orders authorization/manual unlocks, HA re-locks,
hub actuation, lockdown transitions, and live client swaps. Physical workflows
take their stable per-entity lock before entering the barrier and keep that
entity lock through readback; paths needing both locks use that same order.
This avoids deadlock while giving lockdown a clear completion guarantee: after
enable returns, an older application command cannot issue later. The barrier is
held for exactly one physical write and is released before the (now
multi-second) relay-confirmation reads, mirroring the HA re-lock/confirm path,
so a slow-to-actuate hub cannot stall commands to unrelated doors for the whole
confirmation window. Access and HA clients lease the exact writer through that
readback; live Settings publication can switch new work to a tested client,
but retirement waits for already-accepted confirmation without recreating an
old session. Enabling lockdown also
synchronously enforces a safe hub lock. A production Access pair acknowledges
that enforcement only when `keep_lock` plus authoritative raw relay readback
report locked; when the HA command path is available, HA must also report
locked. During an HA outage the Access relay is the fail-safe boundary.
Tokenless rule-derived state cannot acknowledge the physical safety condition.
If persistence or a required lock is unresolved, the API returns `503`, keeps
the safer in-memory lockdown state, and reports unresolved entity IDs through
`lockdown_enforcement_pending` in authenticated health.

Remote-unlock events are different from ordinary queued authorization work: the
upstream event says the door has already opened. Their re-lock scheduling tasks
are marked critical and awaited, rather than cancelled, during client swaps and
shutdown. If persisting the timer fails, the task attempts an immediate HA lock,
requires an observed `locked` state, audits the result, and emits the re-lock
failure event when it cannot confirm recovery.

## Persistence and transaction boundaries

The only durable application store is `/data/access_control.db`. SQLite WAL
sidecars can exist while the application is running. The database contains:

- encrypted upstream credentials, the optional Access Open API token, alarm
  codes, and optional visitor PINs;
- the installation's key metadata, persisted Access site identity, and—in
  database-key mode—its secret key;
- users, locks, rules, groups, visitors, and entry-device associations;
- access/admin audit logs, rate-limit state, lockdown state, and pending
  re-lock deadlines;
- durable ownership and door identity for bidirectional-sync Access
  `keep_unlock` or fail-safe `keep_lock`, plus fully confirmed convergence
  snapshots.

The long-lived SQLite connection runs in autocommit mode, so every ordinary
single-statement write owns its transaction and another coroutine's
commit/rollback cannot capture it. Multi-statement logical operations use
short-lived, task-owned isolated connections with `BEGIN IMMEDIATE`; this
includes topology/config bundles, group membership replacement, pending
re-lock ownership, persistent hub-rule ownership, and legacy explicit batches.
Process locks serialize read-modify-write workflows where needed.

Short-lived UI response caches are process-local and do not create SQLite
writes. A full topology refresh uses an isolated connection and one atomic
transaction, skips unchanged rows, and refuses to mark every user deleted or
every native lock missing when upstream returns an empty/malformed snapshot.

The database owns the invariant that one individual authorization rule exists
per user/lock pair. Upgrade migration keeps the oldest of identical duplicate
policies. If legacy duplicates conflict, it keeps one row but disables it and
clears its schedule for explicit administrator review before installing the
unique index.

Logical multi-key configuration changes use one serialized bundle transaction.
First-run encryption/credential metadata and settings credential/schedule
updates therefore cannot be observed as a half-written set. Candidate clients
are tested before the matching live reference is published.

Use the backup procedure in [Operations](OPERATIONS.md). The manifest requests
a cold Supervisor backup so the process is stopped before `/data` is copied.
That protects WAL consistency but creates a deliberate safety-automation
outage: event intake, due re-lock actuation, sync/lockdown retry, and health are
unavailable until restart. Copying only the main database file while WAL mode
is active is not a consistent backup.

## Resilience and efficiency

- Access and Protect WebSockets reconnect with bounded jittered backoff and
  reauthenticate on an expired session.
- Repeated upgrade authentication failures stop an infinite credential replay
  loop.
- aiohttp heartbeats and supervised reconnect loops detect socket failure;
  ordinary event silence at a quiet door does not trigger reconnect churn.
- HA calls use a circuit breaker; one half-open probe is admitted at a time.
- Topology rows are not rewritten when source values are unchanged.
- Runtime response caches are in memory, and successful API authentication
  avoids a rate-limit write when there is no failure record to clear.
- User/lock topology refresh is atomic and isolated from request transactions.
- Multi-key configuration writes are serialized and atomic.
- Ordinary writes autocommit; multi-statement logical transactions have
  isolated connection ownership.
- The shared physical-command barrier orders lockdown, unlock/re-lock, hub,
  and client-publication transitions.
- Access authentication is not published until its site namespace is verified
  on login and every reauthentication/reconnect.
- Open API Bearer traffic uses an isolated cookieless session on port `12445`;
  configured-token failures cannot downgrade to the private API.
- Access rule events reduce bidirectional-sync latency, while periodic
  authenticated rule/relay reads remain authoritative and repair drift.
- Event handling is deduplicated and concurrency-bounded.
- UI cache refresh tasks are lifespan-owned. Hub-sync and re-lock manager
  shutdown each have a 15-second bound inside the manifest's 60-second stop
  timeout. The complete teardown does not yet have one aggregate deadline, so
  Supervisor force-stop remains possible if a later client or database close
  stalls.

## Network and trust summary

The application trusts Home Assistant administrators, Supervisor, the UniFi
consoles, and the HA instance it controls. It does not authenticate the
physical person independently of the credential event UniFi reports. Ingress
headers are not a cryptographic boundary against another compromised app on
the same Supervisor network. Neither HA entity state nor the official Access
relay is a mechanical bolt, latch, jam, or door-contact sensor. See
[Security model](SECURITY-MODEL.md) for the full threat model and accepted
risks.

## Repository layout

```text
.
├── access_control/
│   ├── config.yaml                 # Home Assistant app manifest
│   ├── Dockerfile                  # multi-architecture image
│   ├── frontend/                   # pinned Tailwind build inputs
│   ├── rootfs/run.sh               # container entry point
│   └── rootfs/opt/access_control/  # Python app, templates, static files, tests
├── docs/                           # canonical documentation
├── .github/workflows/              # CI and release automation
└── README.md                       # project landing page
```
