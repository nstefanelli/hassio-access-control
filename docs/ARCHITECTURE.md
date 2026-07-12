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
   durable hub hold-open ownership; fail-safe uncertain door state locked
   before normal convergence.
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
8. Fires an `access_control_event` in Home Assistant and, when permitted,
   disarms configured alarm panels.

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
strict `SUCCESS` envelope, and door mutations complete only after bounded rule
and relay-state readback.

Native actions map to distinct Access rules. `keep_unlock` is a persistent
hold-open; `keep_lock` is a persistent fail-safe lock; `lock_now` terminates an
active unlock schedule and temporary unlock; and `reset` returns the door to
its Access-native rule. Consequently **Follow Schedule** may immediately
produce an unlocked relay when the native schedule is active. `reset` is not a
lock command. Compatibility mode recognizes known private response envelopes,
but firmware that cannot expose physical state after `reset` produces an
unconfirmed operation instead of a guessed success.

Timed re-locks apply to HA-external locks. For a timed buzz or device-auth
unlock, the replacement deadline is stored and armed before the physical HA
unlock. The returned generation token snapshots the exact predecessor. Since
a timeout can occur after HA executes the request, ambiguous failure retains
the earliest applicable deadline and never removes a sole new intent. A late
recovery cannot overwrite a newer schedule. Restart rehydration, HA
recovery, and an overdue sweep keep retrying durable rows. Manual overrides
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
bound command volume.

Pairing resolution is snapshotted per convergence pass. When a mapping changes,
removed hubs enter the confirmed-safe queue before the newly paired hub may be
held open, and any expansion invalidates the old applied-state cache so new
hubs converge. If multiple independent HA entity owners resolve to one physical
Access hub, every involved pairing is locked and suppressed. The manager emits
`access_control_hub_sync_failed` with `reason=shared_hub_conflict` until the
mapping becomes one-to-one.

Hold-open uses write-ahead ownership. Before `keep_unlock`, the app commits an
`entity_id`/hub row to `hub_sync_holds`; a stale row can cause only an extra
safe lock. Ownership is cleared only after Access confirms the corresponding
safe/release transition. Startup loads every row and closes those hubs even if
HA is unavailable, while graceful shutdown makes the same best-effort action.
An unavailable or unconfirmed command keeps the durable row and release queue
for retry. `hub_sync_state` separately stores last fully confirmed HA/Access
states, origin, Access-rule fingerprint, and pairing signature; Access-origin
schedule state is never confused with an app-owned hold-open lease.

One app-wide command barrier orders authorization/manual unlocks, HA re-locks,
hub actuation, lockdown transitions, and live client swaps. Critical paths take
the barrier before per-entity locks. This avoids deadlock and gives lockdown a
clear completion guarantee: after enable returns, an older application command
cannot issue later. Enabling lockdown also synchronously enforces a safe hub
lock. If persistence or a required lock is unresolved, the API returns `503`, keeps the
safer in-memory lockdown state, and reports unresolved entity IDs through
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
- durable ownership for hubs that may be in Access `keep_unlock` mode, plus
  fully confirmed bidirectional convergence snapshots.

The long-lived SQLite connection runs in autocommit mode, so every ordinary
single-statement write owns its transaction and another coroutine's
commit/rollback cannot capture it. Multi-statement logical operations use
short-lived, task-owned isolated connections with `BEGIN IMMEDIATE`; this
includes topology/config bundles, group membership replacement, pending
re-lock ownership, hub-hold ownership, and legacy explicit batches. Process
locks serialize read-modify-write workflows where needed.

Short-lived UI response caches are process-local and do not create SQLite
writes. A full topology refresh uses an isolated connection and one atomic
transaction, skips unchanged rows, and refuses to mark every user deleted or
every native lock missing when upstream returns an empty/malformed snapshot.

Logical multi-key configuration changes use one serialized bundle transaction.
First-run encryption/credential metadata and settings credential/schedule
updates therefore cannot be observed as a half-written set. Candidate clients
are tested before the matching live reference is published.

Use the backup procedure in [Operations](OPERATIONS.md). Copying only the main
database file while WAL mode is active is not a consistent backup.

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

## Network and trust summary

The application trusts Home Assistant administrators, Supervisor, the UniFi
consoles, and the HA instance it controls. It does not authenticate the
physical person independently of the credential event UniFi reports. Ingress
headers are not a cryptographic boundary against another compromised app on
the same Supervisor network. See [Security model](SECURITY-MODEL.md) for the
full threat model and accepted risks.

## Repository layout

```text
.
├── access_control/
│   ├── config.yaml                 # Home Assistant app manifest
│   ├── Dockerfile / build.yaml     # multi-architecture image
│   ├── frontend/                   # pinned Tailwind build inputs
│   ├── rootfs/run.sh               # container entry point
│   └── rootfs/opt/access_control/  # Python app, templates, static files, tests
├── docs/                           # canonical documentation
├── .github/workflows/              # CI and release automation
└── README.md                       # project landing page
```
