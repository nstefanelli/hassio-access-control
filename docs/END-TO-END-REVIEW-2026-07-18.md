# End-to-End Engineering Review — 2026-07-18

This is the final architecture map, issue ledger, and post-remediation roadmap
for the July 2026
reliability, security, compatibility, and physical-safety review. Findings are
recorded only after reproduction or direct source evidence; unverified concerns
are marked as such.

## Executive assessment

The remediated working tree is materially safer and more truthful than the
baseline: uncertain writes no longer become confirmed grants, safety intent is
durable across cancellation/restart, same-door workflows remain ordered, live
client replacement cannot sever exact-client confirmation, and persistence,
health, packaging, and setup boundaries are hardened. The final regression and
independent-verifier passes found no remaining runtime release blocker.

This is a **conditional GO only for an isolated, supervised canary** after the
cold-backup restore and controller/hardware preflight. It remains a **NO-GO for
broad unattended production** because real controller/relay timing and
mechanical behavior were not tested, TLS peers are not authenticated, and
Protect has no stable persisted site binding. No real lock, relay, alarm, or
controller command was issued during this review.

### Critical and high-priority findings

| Severity | Issue IDs | Area | Final disposition |
|---|---|---|---|
| Critical | PHY-001–003 | Authoritative relay provenance, fail-safe latch, Settings replacement | Fixed and regression-covered; controller state is still not mechanical proof |
| High | CMD-001–004 | Grant confirmation, concurrency, ambiguous transport, same-door ordering | Fixed and regression-covered; real firmware timing remains untested |
| High | HA-001–002, HA-004, UI-001 | Exact HA confirmation, durable re-lock, stale/slow state | Fixed and independently rechecked |
| High | API-001 | Private mutation response validation | Fixed; private schemas remain firmware-sensitive |
| High | DB-001–002 | Duplicate grants and stale concurrent schedule writes | Fixed with migration 26, SQL invariants, and real-SQLite races |
| High | LIFE-002 | Access client retirement during confirmation | Fixed with exact-client leases and cancellation-safe close |
| High | BAK-001, PKG-001 | Cold backup and current HA packaging | Config/build/docs fixed; disposable Supervisor restore and published workflow not run |
| High | SEC-003 | Protect site identity | Open; resolve or accept explicitly before Protect-backed broad use |
| High | SEC-004 | UniFi TLS peer authentication | Accepted risk for canary only on an isolated network; CA/pinning is a broad-production gate |

## Architecture map

### Platform and deployment

- **Type:** Home Assistant app (the current name for an add-on): a standalone
  FastAPI service packaged in a Supervisor-managed container, not a Home
  Assistant custom integration.
- **Process model:** one Uvicorn/FastAPI process listening on container port
  `8080`; Home Assistant Supervisor Ingress is the normal UI entry point.
- **Home Assistant lifecycle boundary:** this is not a custom integration, so
  config entries, config/options flows, platform forwarding, entity creation,
  and the device/entity registries are not applicable. First-run `/setup`,
  authenticated Settings routes, environment overrides, and SQLite-backed
  configuration are the app equivalents.
- **Persistence:** one SQLite database at `/data/access_control.db`, including
  configuration, encrypted credentials, policy, topology, audit history,
  persistent re-lock intents, lockdown state, and hub-sync ownership/state.
- **Diagnostics equivalents:** process liveness is `/health/live`;
  authenticated component/safety status is `/api/health`; full-scope internal
  counters are `/api/debug`; operator activity is retained in the audit log.
- **External systems:** UniFi Access private session API and WebSocket, optional
  UniFi Access Open API (implementation default `12445`; controller-version
  preflight required), UniFi Protect session API and WebSocket, Home Assistant
  REST API, and the Supervisor APIs used for Ingress, authentication, and
  restart.

### Major components and ownership

| Area | Primary files | Review owner |
|---|---|---|
| Runtime lifecycle and event dispatch | `main.py` | HA lifecycle reviewer |
| Home Assistant client and credentials | `ha_client.py`, `ha_creds.py` | HA lifecycle reviewer |
| Add-on packaging/startup/restart | `config.yaml`, `Dockerfile`, `run.sh`, `service_restart.py` | HA lifecycle reviewer |
| UniFi Access client | `access_client.py` | UniFi/API reviewer |
| UniFi Protect client | `protect_client.py` | UniFi/API reviewer |
| Web/API authentication and Ingress boundary | `config.py`, `ingress.py`, `web_auth.py`, `api_auth.py` | UniFi/security reviewer |
| Authorization and lock command policy | `auth_engine.py`, `lock_actions.py` | Lock-safety reviewer |
| Durable timed re-lock | `relock_manager.py` | Lock-safety reviewer |
| Bidirectional HA/Access convergence | `hub_sync.py` | Lock-safety reviewer |
| Database schema, migrations, and transaction boundaries | `database.py` | Lead reviewer |
| Operator UI and external API | `web_routes.py`, `api_routes.py`, templates/static assets | Lead reviewer |
| Tests, CI, build, and release | `tests/`, `.github/`, dependency manifests | Lead reviewer, then focused reviewer |
| Documentation and operations | `README.md`, `access_control/*.md`, `docs/` | Lead reviewer, then focused reviewer |

### Data, command, event, and authentication flow

```text
Access REST/Open API ── topology + rule/relay reads ─┐
Access WebSocket ───── credential/door events ───────┤
Protect WebSocket ──── credential/doorbell events ──┤
                                                     v
                                        main.py normalize/deduplicate
                                                     |
                                                     v
                                           authorization engine
                                                     |
                                 per-entity workflow lock
                                  (held through readback)
                                                     |
                                global physical-write barrier
                             (lockdown recheck + mutation only)
                                   /                 |             \
                         HA lock service      Access door rule    HA alarm
                                   \                 /
                          release global barrier after write
                                      + exact-client lease
                                      + bounded readback
                                             |
                          durable re-lock / observed state + audit
                                             |
                                           SQLite

HA admin ── Supervisor Ingress identity ──> dashboard routes
API caller ── hashed bearer-key lookup ───> `/api/*` routes
stored credentials ── Fernet/PBKDF2 ──────> runtime clients
```

### State ownership

- UniFi owns native Access door rule and relay observations.
- Home Assistant owns the reported state of configured `lock.*` and
  `alarm_control_panel.*` entities.
- The add-on owns authorization policy, deduplication windows, command
  serialization, pending re-lock deadlines, lockdown intent, Access override
  ownership, sync baselines, and audit records.
- A Home Assistant `locked` value confirms the entity state reported by HA; it
  is not independently verified mechanical bolt position.
- The official Access Open API reports controller relay state. That is stronger
  evidence than a rule echo, but it is still not an independent door-contact,
  latch, or mechanical-bolt sensor.
- Native Access operations distinguish write acceptance from bounded relay
  readback. A successful write alone is not documented as state confirmation.
- Writes to the same HA entity or Access door are sequenced through confirmation
  so a slower older readback cannot overwrite a newer command result. Different
  physical entities may confirm concurrently after the global write-order
  barrier is released.

### Failure and reconnect paths

- Access and Protect WebSocket loops reconnect with bounded backoff; Access
  reauthentication is bounded to avoid an unlimited credential replay loop.
- Runtime client swaps quiesce event intake, drain owned tasks, validate the
  candidate client/site identity, refresh topology, and only then republish
  event readiness. Accepted Access and HA physical workflows lease their exact
  client through bounded confirmation; close waits for that lease and cannot
  recreate a retired HTTP session.
- HA calls use explicit timeouts and a circuit breaker. Re-lock intents remain
  durable until HA reports `locked`.
- Hub sync treats invalid, missing, conflicting, or stale observations
  conservatively and converges toward locked; persistent Access overrides use
  write-ahead ownership so restart recovery can safely close or release them.
- Startup restores lockdown, pending re-locks, hub ownership, and sync state.
  Shutdown drains lifecycle-owned tasks, gives the hub-sync and re-lock
  managers separate bounded cleanup windows, then closes clients and SQLite.
  The manifest gives Supervisor a 60-second stop timeout, but the complete
  teardown is not yet governed by one aggregate application deadline.

### Important dependencies

- Runtime: FastAPI, Uvicorn, aiohttp, aiosqlite, Jinja2,
  python-multipart, cryptography, and itsdangerous.
- Build/release: Home Assistant base images and builder, Tailwind CSS,
  GitHub Actions, GHCR, and GitHub Releases.
- Compatibility-sensitive external interfaces: undocumented/private UniFi
  console endpoints and event envelopes, the official local Access Open API,
  Supervisor Ingress headers, and Home Assistant REST service/state contracts.

## Verified software lock semantics and hardware boundaries

The contract below is verified against the final source and regression suite.
The explicitly identified hardware/controller boundaries remain untested:

| Situation | Intended observable behavior |
|---|---|
| HA external lock reads `locked` / `unlocked` | Trust the HA entity's current reported state, not independent bolt hardware |
| Native Access persistent lock-mode command | Distinguish strict write acceptance from bounded rule and official relay readback; return accepted-unconfirmed when the write may have taken effect but readback does not prove the requested result |
| Native Access momentary unlock | The private compatibility endpoint issues the pulse; only official Open API relay readback can promote it to a confirmed grant |
| Command pending | Do not publish guessed success; retain the prior/durable safety intent |
| Command timeout, cancellation, or ambiguous transport failure | If a mutation might have reached the upstream, publish unknown and report/audit accepted-unconfirmed; preserve or create the earliest applicable safe re-lock intent |
| Controller or HA unreachable | Mark health degraded; do not infer a secure physical state from the failed call |
| Restart | Restore lockdown, durable re-locks, sync baselines, and owned Access overrides before normal convergence |
| Duplicate credential event | Suppress within the bounded cross-source deduplication window |
| Stale cached state | Choose the newer of a timestamped command observation and a bounded-TTL HA snapshot; invalidate HA-backed state on disconnect |
| Stale or malformed sync observation | Converge the pair toward locked and surface unresolved safety state in authenticated health |
| Fail-safe latch release | Require HA to report locked and every Access hub to provide authoritative official-API raw relay evidence; a legacy rule-derived state is insufficient |
| Lockdown acknowledgement | Require every paired Access hub to retain `keep_lock` and provide raw official-API locked relay evidence; when the HA command path is available, it must also report locked |
| “Follow Schedule” | Restore Access-native rule ownership; it is not a lock command and may unlock immediately when a native schedule is active |
| “Command success” | Distinguish request delivery, upstream acceptance, controller relay confirmation, HA entity confirmation, and independent physical position; the app has no independent bolt/contact proof |

### External compatibility evidence

- Home Assistant's current
  [app configuration reference](https://developers.home-assistant.io/docs/apps/configuration/)
  documents `backup`, `timeout`, and current app metadata.
- The April 2026
  [builder migration](https://developers.home-assistant.io/blog/2026/04/02/builder-migration/)
  makes the Dockerfile the build source of truth and removes the implicit
  legacy `BUILD_FROM` contract.
- Home Assistant's
  [base-image architecture reference](https://github.com/home-assistant/docker-base#supported-architectures)
  documents the generic multi-architecture base.
- Ubiquiti's
  [official local API introduction](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
  is the public basis for treating the token API separately from private
  console endpoints. Exact response timing and the private endpoints still
  require controller-version validation.
- Ubiquiti's current official port references conflict: the
  [Required Ports Reference](https://help.ui.com/hc/en-us/articles/218506997-Required-Ports-Reference)
  lists Access Open API on `12445`, while
  [Getting Started with UniFi Access](https://help.ui.com/hc/en-us/articles/17452334269975-Getting-Started-with-UniFi-Access)
  lists `12455`. The implementation follows the Access API guide, historical
  deployments, and the dedicated required-ports reference (`12445`). Because
  no live controller was queried, the actual port remains a controller-version
  preflight item rather than a claimed compatibility fact.

## Critical flow timelines

### Physical command and confirmation

1. The dashboard, Bearer API, credential engine, hub sync, or durable re-lock
   resolves one physical entity and acquires its workflow lock.
2. The flow acquires the global physical-write barrier, rechecks lockdown, and
   persists any required re-lock intent before an opening-direction write.
3. It leases the exact Access or HA client, issues one mutation, then releases
   the global barrier so unrelated doors can progress. The per-entity lock and
   exact-client lease remain held.
4. Native Access confirmation has one six-second wall-clock deadline and
   requires the requested rule plus official relay evidence where applicable.
   HA confirmation uses a separate bounded three-read loop and requires the
   exact expected entity state.
5. Confirmed state is published with a monotonic observation timestamp.
   Rejection is reported as failure; ambiguous transport, cancellation after a
   possible write, or missing confirmation publishes `unknown`, records
   `accepted_unconfirmed`, and retains the safe re-lock intent.

### Settings client replacement

1. Event intake is quiesced and a candidate client is created without mutating
   the published runtime client.
2. Authentication and connection health are validated. Access/Protect swaps
   additionally validate read-only topology and event readiness; Access
   validates persisted site identity and official-token readiness where
   configured. Protect lacks the stable identity binding recorded in SEC-003.
3. Publication occurs atomically under the client/publication barrier.
4. The retired client closes outside the global physical-write barrier. Its
   cancellation-safe close waits for exact-client operation leases, then closes
   the session; it cannot recreate a session after retirement.

### Startup, reconnect, and shutdown

1. Startup opens/migrates SQLite, restores lockdown, durable re-locks, sync
   ownership/baselines, and expected site identity before normal event
   convergence.
2. Access/Protect WebSockets reconnect with bounded backoff. Events are
   normalized and deduplicated, but authenticated reads—not event payloads—own
   authoritative state convergence.
3. The five-second hub poll repairs missed events or drift; unknown/conflicting
   input converges toward locked and exposes unresolved safety health.
4. Shutdown stops event intake, drains lifecycle-owned tasks, gives managers
   bounded cleanup windows, closes clients, then closes SQLite. Supervisor
   allows 60 seconds, although LIFE-001 records the remaining lack of one
   aggregate application deadline.

## Issue ledger

Statuses describe the current working tree, not a published build. “Unit
coverage added” means a regression test exists in the patch. The current full
suite and the independent fresh-agent verification have passed. References are
to the working tree on 2026-07-18; symbol names are the stable locator because
fixes in this review shifted numeric lines.

### PHY-001 — Legacy rule-derived state could satisfy a physical-safety condition

- **Severity:** critical
- **Confidence:** confirmed by direct source analysis and regression fixtures
- **Component:** bidirectional hub sync, fail-safe latch, lockdown
- **Files and lines:** `hub_sync.py:941`
  (`_has_authoritative_relay_state`), `hub_sync.py:1177`
  (`_lockdown_pair_confirmed`), `hub_sync.py:1294`
  (`_observe_access_side`), `hub_sync.py:1480`
  (`_reconcile_bidirectional`), and `hub_sync.py:1870` (`_apply_state`)
- **Reproduction or failure scenario:** in tokenless compatibility mode,
  `get_door_state` derives a state from the private rule. A successful
  `keep_lock` rule write could therefore look like independent locked evidence
  even though no relay observation existed.
- **User impact:** the locked-wins latch could clear, or lockdown enforcement
  could be acknowledged, while the Access relay remained unverified.
- **Root cause:** the normal-convergence state and the raw authoritative relay
  observation shared one value.
- **Proposed fix:** preserve a separate raw-relay field only for official Open
  API observations and require that field when releasing the latch or
  acknowledging a lockdown-safe pair.
- **Tests required:** legacy rule-derived locked state and successful legacy
  `keep_lock` must not release the latch or acknowledge lockdown; official raw
  locked relay may do so.
- **Dependencies or related issues:** CMD-001; an Access Open API token with
  `view:space` and `edit:space` is required for authoritative relay evidence.
- **Status:** fixed in the working tree; focused unit coverage added. In
  tokenless mode the app now remains unresolved/retries rather than asserting a
  false safety confirmation. Real controller and relay behavior remains to be
  validated.

### PHY-002 — Client replacement could promote legacy evidence to authoritative relay state

- **Severity:** critical
- **Confidence:** confirmed
- **Component:** Access client lifecycle and bidirectional hub sync
- **Files and lines:** `hub_sync.py` (`_drive_hub`, `_apply_state`, and
  `_reconcile_bidirectional`); `access_client.py` operation lifecycle
- **Reproduction or failure scenario:** a tokenless client accepted a rule
  command and began readback; Settings replaced it with an official-token
  client before the old operation returned. Authority was then inferred from
  the new global client rather than from the exact client that produced the
  result.
- **User impact:** legacy rule-derived `locked` evidence could be mislabeled as
  authoritative relay confirmation, allowing false safety acknowledgement.
- **Root cause:** state and evidence provenance were returned separately and
  authority was re-read from mutable global client state.
- **Proposed fix:** return state plus an immutable
  `authoritative_relay` provenance flag from the exact leased client operation
  and propagate that result without consulting the replacement client.
- **Tests required:** deterministic client swap while legacy readback is in
  flight; the old result must remain non-authoritative.
- **Dependencies or related issues:** PHY-001, LIFE-002.
- **Status:** fixed in the working tree; deterministic regression coverage
  added.

### PHY-003 — External rule supersession could clear the locked-wins fail-safe latch

- **Severity:** critical
- **Confidence:** confirmed
- **Component:** bidirectional hub-sync ownership and fail-safe latch
- **Files and lines:** `hub_sync.py` (`_observe_access_side` and locked-wins
  latch release path)
- **Reproduction or failure scenario:** after conflicting observations armed
  the fail-safe latch, an external Access rule change superseded the app-owned
  rule before both HA and authoritative Access relay observations were locked.
- **User impact:** normal convergence could resume without proving the safe
  locked boundary, weakening the protection against an unintended unlock.
- **Root cause:** ownership supersession and physical-safety latch release were
  coupled even though only the ownership fact had changed.
- **Proposed fix:** clear superseded ownership independently, but retain the
  latch until HA reports locked and the exact Access relay observation is
  authoritatively locked.
- **Tests required:** external rule supersession while latched must not bypass
  the both-sides-locked release gate.
- **Dependencies or related issues:** PHY-001, PHY-002.
- **Status:** fixed in the working tree; regression coverage added.

### CMD-001 — Native momentary unlock acceptance was reported as a confirmed grant

- **Severity:** high
- **Confidence:** confirmed
- **Component:** Access client, authorization engine, dashboard lock actions
- **Files and lines:** `access_client.py:1681`
  (`unlock_momentary_confirmed`), `auth_engine.py:280`
  (`process_event`), `auth_engine.py:731` (`_unlock_access_native`), and
  `lock_actions.py:235` (`execute_lock_action`)
- **Reproduction or failure scenario:** the private momentary-unlock endpoint
  returned HTTP success or an empty accepted body, but the relay never reported
  unlocked or no official token was configured.
- **User impact:** the app could log a grant, publish an unlocked cache value,
  fire the granted HA event, and auto-disarm an alarm without confirmed relay
  evidence.
- **Root cause:** acceptance of the fire-and-forget private mutation was the
  only success condition.
- **Proposed fix:** after the private compatibility acceptance check, poll the
  official Open API relay; otherwise raise a typed accepted-unconfirmed result.
  Publish cache
  `unknown`, audit `accepted_unconfirmed`, and do not fire grant-only events or
  auto-disarm.
- **Tests required:** confirmed relay, no token, readback timeout, pre-write
  rejection, dashboard action, credential authorization, cache, HA event, and
  auto-disarm branches.
- **Dependencies or related issues:** PHY-001, CMD-003.
- **Status:** fixed in the working tree; unit coverage added. A short pulse can
  still finish between polls, so a safe false-negative remains possible and
  requires hardware timing validation.

### HA-001 — HA credential unlock used service acceptance as state confirmation

- **Severity:** high
- **Confidence:** confirmed
- **Component:** authorization engine and HA lock state cache
- **Files and lines:** `auth_engine.py:837` (`_unlock_ha_external`) and its
  callers in `auth_engine.py:280` (`process_event`) and `main.py`
- **Reproduction or failure scenario:** HA accepted an unlock service call but
  its entity remained locked, unknown, or unavailable.
- **User impact:** the app could report a granted credential event and permit
  grant-only alarm behavior even though HA did not report the requested state.
- **Root cause:** the credential path lacked the exact bounded state readback
  already expected of manual actions.
- **Proposed fix:** release the command barrier after the write, require exact
  `unlocked` readback using the same HA client, and update cache/event/disarm
  state only after confirmation.
- **Tests required:** exact confirmed state, mismatched/unknown state, client
  swap during readback, lockdown recheck, and cache/event side effects.
- **Dependencies or related issues:** HA-002, CMD-003.
- **Status:** fixed in the working tree; unit coverage added. HA state remains
  entity-reported state, not independent bolt position.

### HA-002 — Cancellation could strand durable re-lock ownership

- **Severity:** high
- **Confidence:** confirmed
- **Component:** authorization and manual HA unlock/re-lock workflows
- **Files and lines:** `auth_engine.py:837` (`_unlock_ha_external`);
  `lock_actions.py:235` (`execute_lock_action`) and
  `relock_manager.py` durable-intent methods
- **Reproduction or failure scenario:** a request or lifecycle task was
  cancelled after a timed-unlock intent was armed, or while an older intent was
  paused for a manual action.
- **User impact:** a door could have accepted an unlock while its only live
  re-lock intent was abandoned or remained paused.
- **Root cause:** normal cancellation propagation interrupted safety cleanup.
- **Proposed fix:** shield the retain/resume operation until it resolves, then
  propagate the original cancellation.
- **Tests required:** cancellation before/after the HA write, repeated
  cancellation during cleanup, retain failure, and paused-row resume.
- **Dependencies or related issues:** LIFE-001.
- **Status:** fixed in the working tree; unit coverage added. Process
  force-kill and Supervisor timeout behavior remain operational limits.

### CMD-002 — Global physical-command barrier covered multi-second readback

- **Severity:** high
- **Confidence:** confirmed
- **Component:** manual lock actions, credential authorization, hub sync
- **Files and lines:** `lock_actions.py:235` (`execute_lock_action`),
  `auth_engine.py:731` (`_unlock_access_native`), and
  `hub_sync.py:2648` (`_drive_hub`)
- **Reproduction or failure scenario:** one Access write was accepted and its
  relay took several seconds to converge while an unrelated command or
  lockdown transition waited on the global barrier.
- **User impact:** slow firmware on one door could delay safety commands to
  unrelated doors.
- **Root cause:** the barrier surrounded both mutation and bounded
  confirmation reads.
- **Proposed fix:** use an explicit `on_written` hook to release the barrier
  immediately after strict write acceptance, before readback.
- **Tests required:** each native action releases the barrier after the write
  while confirmation is blocked; lockdown still wins before a not-yet-issued
  write.
- **Dependencies or related issues:** CMD-001, HA-001.
- **Status:** fixed in the working tree; unit coverage added.

### CMD-003 — Ambiguous or cancelled mutations could retain stale known state

- **Severity:** high
- **Confidence:** confirmed
- **Component:** Access/HA command transport, authorization, manual actions,
  cache, and audit
- **Files and lines:** `access_client.py` (`_request`,
  `_open_api_request`, and mutation validation); `auth_engine.py`;
  `lock_actions.py`
- **Reproduction or failure scenario:** a network reset, timeout, malformed
  mutation-success envelope, or task cancellation occurred after a write might
  have reached Access or HA but before confirmation/audit completed.
- **User impact:** the UI/API cache could retain a prior `locked` or `unlocked`
  value and the audit trail could omit a command that may have actuated.
- **Root cause:** ambiguous transport failures shared the same exception as
  definite pre-write rejection, and normal cancellation skipped post-acceptance
  uncertainty cleanup.
- **Proposed fix:** use a typed outcome-unknown error for mutation ambiguity;
  publish `unknown`, shield a minimal `accepted_unconfirmed` audit after known
  acceptance, retain re-lock safety, and propagate cancellation afterward.
- **Tests required:** mutation timeout/reset versus safe GET timeout, explicit
  rejection, malformed success, cancellation during write/readback, cache,
  audit, and grant-only side effects.
- **Dependencies or related issues:** CMD-001, HA-002, API-001, API-002.
- **Status:** fixed in the working tree; regression coverage added.

### CMD-004 — Same-door confirmations could publish out of command order

- **Severity:** high
- **Confidence:** confirmed
- **Component:** manual actions, credential authorization, re-lock, remote
  mirroring, and hub sync
- **Files and lines:** `main.py` (`physical_entity_locks`);
  `lock_actions.py`; `auth_engine.py`; `relock_manager.py`; `hub_sync.py`
- **Reproduction or failure scenario:** two writes to one physical entity were
  issued in order after each released the global barrier, but the older
  confirmation completed after the newer confirmation.
- **User impact:** an older result could overwrite the cache or audit-facing
  outcome for the newer desired state.
- **Root cause:** unrelated-door concurrency was introduced without retaining
  ordering through readback for the same physical entity.
- **Proposed fix:** acquire a shared per-entity workflow lock before the global
  write barrier and hold it through exact confirmation; keep separate internal
  re-lock generation locks to avoid self-deadlock.
- **Tests required:** reverse confirmation completion for two same-entity HA
  commands plus re-lock/hub-sync interoperability.
- **Dependencies or related issues:** CMD-002, HA-002.
- **Status:** fixed in the working tree; deterministic ordering coverage
  added.

### CMD-005 — Confirmation retries did not have one hard overall deadline

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** native Access rule and relay confirmation
- **Files and lines:** `access_client.py:69` (`_LOCK_CONFIRM_WINDOW`),
  `access_client.py:1277` (`_confirm_rule_command`), and
  `access_client.py:1681` (`unlock_momentary_confirmed`)
- **Reproduction or failure scenario:** each individual HTTP read consumed its
  own timeout and was followed by retry sleeps, allowing a nominally short
  confirmation window to expand to many tens of seconds.
- **User impact:** command requests, client swaps, and shutdown could remain
  occupied far longer than documented.
- **Root cause:** the retry count bounded attempts, not elapsed wall time.
- **Proposed fix:** wrap the entire read/sleep confirmation loop in one
  six-second `asyncio.timeout` budget.
- **Tests required:** deliberately blocked rule and relay reads must terminate
  within the overall budget, not one timeout per attempt.
- **Dependencies or related issues:** CMD-002, LIFE-002.
- **Status:** fixed in the working tree; deadline regressions added.

### API-001 — Private UniFi mutations trusted HTTP 2xx without validating the envelope

- **Severity:** high
- **Confidence:** confirmed
- **Component:** UniFi Access private compatibility client
- **Files and lines:** `access_client.py:660`
  (`_validate_legacy_mutation_payload`) and `access_client.py:704`
  (`_legacy_mutation_response`), including mutation callers such as
  `access_client.py:1681` (`unlock_momentary_confirmed`)
- **Reproduction or failure scenario:** Access returned 2xx with malformed JSON,
  a non-object body, `success: false`, a failing `code`, or a failing
  `meta.rc`.
- **User impact:** rejected momentary unlock, visitor, user, or PIN mutations
  could be logged or displayed as successful.
- **Root cause:** several mutation methods ignored the body or defaulted missing
  `data` to an empty object.
- **Proposed fix:** centralize semantic validation; reject malformed/non-object
  bodies and explicit known failure markers, require a data object where the
  caller consumes one, and retain empty/neutral HTTP 2xx compatibility for the
  observed delete and momentary fire-and-forget operations.
- **Tests required:** success envelopes, explicit failures, malformed/non-object
  JSON, empty compatibility bodies, and required data objects for every
  mutation family.
- **Dependencies or related issues:** CMD-001.
- **Status:** fixed in the working tree; unit coverage added. A non-empty
  private fire-and-forget object with no recognized success or failure marker
  remains accepted for compatibility, so private endpoint schemas still need
  controller-version validation.

### DB-001 — Concurrent individual-rule creation could leave duplicate grants

- **Severity:** high
- **Confidence:** confirmed
- **Component:** SQLite authorization policy
- **Files and lines:** `database.py:572-638` (migration 26) and
  `database.py:1305` (`add_rule`)
- **Reproduction or failure scenario:** two concurrent dashboard submissions
  passed the application-level existence check and inserted the same
  user/lock pair.
- **User impact:** disabling or deleting one visible row could leave another
  authorization grant active; authorization selected an arbitrary duplicate.
- **Root cause:** uniqueness was enforced with a racy check-then-insert rather
  than a database invariant.
- **Proposed fix:** deduplicate legacy rows, fail closed on conflicting policy,
  add a unique `(user_id, lock_id)` index, and make insertion idempotent.
- **Tests required:** concurrent inserts persisted across reopen, identical
  duplicate migration, and conflicting duplicate fail-closed migration.
- **Dependencies or related issues:** administrator must review any migrated
  conflicting rule that is disabled.
- **Status:** fixed in the working tree; migration and concurrency coverage
  added.

### DB-002 — Concurrent schedule edits could re-enable a disabled grant

- **Severity:** high
- **Confidence:** confirmed
- **Component:** SQLite authorization policy and dashboard/API rule editors
- **Files and lines:** `database.py` access-rule update methods;
  `web_routes.py` and `api_routes.py` individual-rule handlers
- **Reproduction or failure scenario:** a schedule editor read an enabled rule,
  an administrator disabled it, and the stale schedule save then wrote the
  entire prior row back.
- **User impact:** a concurrent schedule-only change could silently restore
  physical-access authorization that an administrator had just disabled.
- **Root cause:** independent policy controls shared a full-row
  read/modify/write helper.
- **Proposed fix:** use atomic column-specific SQL for the enabled toggle and
  schedule replacement.
- **Tests required:** concurrent toggle/schedule operations against real
  SQLite, preserving both the disabled state and the new schedule.
- **Dependencies or related issues:** DB-001.
- **Status:** fixed in the working tree; real-SQLite concurrency coverage
  added.

### BAK-001 — Live WAL-backed state lacked an explicit cold-backup contract

- **Severity:** high
- **Confidence:** confirmed from manifest and persistence design
- **Component:** Home Assistant manifest, SQLite operations
- **Files and lines:** `config.yaml:16-23`; `docs/OPERATIONS.md` backup runbook
- **Reproduction or failure scenario:** Supervisor backs up `/data` while the
  process is writing safety-critical WAL state, or an operator copies only the
  live main database.
- **User impact:** a restored backup can omit or inconsistently capture re-lock,
  lockdown, policy, or hub-ownership state.
- **Root cause:** the manifest did not request a stopped/cold app backup and the
  safety outage during a cold backup was not called out.
- **Proposed fix:** request `backup: cold`, allow a 60-second stop timeout, and
  document that event intake and safety actuation are unavailable while the
  app is stopped.
- **Tests required:** manifest/YAML validation and an isolated Supervisor
  backup/restore drill with integrity and state checks.
- **Dependencies or related issues:** LIFE-001.
- **Status:** fixed in configuration and documentation; real Supervisor cold
  backup/restore validation remains pending.

### PKG-001 — Packaging used the retired per-architecture builder contract

- **Severity:** high
- **Confidence:** confirmed against current Home Assistant developer guidance
- **Component:** Dockerfile, CI, Home Assistant app metadata
- **Files and lines:** `Dockerfile:1`, `.github/workflows/ci.yaml` image-build
  job, deleted `access_control/build.yaml`
- **Reproduction or failure scenario:** current Home Assistant builder treats
  the Dockerfile as the source of truth and no longer implicitly supplies the
  legacy `BUILD_FROM` contract.
- **User impact:** future app builds or releases could fail, or retain stale
  add-on metadata.
- **Root cause:** the repository still selected per-architecture bases through
  `build.yaml` and labeled the image as `addon`.
- **Proposed fix:** use the generic multi-architecture HA Python base directly,
  remove `build.yaml`/`BUILD_FROM`, and publish current `io.hass.type=app` plus
  repository URL metadata.
- **Tests required:** lint plus clean amd64 and arm64 image builds through the
  release workflow.
- **Dependencies or related issues:** the base tag is version-pinned but not
  digest-pinned.
- **Status:** fixed in the working tree; clean local amd64 and arm64 builds
  pass. Published workflow/release verification is still pending.

### LIFE-001 — Shutdown work and UI refresh tasks were not fully lifecycle-bounded

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** FastAPI lifespan, hub/re-lock managers, UI SWR cache
- **Files and lines:** `main.py:90` (`_shutdown_manager_bounded`),
  `main.py:227` (`_track_event_task`), `main.py:1747-1812` (primary cleanup),
  and `web_routes.py:194` (`_cached_device_options`)
- **Reproduction or failure scenario:** a manager shutdown blocks indefinitely,
  or a stale-while-revalidate task continues using a client/SQLite after
  lifespan cleanup starts.
- **User impact:** Supervisor can force-kill before cleanup completes; an
  unowned task can fail during teardown or race closed resources.
- **Root cause:** manager shutdown had no timeout and the UI task was not
  registered with the lifespan task tracker.
- **Proposed fix:** track/drain the UI task and give each safety manager a
  bounded 15-second shutdown window inside the manifest's 60-second stop
  budget.
- **Tests required:** task ownership/drain, manager timeout continuation,
  startup-failure cleanup, and durable-row preservation.
- **Dependencies or related issues:** HA-002, BAK-001.
- **Status:** partially fixed and unit-covered. The entire shutdown sequence
  (event drain, two manager windows, client closes, and SQLite close) still has
  no single aggregate deadline, so a stuck non-manager cleanup can consume the
  remaining Supervisor budget.

### LIFE-002 — Client replacement could interrupt confirmation or resurrect a retired session

- **Severity:** high
- **Confidence:** confirmed
- **Component:** Access HTTP session and live Settings client replacement
- **Files and lines:** `access_client.py` (`_operation_lease`, `close`, and
  session creation); client swap paths in `main.py`
- **Reproduction or failure scenario:** Settings closed the old Access client
  after its mutation was accepted but while confirmation was still polling;
  the polling path could fail early or lazily create a new session on the
  retired client.
- **User impact:** an accepted physical command could lose its bounded
  confirmation/audit path and leave two logical client lifetimes active.
- **Root cause:** client close did not distinguish new work from already
  accepted in-flight operations.
- **Proposed fix:** reject new work once closing starts, lease accepted
  high-level operations through confirmation, drain leases before closing the
  HTTP session, and permanently reject post-close session creation.
- **Tests required:** close waits for an in-flight confirmation and any later
  command on that instance is rejected.
- **Dependencies or related issues:** PHY-002, CMD-003, CMD-005.
- **Status:** fixed in the working tree; lifecycle regression coverage added.

### LIFE-003 — HA Settings replacement could retire the writer before exact readback

- **Severity:** medium
- **Confidence:** confirmed by the fresh independent verifier
- **Component:** HA client lifecycle, Settings publication, and every HA
  write/readback workflow
- **Files and lines:** `ha_client.py` (`operation_lease`, `_ensure_session`,
  and `close`); HA command paths in `lock_actions.py`, `auth_engine.py`,
  `hub_sync.py`, `relock_manager.py`, and `main.py`; `_update_ha_impl` in
  `web_routes.py`
- **Reproduction or failure scenario:** a physical HA write released the
  global barrier and began exact-state polling; Settings published a new
  client and closed the old one. A later retry on the old client could create a
  new unowned HTTP session.
- **User impact:** confirmation could fail despite an accepted command, or a
  retired HA client session could leak. Safety handling was conservative, so
  the verifier did not find a false grant from this race.
- **Root cause:** HAClient had neither a permanent closed state nor an
  operation lease spanning the write plus confirmation boundary.
- **Proposed fix:** acquire an exact-client operation lease while holding the
  publication barrier, retain it through readback, make an owned close task
  drain leases even through caller cancellation, reject post-close session
  creation, and drain the old client outside the global barrier after atomic
  publication.
- **Tests required:** close waits for an active lease, post-close reopen is
  rejected, and a physical workflow retains the lease after releasing the
  global write barrier.
- **Dependencies or related issues:** LIFE-002, HA-001, CMD-004.
- **Status:** fixed and independently rechecked; lifecycle, cancellation, and
  workflow regressions pass.

### HA-003 — HA connection probes did not heal or trip the circuit breaker

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** Home Assistant health/circuit breaker
- **Files and lines:** `ha_client.py:99` (`test_connection`) and
  `ha_client.py:128` (`check_health`)
- **Reproduction or failure scenario:** the health probe succeeded after prior
  failures, but the circuit stayed open; or repeated probe transport failures
  did not contribute to opening it.
- **User impact:** recovery work and state seeding could remain suppressed, or
  health could understate repeated HA failure.
- **Root cause:** `test_connection` updated connection flags but not circuit
  state.
- **Proposed fix:** record probe success/failure in the same breaker used by
  service and state calls.
- **Tests required:** successful healing and failed-probe circuit accounting.
- **Dependencies or related issues:** API-002.
- **Status:** fixed in the working tree; unit coverage added.

### HA-004 — Remote/re-lock failures and HA disconnects retained stale command state

- **Severity:** high
- **Confidence:** confirmed
- **Component:** HA remote mirroring, durable re-lock, state seeding, and Locks
  dashboard
- **Files and lines:** remote-unlock handlers and health loop in `main.py`;
  `relock_manager.py` (`on_unknown`); Locks snapshot handling in
  `web_routes.py`
- **Reproduction or failure scenario:** a remote mirror or due re-lock was
  accepted without exact state confirmation, retries exhausted, HA
  disconnected, or HA was changed externally after a prior command.
- **User impact:** the dashboard could indefinitely show a stale secure or open
  state even though the current HA result was unknown.
- **Root cause:** failure paths preserved durable safety intent but did not
  invalidate presentation state, and the dashboard preferred command cache
  indefinitely over current HA state.
- **Proposed fix:** generation-check failure callbacks that publish `unknown`,
  invalidate HA-backed cache on disconnect, retain native entries during seed,
  and prefer a bounded-fresh HA entity snapshot on the Locks page.
- **Tests required:** remote unconfirmed command, re-lock retry failure,
  immediate fail-safe lock, HA disconnect, and external HA state change.
- **Dependencies or related issues:** HA-001, HA-002, API-002.
- **Status:** fixed in the working tree; regression coverage added.

### UI-001 — A pre-command HA snapshot could override a newly confirmed state

- **Severity:** high
- **Confidence:** confirmed by the fresh independent verifier
- **Component:** Locks dashboard HA snapshot and command-state cache
- **Files and lines:** `web_routes.py` (`_cached_device_options` and
  `locks_list`); `lock_actions.py` (`publish_lock_state`); state publication in
  `main.py`
- **Reproduction or failure scenario:** the dashboard cached HA `locked`, a
  later manual/API unlock was exactly confirmed and published `unlocked`, then
  the redirect rendered within the snapshot's 30-second TTL.
- **User impact:** the Locks page displayed the opposite of the latest
  confirmed HA state, including falsely showing `locked` after a confirmed
  unlock.
- **Root cause:** snapshot values always took precedence even when fetched
  before the command; neither source carried an observation order.
- **Proposed fix:** timestamp command observations and upstream snapshot fetch
  starts with monotonic time, select the newer observation, and prevent a slow
  seed read that began earlier from overwriting a later command result.
- **Tests required:** command-newer-than-snapshot, snapshot-newer-than-command,
  and a write/readback flow publishing its timestamped result.
- **Dependencies or related issues:** HA-004, CMD-004.
- **Status:** fixed and independently rechecked; both observation-order
  regressions pass.

### SEC-001 — Environment-key fingerprint allowed fast offline guessing

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** key management
- **Files and lines:** `config.py:19` (`secret_key_fingerprint`),
  `config.py:40` (`_matches_secret_key_fingerprint`), and runtime bootstrap in
  `main.py`
- **Reproduction or failure scenario:** an attacker obtains SQLite but not a
  weak environment key and tests guesses against its unsalted raw SHA-256
  fingerprint.
- **User impact:** weak operator-supplied keys could be recovered much faster
  than the application's Fernet KDF cost suggests.
- **Root cause:** mismatch detection stored a fast, deterministic verifier.
- **Proposed fix:** store a salted, versioned PBKDF2-SHA256 verifier at 480,000
  iterations; accept a matching legacy verifier once and replace it without
  rotating the encryption key.
- **Tests required:** current verifier matching/mismatch/malformed input and
  one-time legacy migration without writing or rotating the secret.
- **Dependencies or related issues:** SEC-002.
- **Status:** fixed in the working tree; unit coverage added.

### SEC-002 — New direct-mode administrators and environment keys had no minimum strength

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** first-run setup
- **Files and lines:** `web_routes.py:149-154` (strength constants) and
  `web_routes.py:659-750` (setup validation); `templates/setup.html`
- **Reproduction or failure scenario:** a directly exposed first-run setup used
  a very short password or `ACCESS_CONTROL_SECRET_KEY`.
- **User impact:** online session compromise or offline recovery of encrypted
  upstream credentials.
- **Root cause:** presence was validated, but length was not.
- **Proposed fix:** require 12 characters for a new direct-mode password and 32
  characters for a new environment key before probing upstream credentials.
- **Tests required:** boundary values and proof that rejected setup performs no
  upstream probes/writes.
- **Dependencies or related issues:** SEC-001.
- **Status:** fixed for new setup in the working tree; unit coverage added.
  Existing matching keys are retained for compatibility and should be rotated
  deliberately if weak.

### API-002 — Health and mutation outcomes obscured actionable degraded/uncertain state

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** authenticated REST API and dashboard
- **Files and lines:** `api_routes.py:75` (`health`),
  `api_routes.py:240` (`set_lock_mode`), `lock_actions.py:235`
  (`execute_lock_action`), and `web_routes.py:1522` (`_lock_action`)
- **Reproduction or failure scenario:** `/api/health` returned `ok` while a
  required upstream or WebSocket was down, and an Access write accepted without
  confirmation collapsed into a generic error.
- **User impact:** monitoring missed degraded/critical safety state; automation
  could not distinguish “rejected before write” from “may already be active.”
- **Root cause:** aggregate status was constant and the command result model had
  no accepted-unconfirmed outcome.
- **Proposed fix:** calculate `ok`/`degraded`/`critical`, return HTTP 202 plus
  structured `accepted_unconfirmed` for known accepted writes, publish cache
  `unknown`, and show an operator notice.
- **Tests required:** every aggregate-health trigger, structured 202 mapping,
  cache unknown, dashboard notice, and no auto-disarm.
- **Dependencies or related issues:** PHY-001, CMD-001.
- **Status:** fixed in the working tree; unit coverage added. Monitoring must
  still inspect component fields, and an accepted-unconfirmed write may require
  direct controller/door inspection.

### API-003 — Protect optionality is ambiguous in aggregate health

- **Severity:** medium
- **Confidence:** confirmed
- **Component:** authenticated health API and monitoring
- **Files and lines:** `api_routes.py:75` (`health`); degraded Protect startup
  path in `main.py`
- **Reproduction or failure scenario:** a deployment intentionally does not use
  Protect-origin events and has no connected Protect client.
- **User impact:** aggregate health remains `degraded`, producing a permanent
  false-positive alert even when every configured safety path is healthy.
- **Root cause:** aggregation treats every Protect disconnect as degraded but
  the runtime has no explicit “Protect required/used” signal.
- **Proposed fix:** derive durable Protect usage from configured
  `protect_doorbell` entry-device mappings and aggregate disconnection only
  when one exists.
- **Tests required:** Access-only deployment, configured-but-disconnected
  Protect, active Protect mappings, and recovery.
- **Dependencies or related issues:** API-002.
- **Status:** fixed in the working tree; authenticated health now exposes
  `protect_in_use`, Access-only deployments can report `ok`, and mapped
  Protect paths still degrade on disconnection.

### AUD-001 — Policy/incident mutations lacked attributable admin audit

- **Severity:** low
- **Confidence:** confirmed
- **Component:** REST API and dashboard audit trail
- **Files and lines:** audit helpers at `api_routes.py:52` and
  `api_routes.py:60`; mutations at `api_routes.py:183`, `api_routes.py:240`,
  and `api_routes.py:272`; dashboard mutation handlers in `web_routes.py`
- **Reproduction or failure scenario:** a Bearer key changed lockdown, a rule
  schedule, or lock mode; or a dashboard administrator added, toggled, deleted,
  or rescheduled an individual grant.
- **User impact:** operators could not attribute the administrative mutation to
  a named key record.
- **Root cause:** these routes either omitted admin audit or used only a
  non-unique API-key display name.
- **Proposed fix:** record dashboard username or stable API key `name#id`,
  never the Bearer secret; make post-mutation audit best-effort so an audit
  storage failure cannot misreport the mutation outcome.
- **Tests required:** success/error attribution, audit-write failure, dashboard
  policy mutations, and secret non-disclosure.
- **Dependencies or related issues:** none.
- **Status:** fixed in the working tree; unit coverage added.

### SEC-003 — Protect sessions are not bound to a persisted site namespace

- **Severity:** high
- **Confidence:** possible (the missing binding is confirmed; stable Protect
  identity and ID-collision behavior across supported firmware are unverified)
- **Component:** UniFi Protect authentication and topology
- **Files and lines:** `protect_client.py`; contrast the Access binding in
  `access_client.py`
- **Reproduction or failure scenario:** credentials or DNS are changed to a
  different Protect console whose camera identifiers overlap local mappings.
- **User impact:** events from the wrong site could be attributed to existing
  entry-device policy.
- **Root cause:** Access has a persisted authenticated namespace binding;
  Protect currently relies on the configured endpoint/account.
- **Proposed fix:** first verify a stable authenticated Protect
  console/application identity across supported versions, then bind before
  publishing sessions or topology. Until then, treat Protect host changes as a
  manual re-enrollment and mapping-review operation.
- **Tests required:** same-site reconnect/host move, wrong-site rejection,
  missing/changed identity schema, and overlapping camera IDs.
- **Dependencies or related issues:** UniFi firmware schema research and real
  split-console fixtures.
- **Status:** open; no speculative schema was added.

### SEC-004 — UniFi TLS peers are encrypted but not authenticated

- **Severity:** high
- **Confidence:** confirmed
- **Component:** Access session/Open API, Protect session/WebSocket
- **Files and lines:** `access_client.py:206-208`,
  `protect_client.py:52-54`
- **Reproduction or failure scenario:** an attacker becomes on-path between the
  app and UniFi and presents an arbitrary certificate.
- **User impact:** console credentials, Open API token, events, topology, and
  physical commands can be observed or impersonated.
- **Root cause:** typical local UniFi deployments use self-signed certificates,
  and the app has no CA enrollment or certificate-pinning workflow; hostname
  checking and certificate verification are disabled.
- **Proposed fix:** add an explicit trusted-CA or reviewed certificate-pinning
  workflow before enabling verification by default. Until then, isolate the
  management network and use least-privileged dedicated identities.
- **Tests required:** CA/pin enrollment, rotation, mismatch, expiry, host move,
  and recovery across REST/Open API/WebSocket sessions.
- **Dependencies or related issues:** the Access site namespace is not
  cryptographic peer authentication; SEC-003 covers the additional missing
  Protect binding.
- **Status:** accepted high-impact network-trust risk; documented, not fixed in
  this patch.

## Prioritized summary

| ID | Severity | Disposition | Residual decision |
|---|---|---|---|
| PHY-001 | Critical | Fixed in working tree | Official raw relay still does not prove bolt/contact position; tokenless safety acknowledgement remains unresolved |
| PHY-002 | Critical | Fixed; provenance regression passes | Real live Settings swap timing remains untested |
| PHY-003 | Critical | Fixed; latch regression passes | Requires authoritative relay evidence to clear |
| CMD-001 | High | Fixed in working tree | Hardware pulse timing and firmware response shapes require validation |
| HA-001 | High | Fixed in working tree | HA entity state is the confirmation boundary |
| HA-002 | High | Fixed in working tree | Force-kill can still interrupt in-process cleanup |
| CMD-002 | High | Fixed; current full suite passes | Real controller timing/concurrency remains untested |
| CMD-003 | High | Fixed; ambiguity/cancellation coverage passes | A physically accepted write cannot be rolled back by the app |
| CMD-004 | High | Fixed; same-entity ordering coverage passes | Per-entity workflow-lock map is bounded by configured topology in normal operation |
| CMD-005 | Medium | Fixed; hard-deadline coverage passes | Six-second window needs hardware timing validation |
| API-001 | High | Fixed in working tree | Private endpoint compatibility remains firmware-dependent |
| DB-001 | High | Fixed in working tree | Conflicting migrated rules are deliberately disabled for review |
| DB-002 | High | Fixed; real-SQLite race coverage passes | Multi-process writers remain unsupported |
| BAK-001 | High | Config/docs fixed | Isolated Supervisor backup/restore drill pending |
| PKG-001 | High | Packaging migrated; local builds pass | The published GitHub workflow was not executed locally |
| LIFE-001 | Medium | Partially fixed | Complete shutdown lacks one aggregate application deadline |
| LIFE-002 | High | Fixed; client-close regression passes | Real controller disconnect timing remains untested |
| LIFE-003 | Medium | Fixed and independently rechecked | Real live Settings swap timing remains untested |
| HA-003 | Medium | Fixed in working tree | Real HA reconnect timing remains untested |
| HA-004 | High | Fixed; stale-state regressions pass | HA/controller state is not independent mechanical proof |
| UI-001 | High | Fixed and independently rechecked | Cached HA state remains controller-reported, not mechanical proof |
| SEC-001 | Medium | Fixed in working tree | Existing weak environment keys are not silently rotated |
| SEC-002 | Medium | Fixed for new setup | Existing credentials retain backward compatibility |
| API-002 | Medium | Fixed in working tree | Monitoring must still inspect component detail |
| API-003 | Medium | Fixed in working tree | Protect usage is derived from durable mappings |
| AUD-001 | Low | Fixed in working tree | Audit is intentionally best-effort after the primary mutation |
| SEC-003 | High | Open | Requires stable Protect identity evidence before implementation |
| SEC-004 | High | Accepted risk | Requires a CA/pinning product design; isolate the management network |

## Implemented fix groups

| Fix group | Issue IDs | Result | Regression emphasis |
|---|---|---|---|
| Truthful physical-command outcomes | PHY-001–003, CMD-001, HA-001, CMD-003–005 | Separates acceptance, confirmed controller/HA state, and unknown; safety acknowledgement requires authoritative evidence | Tokenless rule echoes, malformed success, hard deadline, cancellation, unknown publication |
| Command ordering and client lifetime | CMD-002, CMD-004, LIFE-002–003, UI-001 | Per-entity workflows stay ordered while unrelated doors confirm concurrently; exact clients survive through readback | Reversed completions, Settings swaps, cancelled close, stale HA snapshot ordering |
| Durable safety recovery | HA-002, HA-004, LIFE-001 | Re-lock intent survives cancellation/restart; failed remote/re-lock paths invalidate stale state; shutdown work is bounded | Cancellation injection, overdue retry, remote failure, reconnect, teardown |
| API and controller validation | API-001–003, HA-003, AUD-001 | Strict mutation envelopes, structured HTTP 202 uncertainty, actionable health, optional Protect health, attributable best-effort audit | Rejection/ambiguity shapes, health aggregation, audit-storage failure |
| Policy persistence | DB-001–002 | Database uniqueness plus conservative migration; atomic enable and schedule updates | Real-SQLite concurrent insert/edit races and migration conflicts |
| Secret/setup hardening | SEC-001–002 | Salted versioned PBKDF2 verifier and new-setup strength floors | Legacy verifier upgrade, wrong key, minimum boundaries, Ingress setup |
| HA packaging and recovery contract | BAK-001, PKG-001 | Dockerfile-first multi-architecture build, version `1.6.0`, cold backup, 60-second stop allowance | YAML/release helper checks, local `linux/amd64` and `linux/arm64` builds/import smokes |

## Validation status

| Check | Status | Evidence/notes |
|---|---|---|
| Pre-change Python regression baseline | Pass | Lead recorded 371 passed, 15 subtests, 1 warning before this review patch |
| Focused changed-component regression set | Pass | 304 passed plus 8 subtests |
| Client/HA lifecycle and concurrency regression set | Pass | 68 passed plus 103 subtests |
| Current full Python regression suite | Pass | **446 passed, 111 subtests passed in 23.29s** on the final implementation tree |
| Adversarial test ordering | Pass | `event_dispatch → auth_engine`: 56 passed; `integration → auth_engine`: 49 passed |
| Python compile and Bandit | Pass | `compileall` and configured medium/confidence Bandit scan passed; Bandit emitted only `nosec`-comment warnings |
| YAML and shell parser checks | Pass | `yamllint`, YAML parsing, and `bash -n` passed |
| Formatter and static type checker | **Not run** | No repository formatter/type-checker configuration was found; no result is claimed |
| Local ShellCheck and Hadolint | **Not run** | Third-party container execution/mount was policy-blocked; `bash -n` is the recorded shell fallback, not an equivalent lint result |
| Python dependency validation | Pass | `pip check` plus runtime and development `pip-audit` passed |
| Frontend dependency/build check | Pass | Clean `npm ci`, `npm ls`, production build, and tracked-CSS no-diff check passed |
| Frontend vulnerability audit | Partial | Offline audit reported zero; online registry audit was policy-blocked, so current registry advisory coverage is not claimed |
| Clean container platform builds | Pass | Local `linux/amd64` and `linux/arm64` builds completed; labels report `amd64`/`arm64`, `app`/`1.6.0`, and isolated Python import smokes pass |
| Release utilities | Pass | Version/changelog extraction and release helper checks passed for the current working tree |
| Git whitespace validation | Pass | `git diff --check` reported no errors |
| HA custom-integration validation | N/A | This is a Supervisor app, not a custom integration; config-flow, entity-registry, and `hassfest` integration checks do not apply |
| Disposable Supervisor install/Ingress/lifecycle smoke | **Not run** | Requires an isolated Home Assistant Supervisor environment |
| Isolated Home Assistant cold backup/restore | **Not run** | Requires a disposable Supervisor environment |
| Real UniFi Access/Protect and physical-door validation | **Not run** | No production lock, relay, alarm, or controller command was issued |
| Published CI/release workflow | **Not run** | Local equivalents and images passed; no remote workflow or registry publication was triggered |
| Independent fresh-agent verification | Pass | Initial findings UI-001/LIFE-003 plus cancellation and test-isolation follow-ups were fixed; final recheck found no new runtime release blocker |

Final command transcript highlights (focused invocations, dependency audits,
frontend commands, and two Docker platform builds were also run):

```bash
cd access_control/rootfs/opt
.venv/bin/pytest access_control/tests -q
.venv/bin/pytest access_control/tests/test_event_dispatch.py access_control/tests/test_auth_engine.py -q
.venv/bin/pytest access_control/tests/test_integration.py access_control/tests/test_auth_engine.py -q
cd ../../..
python3 -m compileall -q access_control/rootfs/opt/access_control
access_control/rootfs/opt/.venv/bin/yamllint .
bash -n access_control/rootfs/run.sh
bash -n .github/scripts/release-utils.sh
bash .github/scripts/release-utils.sh self-test
git diff --check
```

## Remaining risks and validation boundaries

- **Physical truth:** official Access relay and HA entity state are controller
  observations, not door-contact, latch, mechanical-bolt, jam, or egress proof.
- **Tokenless behavior:** private rule-derived state remains useful for
  conservative convergence, but cannot release the fail-safe latch or
  acknowledge lockdown safety. When authoritative safety acknowledgement is
  pending, health remains critical/unresolved and the app reasserts the safe
  direction until authoritative evidence is available.
- **Accepted-unconfirmed writes:** a mutation may already have opened, locked,
  or restored a schedule. The app publishes unknown and suppresses grant-only
  side effects, but an operator must inspect Access and the physical opening.
- **UniFi compatibility:** private endpoints and even official response timing
  are firmware-sensitive. Supported controller-version matrices and real relay
  timing have not been proven by these mocked tests. A neutral private
  fire-and-forget response with no recognized marker is accepted on HTTP 2xx.
  Current official Ubiquiti pages also disagree on Open API port `12445` versus
  `12455`; this build uses `12445`, and the real controller preflight must
  record the actual endpoint.
- **Protect identity:** SEC-003 remains open.
- **Protect health aggregation:** optionality is derived from durable
  Protect-doorbell mappings; monitor both `protect_in_use` and
  `protect_connected`.
- **TLS:** UniFi TLS peer verification remains disabled for self-signed/local
  deployments. Site-namespace checks do not replace certificate validation.
- **Shutdown:** manager work is bounded, but the entire 60-second teardown is
  not under one aggregate deadline.
- **Cold-backup outage:** while Supervisor stops the app, it cannot receive
  events, execute a due re-lock, retry lockdown/sync, or serve health.
- **Supply chain:** direct Python requirements and actions are pinned, but
  transitive Python hashes, the HA base-image digest, image signing/SBOM, and a
  current online frontend-registry audit remain follow-up hardening.

## Upgrade and migration notes

- The database migration establishes one individual rule per user/lock.
  Identical duplicates retain the oldest policy; conflicting duplicates retain
  one disabled, schedule-cleared row for administrator review.
- A matching legacy raw-SHA environment-key fingerprint is upgraded in place
  to a salted PBKDF2 verifier without changing the actual encryption key.
- `build.yaml` is intentionally removed. The Dockerfile now selects Home
  Assistant's generic multi-architecture Python base and is the image source of
  truth.
- The app requests a cold Supervisor backup and a 60-second stop timeout.
- Known accepted-but-unconfirmed native lock-mode writes now return HTTP 202
  rather than a generic 503; clients must handle the structured result.

## Release recommendation and changelog scope

The safety, API, migration, packaging, and backup behavior changes justify a
minor release. The working tree is versioned as `1.6.0` rather than another
`1.5.x` patch. Release notes call out:

- authoritative official-relay requirements for fail-safe/lockdown and native
  momentary grants;
- the `accepted_unconfirmed`/HTTP 202 contract and suppressed auto-disarm;
- exact HA unlock confirmation and cancellation-safe durable re-lock cleanup;
- the one-rule-per-user/lock migration behavior;
- cold-backup downtime and post-restart checks;
- current HA builder/base-image migration; and
- the still-open physical, Protect-identity, TLS, and controller-version
  validation limits.

## Production recommendation

**Conditional GO for an isolated, supervised canary; NO-GO for broad
unattended production today.**

The canary should use an official Access Open API token, a dedicated
least-privileged UniFi identity, an isolated management network, a non-critical
opening, direct human observation, and alerting on critical health,
accepted-unconfirmed commands, and overdue re-locks. Before that canary,
complete the disposable Supervisor cold-backup/restore drill and the
controller/relay timing matrix in the next-actions section.

Broad unattended production remains a no-go until real hardware/controller
validation is recorded and the deployment either implements TLS CA/pinning or
formally accepts SEC-004 on a demonstrably isolated network. Protect-backed
event deployments also need SEC-003 resolved or an explicit site-binding risk
acceptance. Neither official relay state nor HA entity state proves mechanical
bolt/contact position, so life-safety, egress, and code compliance remain an
installer/hardware responsibility.

## Feature roadmap

Feature ideation began only after the fix pass, full regression suite, and
independent verification completed. The ranking favors truthful observation
and operational safety over adding more ways to open a door.

The current implementation has source- and fixture-validated code paths for
official Access door listing, lock-rule read/write, and controller relay
status; no live controller was used. It does **not** prove an API schema for
independent door contact, latch/bolt/jam, request-to-exit, reader health,
battery, or Protect site identity. Ubiquiti documents
[door-position and request-to-exit hardware](https://help.ui.com/hc/en-us/articles/25689847509783-Understanding-UniFi-Access-Control-Hub-Input-and-Output-Terminals),
but hardware capability is not evidence that the installed controller exposes
stable telemetry. Those proposals remain gated on read-only fixture capture
from supported firmware.

Complexity uses S, M, L, and XL relative to this codebase. P0 is the highest
roadmap priority, P1 is the next product increment, P2 is useful after
capability validation, and P3 is demand-driven. A release/canary gate applies
only where its row says so explicitly.

### Quick wins

| Rank | Feature and user problem / real-world use | Required API capability and architecture | Safety and security | Complexity and testing | Backward compatibility | Priority and placement |
|---|---|---|---|---|---|---|
| Q1 | **State evidence and confidence view.** During an incident, an operator needs to know whether `locked`, `unlocked`, or `unknown` came from HA, official relay readback, a legacy rule inference, or an accepted-but-unconfirmed write, and how old it is. | No new upstream API. Add a read-only observation DTO with state, source, observation time/age, relay-authority flag, and an explicit `physical_position_known: false`; expose it in the UI/API. | Never label HA/relay evidence as mechanical lock, latch, or contact proof. Redact identifiers for low-privilege scopes. | **S–M.** Test provenance, stale/unknown transitions, tokenless evidence, out-of-order updates, swaps, scopes, and wording. | Additive fields and UI; command behavior is unchanged. | **P0, core.** |
| Q2 | **Redacted readiness/support bundle.** Installers need a shareable pre-canary artifact without disclosing the database, credentials, PINs, people, or movement history. | Reuse health, `/api/debug`, versions/schema, read-only topology counts, and token readiness. Admin-only JSON/ZIP generator; never include the raw database. | Exclude names, emails, upstream IDs, hosts, tokens, cookies, PINs, hashes, full certificate fingerprints, and raw events by default. Bound size and error text. | **S–M.** Plant secrets/PII in golden fixtures, scan output, test size limits, malformed state, auth/CSRF, and offline generation. | Entirely additive. | **P0, core.** |
| Q3 | **Transition-based HA safety events.** Automations need reliable alerts when health becomes critical, Open API readiness is lost, a fail-safe latch activates, or a command becomes accepted-unconfirmed. | Existing HA REST event API; no new UniFi API. Add a central edge-triggered publisher with event IDs/dedup while retaining SQLite audit when HA is down. | Avoid event storms and person/credential data. Events describe software/controller observations, never physical closure. | **S–M.** Test reconnect flaps, repeated retries, HA outage/recovery, redaction, shutdown, and every uncertainty path. | New opt-in events; existing event names remain stable. | **P1, core.** |
| Q4 | **Read-only compatibility, permission, and endpoint report.** Before a canary, an operator needs per-check pass/fail/unknown for endpoint, schema, device, and evidence support without actuating a door; the conflicting official `12445`/`12455` references make this concrete. | Use authenticated GETs only. Permit an explicit numeric Open API port constrained to the configured Access host; never infer `edit:space` from successful reads and report it as unknown until a deliberate command. | The token must never be sent to an arbitrary host or discovered redirect. The probe must contain a hard no-mutation assertion. | **S–M.** Fixtures for both documented ports, unavailable endpoint, supported/unknown envelopes, empty site, site mismatch, tokenless mode, and proof no mutator ran. | Default remains `12445`; new setting/report is additive. | **P0, core; a manual equivalent is the canary gate until this is productized.** |

### High-value medium effort

| Rank | Feature and user problem / real-world use | Required API capability and architecture | Safety and security | Complexity and testing | Backward compatibility | Priority and placement |
|---|---|---|---|---|---|---|
| M1 | **Per-door active, opening-disabled, monitor-only, and dry-run policy.** Commissioning or maintenance may need policy evaluation without opening a door, or may need to block every opening direction while keeping safe-direction recovery. | No new upstream API. Add one durable command-policy gate used by credential, dashboard/API, remote mirror, hub sync, schedule restore, lockdown, and re-lock paths. Dry-run records `would_grant`; opening-disabled still permits safe-direction lock/recovery. | Entering monitor-only with a pending re-lock, hold-open, or unresolved override can strand an unsafe state, so activation must be blocked or require confirmed safe convergence. Dry-run must never fire grant events or disarm. | **M–L.** Exhaustively cover every write entry point, restart, lockdown, pending work, client swap, schedules, and policy races. | Default `active` preserves behavior; modes are per-door opt-in. | **P1, core.** |
| M2 | **Independent door contact plus held-open/forced-open alerts.** Users need to distinguish “relay says locked” from “door leaf is open” and alert on a genuine contact condition. | **Unverified.** Require a stable independent contact snapshot/event with door ID and timestamp from supported Access firmware, or an explicitly mapped HA `binary_sensor`. Relay/rule/grant state is insufficient. Add a separate contact-observation model and restart-safe alert timers. | Unknown/stale contact is unknown, never closed. Do not use these alerts as certified life-safety evidence or as unlock authorization. | **M after capability proof.** Hardware/firmware fixtures; ordering, missed events, snapshots, stale sensors, timer restart, duplicates, and forced-open correlation. | Disabled until explicitly mapped; additive. | **P1 if proven; core model with optional per-door source.** |
| M3 | **Granted, denied, and request-to-exit activity/triggers.** Operators need denial investigations and exit automations without treating observational events as requests for this app to unlock. | **Unverified across firmware.** Require stable event types, result semantics, IDs, and optional actor data. Add a neutral ingestion path, dedup, bounded retention, and HA events separate from authorization. | Denied/REX events must never enter the grant engine. Minimize identity by default and make attribution/retention explicit. | **M.** Real captured fixtures, schema fuzzing, missing actors, duplicate/reordered reconnects, privacy tests, and hard proof observational events cannot actuate. | Additive, with attribution opt-in. | **P2 after fixture validation, core event layer.** |
| M4 | **Reader, hub, and door-device availability.** Aggregate connectivity can be healthy while one reader/hub is offline and users are about to be locked out. | Protect camera `isConnected` exists. Stable Access reader/hub connectivity, firmware, power, and battery fields are **unverified**; many conventional powered hubs have no useful battery metric. Add per-device observations with age and topology lifecycle. | Offline must not mean locked or closed. Hide serials/MACs from low-privilege scopes. | **M.** Poll/event reconciliation, disappearance, stale state, partial failure, reconnect, identifier reuse, and authorization scopes. | Additive observation fields. | **P2; core health model, hardware-specific fields optional.** |

### Strategic larger work

| Rank | Feature and user problem / real-world use | Required API capability and architecture | Safety and security | Complexity and testing | Backward compatibility | Priority and placement |
|---|---|---|---|---|---|---|
| S1 | **Trusted-CA or reviewed certificate-pinning enrollment.** Current TLS encrypts but does not authenticate UniFi peers, so an on-path attacker can impersonate a controller. | No REST feature required; needs certificate/chain access and an operator-review or CA workflow. Add per-endpoint trust across Access REST/Open API/WebSocket and Protect, including enrollment, rotation, expiry, host move, and recovery. | Fail closed on mismatch while preserving an authenticated recovery path. Never silently trust a changed pin; TOFU requires explicit review. | **L.** Test enrollment, mismatch, expiry, rotation, split consoles, reconnect, backup/restore, and lockout recovery. | Stage explicit current “unverified” mode before any default change. | **P0 before broad production, core security.** |
| S2 | **Protect site-namespace binding.** A changed or misdirected Protect host can reuse camera IDs and route events through old mappings. | **Unverified.** First identify a stable authenticated Protect console/application identity across supported firmware. Persist/namespace it and reject candidates before callbacks/topology publication. | Prevents wrong-site credential events from reaching policy. Hostname or display name is not sufficient identity. | **M–L.** Same-site reconnect/host move, wrong-site collision, missing/changing identity, split consoles, migration, and restore. | Existing Protect mappings require one reviewed enrollment. | **P0/P1 for Protect deployments, core.** |
| S3 | **Native Home Assistant companion integration.** Users want devices, sensors, repair issues, availability, and device/automation triggers rather than only Ingress, REST, and raw events. | No new UniFi API. Requires a stable least-privilege observation API from this app, initially polled and optionally followed by a read-only event stream. Build a separate custom integration; this app remains the sole command/safety authority. | Store a scoped key in HA, do not duplicate command logic, and expose evidence source so relay never masquerades as physical contact/bolt state. | **L.** HA config-entry setup/unload/reauth, coordinator, entity/device registry stability, unavailable/stale state, triggers, upgrade, and missing-app tests. | Existing app users are unaffected. | **P2, separate optional component.** |
| S4 | **Multiple Access controllers/sites.** Multi-building users need one policy/monitoring surface without identifier collisions or false aggregate lockdown success. | Stable authenticated identity for every Access site; Protect identity is prerequisite where used; capabilities are recorded per controller. Namespace every user/location/device/mapping/audit/dedup key and add client pools plus partial-failure policy. | Cross-site user merging must be explicit. A partial lockdown can never be reported complete, and controller isolation must bound command blast radius. | **XL.** Mixed firmware, ID collisions, partial outages, rotation, cross-controller dedup, migration/rollback, and a multi-site hardware matrix. | Singleton remains default; migration is explicit and reversible. | **P3 demand-driven; core data model if built.** |

### Not recommended

| Proposal and user appeal | Required capability, architecture, and safety disposition | Complexity, testing, compatibility, priority, and placement |
|---|---|---|
| Infer door-open, bolt, latch, jam, or “secure” state from HA lock state, Access rules, relay status, or grant success for a simpler dashboard | An independent physical sensor is absent; these signals answer different questions. No architecture can make the inference truthful, so preserve separate evidence domains. | Technically **S** but unsafe. Regressions must continue proving rule/relay/HA evidence cannot promote physical truth. No compatibility change. **P0 reject; neither core nor optional.** |
| Automatically retry unlock or issue a blind compensating command after an ambiguous mutation to make a failed-looking command “work” | Requires an upstream idempotency key or operation-status API, neither of which is demonstrated. The first write may already have opened the door, while `reset` may resume a schedule. Keep unknown/accepted-unconfirmed and deliberate recovery. | Technically **S–M** but unsafe. Preserve timeout/reset/cancellation tests and the single-write invariant. No compatibility change. **P0 reject.** |
| Build a second app-owned scheduled hold-open engine for richer calendars | Would require a durable transactional upstream schedule API with authoritative readback. Crash, backup stop, partition, or clock error can strand an opening; UniFi should remain schedule owner. | **L** and high operational risk. Existing restart/ownership tests cannot eliminate upstream-outage risk. No compatibility change. **Reject for core; reconsider only if the missing API contract appears.** |
| Fail open during HA/controller outage, or silently fall back from a configured official token to private mutation for availability | No API can provide trusted confirmation while unreachable, and fallback crosses the explicit token security/capability boundary. It would undo the fail-safe design. | Technically **S** but unacceptable. Keep outage, lockdown, and no-fallback regressions. No compatibility change. **P0 reject; no component.** |
| Export raw people, credentials, PINs, event payloads, or long-term movement history by default for support/analytics | No new upstream API is needed, but the architecture would expand storage/export of high-sensitivity security and privacy data. Q2 redaction and optional scoped M3 attribution solve the legitimate use cases. | **S–M** but disproportionate privacy risk. Maintain planted-secret/redaction and retention tests. No compatibility change. **Reject as default/core behavior.** |

Before implementing M2–M4 or S2, capture read-only fixtures from every
supported controller/firmware family for door details, event taxonomy, device
health, and Protect identity. An unused JSON field remains an unknown
capability until its semantics and lifecycle are verified.

## Next three actions

1. **Run a disposable Supervisor recovery drill.** Install `1.6.0` in an
   isolated Home Assistant instance, exercise setup/Ingress/start-stop/restart,
   create a cold backup, restore it, and verify schema 26, lockdown, pending
   re-locks, sync ownership, secrets, and UI/API health. Use fake upstreams; no
   physical command is needed.
2. **Execute an explicitly authorized non-critical hardware matrix.** Record
   console, Access/Protect, hub/reader, and HA versions; actual Open API port;
   read/write envelopes; relay and HA convergence timing; network loss;
   reconnect; and Settings replacement. Only a human-observed test opening may
   receive lock/unlock commands, under a separate approval and rollback plan.
3. **Close or formally accept the production trust gates.** Implement S1
   CA/pinning, establish S2 Protect identity where Protect is used, or record
   narrowly scoped risk acceptance on an isolated management network. Then cut
   the `1.6.0` canary and monitor critical health, accepted-unconfirmed
   outcomes, and overdue re-locks before considering broader rollout.
