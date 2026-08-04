# Changelog

All notable changes to this app are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-08-04

### Added

- Home Assistant WebSocket push for bidirectional hub sync. The HA client now
  maintains a `state_changed` WebSocket subscription (Supervisor
  `/core/websocket`, or `/api/websocket` on a direct HA URL), authenticated
  with the existing token and reconnecting with 5s→300s jittered backoff that
  resets only after 30 s of stable connection; `auth_invalid` is treated as
  transient Supervisor token rotation, not a terminal failure. Lock state
  changes wake hub-sync reconciliation immediately through a coalesced
  single-flight pass — an event burst across many doors collapses into one
  pass plus at most one trailing pass — and saving lock settings likewise
  wakes a pass, so enabling sync at runtime converges immediately. Push
  events are wake-up hints only; authenticated readback remains authoritative.

### Changed

- With push available, the hub-sync 5-second HA REST poll relaxes to a
  60-second reconciliation backstop, used only while the HA WebSocket is
  connected, HA REST health is good, and no deferred work (pending releases,
  failure backoffs, flap suspensions, momentary leases, app-initiated
  markers, min-apply deferrals) is waiting; anything else returns to the full
  five-second cadence. This replaces roughly 17,000 HA REST polls per lock
  per day with push wakes plus a drift-bound backstop and cuts reaction
  latency to HA-side lock changes from up to 5 s to near-immediate.
- The app-initiated-unlock marker TTL was raised from 15 s to 75 s (backstop
  interval plus pass slack): with a lost push event the unlock edge is first
  observed by the next backstop pass, and an expired marker misclassified a
  deliberate operator hold-open as an external unlock, scheduling a spurious
  auto re-lock.
- Hub-sync shutdown now owns the push-reconcile task: new wakes are refused,
  the queued trailing pass is cleared, and the in-flight pass is cancelled
  and awaited before app-owned holds are released, so a late push event can
  never re-drive a hub from an exiting process.

### Fixed

Highlights of the 2026-08-04 end-to-end review remediation (31 findings
fixed; the full report is
[docs/END-TO-END-REVIEW-2026-08-04.md](../docs/END-TO-END-REVIEW-2026-08-04.md)):

- A transiently failed hub drive of a genuine HA unlock (or Access schedule
  mirror) no longer records the divergent observation as the confirmed
  baseline; the next pass re-arbitrates with the original origin and retries
  after backoff instead of misclassifying the unchanged divergence as a
  concurrent conflict and physically re-locking the door.
- Lockdown enable persists write-ahead, before awaiting the global
  command-barrier drain, so a crash or watchdog restart between the
  operator's enable and the barrier wait no longer comes back up with
  lockdown off mid-incident.
- Protect REST calls clear auth state and retry once on 401 instead of
  silently returning empty lists forever after session expiry, and the
  Protect WebSocket frame parser honors the deflate flag and decompresses
  payloads — compressed door/ring/NFC events were previously dropped as
  parse errors while the connection reported healthy.
- The HA-outage fail-safe `keep_lock` is driven once per outage per pairing
  (was once per 5-second poll: hub command plus durable write plus audit row
  each time), and steady-state convergence skips the durable per-entity
  write when desired state, rule, and pairing are unchanged.
- SQLite: removed a migration cycle that rewrote the `api_keys` table on
  every startup, set `PRAGMA synchronous=NORMAL` alongside WAL on all
  writer connections, pruned stale never-locked-out rate-limit rows, and
  added per-tap lookup indexes (migrations 28–29).

### Security

- Closed a stored XSS in the group-detail remove-member confirm by moving
  the group name out of the inline `onsubmit` JS string into a data
  attribute.
- CSRF token identity now resolves with the same precedence as the
  validators (Ingress SSO first), the session cookie is no longer re-signed
  under Ingress, and the cookie `Secure` flag is derived from the request,
  so plain-HTTP direct-port logins no longer loop.
- Dependency bumps for six known CVEs: aiohttp 3.14.1 → 3.14.3
  (CVE-2026-59881, CVE-2026-69243, CVE-2026-69244) and cryptography
  48.0.1 → 50.0.0 (CVE-2026-69247, CVE-2026-69248, CVE-2026-69249).

## [1.7.1] - 2026-07-27

### Fixed

- Bidirectional hub sync no longer misreads its own most recent hub drive as
  an external Access rule change. `_persist_convergence` records a
  `command:<state>` marker (not a real rule fingerprint) into the baseline
  used for next-poll comparison; comparing it against the following poll's
  actual JSON fingerprint was always spuriously unequal, and — if Home
  Assistant also changed in that same window — fell through to
  `concurrent_conflict`, reverting a legitimate unlock issued right after a
  lock. `_reconcile_bidirectional` now recognizes that marker and derives
  the Access-side change from `access_state` alone for that one comparison,
  leaving fingerprint-based external-change detection unchanged for every
  baseline that came from a real observation. This also repairs the same
  spurious-`access_changed` misread on the first poll after **every app
  restart**, not only after an in-memory drive: `_persist_convergence`
  wrote the `command:<state>` marker to SQLite and `_load_persisted_sync_state`
  restored it verbatim, so a restart shortly after a drive carried the same
  poisoned baseline into the next process.
  - Known, accepted limitation: this weakens external-change *detection* to
    *arbitration* for the one poll immediately following our own drive. An
    Access rule change within the same effective state (e.g. an admin's
    `keep_lock` replaced by our own `keep_unlock`, both `"locked"` as far
    as `access_state` is concerned) is invisible to the state-only
    comparison; if HA also changed in that same window, the pass can
    resolve to `source="ha"` instead of `concurrent_conflict`, and the
    relay is driven by HA's desired state even though Access-side intent
    also moved. This can never hide a locked/unlocked divergence and so
    cannot revert a genuine unlock or mask a lockout — it only affects
    which side's rule wins when both change within the same state on that
    one poll. The proper fix (threading the confirmed readback rule/state
    through `_HubDriveResult` so a real fingerprint is built instead of
    `f"command:{desired}"`) is a filed follow-up, not part of this change.
- Bidirectional hub sync no longer treats a Z-Wave/Zigbee deadbolt's
  transitional `unlocking`/`locking` report as an untrusted state. A bolt
  mid-throw was falling into the `untrusted_state` fail-closed branch,
  latching the entity into the fail-safe reset set and driving a
  just-completed unlock back closed on both sides (field data for
  `lock.back_door`: unlock transitions normally complete in 0.5-2.0s, but
  one observed transition took 7.69s — long enough for a 5s poll to land
  mid-throw). `_reconcile_bidirectional` now makes no convergence decision
  for an entity reporting `unlocking`/`locking` — no drive, no latch, no
  mutation of the observed baselines — for up to a new bounded
  `_HA_TRANSITION_GRACE` (30s) window, timed from when the entity was first
  seen transitional and cleared as soon as a valid `locked`/`unlocked`
  state is observed. An entity still transitional past the grace window
  falls through to the existing `untrusted_state` fail-closed path exactly
  as before, and an entity already inside an active fail-safe incident is
  never paused by a transitional reading — locked-wins enforcement
  continues unchanged. The recorded start time is now cleared by *any*
  non-transitional reading (a genuinely invalid one, e.g.
  `unavailable`/`unknown`, as well as a valid one) rather than only a
  valid `locked`/`unlocked` reading, and by an entity leaving the synced
  set (`_drop_tracking`), so a stale start time from an earlier, unrelated
  transition can never make a brand-new transition's grace window appear
  already expired. It is deliberately *not* cleared by
  `_prepare_pairing_change`: unlike `_drop_tracking`, that method re-runs
  on every poll for as long as a stale hub's release keeps failing, so
  clearing it there would re-arm the window each poll and a stuck bolt
  would never fail closed.
- Hub sync now logs the transitional-state deferral path: a debug line
  once when an entity first enters the grace window, and a warning if it
  is still transitional once the window expires and the entity is failed
  closed. This branch previously wrote nothing to either the DB or the
  logs — the only convergence outcome invisible in both channels.

## [1.7.0] - 2026-07-22

### Added

- Opt-in per-lock setting **Keep hold-open across graceful restarts**
  (`preserve_hold_on_restart`, shown when hub sync is on, off by default).
  Because `backup: cold` gracefully stops/starts the app on every backup,
  recovery previously fail-closed any app-owned `keep_unlock` hold — a door
  deliberately held open re-locked itself after each backup. With the opt-in,
  a graceful shutdown leaves the hold physically in place and records a
  single-use, time-bounded clean-shutdown marker; startup recovery re-adopts
  the hold only after readback proves Home Assistant still reports the
  deadbolt unlocked and the Access door still reports `keep_unlock`. Unclean
  exits, stale or unreadable markers, lockdown, opt-out while stopped, failed
  readback, and the failed-startup shutdown path all keep the existing
  fail-closed (`keep_lock`) recovery behavior. Adds locks-table migration 27
  and `Database.delete_config`.

## [1.6.1] - 2026-07-18

### Fixed

- The per-entity command lock is now released even when barrier release or
  the HA operation-lease close is cancelled mid-cleanup; previously a
  cancellation at that point could permanently wedge every later command and
  pending re-lock for that door.
- The hub-sync write-ahead freshness guard no longer runs the progressive
  ~5s relay-lag observation window while holding the global physical-command
  barrier. It now takes a single time-bounded read and suppresses the
  HA-origin unlock (fail-safe) on any ambiguity, so a slow or lagging hub
  cannot stall commands for unrelated doors.
- Restored the missing runner in `test_lockdown_enforcement_unaffected`,
  which previously passed without executing its lockdown-enforcement
  assertions.

### Documentation

- Synchronized the reference docs ([Architecture](../docs/ARCHITECTURE.md),
  [Operations](../docs/OPERATIONS.md), [Security model](../docs/SECURITY-MODEL.md),
  [Development](../docs/DEVELOPMENT.md)) with the behavior changes shipped in
  1.5.6 through 1.5.10: hub-sync damping scope, the removed legacy Access
  lock-rule API and its retry/backoff behavior, static-asset cache-busting and
  Ingress path resolution, the official Open API's empty rule type for idle
  doors, and CSRF-protected sign-out.

## [1.6.0] - 2026-07-18

### Changed

- Access commands now distinguish a controller-accepted write from an
  authoritatively confirmed relay state. Native momentary unlocks require an
  unlocked readback from the official Access Open API before authorization is
  granted or an alarm is automatically disarmed; persistent lock and unlock
  paths likewise surface `accepted_unconfirmed` (HTTP 202 on API paths) when a
  write succeeds but its resulting state cannot be proved. The global physical
  command barrier is released after the write and before bounded readback, so
  confirmation latency on one door does not block unrelated doors; a shared
  per-entity lock still preserves write/readback order for the same door.
- Health reporting now marks unresolved safety states as `critical` and
  upstream disconnects, open circuit breakers, and an unavailable configured
  Open API as `degraded`; optional Protect connectivity affects the aggregate
  only when a configured doorbell path uses it. Lockdown, lock-mode, and
  individual access-rule mutations now produce attributable admin audit
  entries without audit-storage failures obscuring the mutation result.
- Home Assistant packaging now uses the 2026.04+ Dockerfile-first generic
  multi-architecture builder flow and the Python 3.12 Alpine 3.24 base image;
  the obsolete `build.yaml` and `BUILD_FROM` build argument are no longer
  required.
- Development dependencies now use `httpx2` for compatibility with the current
  Starlette test client.

### Fixed

- Re-lock intent is persisted before unlock side effects and retained across
  task cancellation, uncertain confirmation, restart recovery, and retry
  paths, preventing cancellation from silently dropping a safety-critical
  re-lock.
- Hub synchronization now treats only official Open API relay readback as
  independent Access state evidence. Legacy rule acknowledgements cannot
  release the locked-wins fail-safe latch or satisfy lockdown confirmation.
  Relay authority remains attached to the exact client that produced it across
  live Settings replacement, and external rule supersession cannot clear the
  fail-safe latch before both sides are authoritatively locked.
- Mutation timeouts, connection resets, malformed success envelopes, and
  post-acceptance cancellation now preserve truthful `unknown` state and
  accepted-unconfirmed audit evidence. Native confirmation has one hard
  six-second wall-clock budget, while an in-flight accepted operation leases
  its client through readback so replacement cannot resurrect a retired
  session.
- Remote mirroring, durable re-lock failures, and HA disconnects invalidate
  stale command state. The Locks page orders cached HA snapshots and confirmed
  command observations by monotonic acquisition time, so a pre-command
  snapshot cannot overwrite a newer result while later HA observations still
  capture external changes. Same-entity command flows remain ordered through
  confirmation.
- HA physical workflows now lease the exact client that issued the write
  through state readback. Live Settings replacement publishes the tested new
  client atomically, drains the retired client outside the global write
  barrier, and prevents a closed client from recreating an unowned session.
  Client close cleanup now finishes through caller cancellation before
  propagating it.
- Home Assistant connection probes now update circuit-breaker state, stale
  while-revalidate tasks are lifecycle-owned, and manager teardown is bounded
  so shutdown can make deterministic progress within the Supervisor grace
  period.
- Access rules now have a database-enforced unique `(user_id, lock_id)`
  invariant, closing concurrent duplicate-creation races. Enabled toggles and
  schedule edits use separate atomic SQL updates so a stale concurrent
  schedule save cannot re-enable a disabled grant.

### Security

- Newly created admin accounts require a password of at least 12 characters,
  and new environment-backed setups require a secret key of at least 32
  characters.
- Stored secret-key verifiers now use a salted, versioned PBKDF2-SHA256 format.
  A matching legacy unsalted fingerprint is migrated only after successful
  verification.
- Private Access mutation responses now reject malformed envelopes and explicit
  controller failure markers instead of treating every HTTP success as an
  accepted command.

### Compatibility and migration

- An Access Open API token is required for authoritative native relay
  confirmation. Without one, a controller-accepted native command is reported
  as unconfirmed and does not trigger authorization-dependent side effects.
- Database migration 26 deduplicates existing access rules conservatively:
  identical duplicates keep the oldest row, while conflicting duplicates keep
  the oldest row disabled with its schedule cleared. Review disabled rules
  after upgrading if the database previously contained duplicates.
- Backups are now declared `cold` because SQLite WAL state includes durable
  re-lock and lockdown ownership. Home Assistant Supervisor stops the app
  during backup, so access-control automation is unavailable for that interval.

### Known limitations

- Access relay and Home Assistant entity state are controller observations,
  not independent door-contact, latch, mechanical-bolt, jam, or egress proof.
- Protect sessions are not yet bound to a persisted site namespace. Review
  camera mappings after a Protect host change.
- UniFi TLS uses encryption without peer verification for common self-signed
  local deployments. Keep the management network isolated until a trusted-CA
  or reviewed certificate-pinning workflow is available.
- Controller/firmware response timing, the current Open API port, physical
  relay behavior, and Supervisor cold-backup restore still require validation
  on a disposable deployment before broad unattended use.

## [1.5.12] - 2026-07-14

### Fixed

- A bidirectionally synced lock could get stuck re-locking itself after every
  unlock on current UniFi Access firmware. That firmware reports the door relay
  state several seconds after it accepts a rule write, and it self-clears a
  momentary `lock_now` to `reset` while the relay is still actuating. The
  previous confirmation window was shorter than a second, so a normal unlock or
  lock command frequently could not be confirmed in time. When the lock
  direction failed to confirm, the locked-wins fail-safe latch never released —
  even though both sides were in fact locked — and every subsequent unlock from
  anyone was reverted within one poll (~5 s), indefinitely, until the add-on was
  restarted. Three changes fix it: the Access rule-write confirmation and the
  hub-sync relay observation now wait on a bounded progressive window (~5 s
  total) instead of a fixed sub-second loop, so a slow-to-report relay is given
  time to settle; the confirmation now understands that an observed `reset` rule
  right after a momentary lock is the documented post-execution state and relies
  on the relay reading locked for its positive evidence; and the fail-safe latch
  now releases as soon as a poll independently observes both sides locked, so a
  command whose confirmation keeps failing can no longer wedge the pair. An
  unconfirmed command still fails closed, locked-wins conflict resolution is
  unchanged, and lockdown enforcement is untouched. When a rule write is accepted
  but the relay never reaches the expected state, the error now says so
  explicitly ("rule accepted but relay did not report ... within Ns").
- The physical-command barrier is now released before the extended Access relay
  confirmation waits (as the Home Assistant re-lock path already did), so a
  single slow-to-actuate hub cannot stall commands to unrelated doors for the
  whole confirmation window.

### Added

- `GET /api/health` now reports `hub_sync_fail_safe`: the HA entity IDs whose
  bidirectionally synced pair is currently held by the locked-wins fail-safe
  latch. A non-empty list means unlocks on those locks are being reverted until
  both sides confirm locked, so a stuck latch is visible instead of silent.

## [1.5.11] - 2026-07-13

### Fixed

- A timed buzz or device-auth unlock on a bidirectionally synced HA lock no
  longer mints a persistent Access `keep_unlock` override. Both paths now lease
  the same momentary hold the remote-unlock path already used, so the hub
  poller treats the temporary HA-unlocked window as app-owned instead of
  echoing it back as a persistent rule — which also stops a routine buzz on a
  busy door from burning flap budget and tripping flap suspension. Unsynced
  locks and the remote path are unchanged.
- Live re-lock timers are now bounded by a monotonic clock captured when they
  are armed, in addition to the durable wall-clock deadline. A backward NTP or
  DST step can now only shorten an open-door window (re-locking sooner, the
  fail-safe direction) and can never silently extend it. The persisted
  wall-clock deadline remains authoritative for cross-restart recovery, and
  rehydrated, swept, and resumed rows keep pure wall-clock behaviour.
- A re-lock that stays overdue is no longer silent after the first failure. The
  failure event now re-fires on a bounded (~10 minute) per-entity cadence while
  the sweep keeps retrying, `/api/health` reports `pending_relocks` counts
  (total and overdue, no entity IDs so the low-privilege read stays
  scope-safe), and the Locks page shows a "re-lock pending" / "re-lock overdue"
  badge on affected lock cards.

### Added

- New per-lock setting "Auto re-lock after external (thumb-turn / HA) unlocks"
  (`relock_on_ha_origin`, default off). When enabled on a bidirectionally
  synced lock, an unlock that originates on Home Assistant's side (a thumb-turn
  or HA automation) schedules a durable, time-bounded re-lock. App-initiated
  unlocks are excluded: a manual dashboard Unlock stays held open, an
  authorized credential tap on a lock with auto re-lock disabled keeps its
  chosen hold-open semantics, and a buzz, device-auth, or remote unlock that
  already owns its timer is never double-scheduled. With the setting off,
  behaviour is unchanged.

## [1.5.10] - 2026-07-13

### Fixed

- Access API token validation no longer fails against a console whose first
  door has no active lock rule. The Open API answers a rule read on an idle
  door with an empty rule type (`{"type": "", "ended_time": 0}`); the strict
  parser rejected that as an unknown rule type, which failed Test & Save for
  valid tokens and would have failed every hub-sync readback of an idle
  door. The empty type now parses as the native-behavior `reset` rule on
  the official API path only; legacy envelope parsing stays strict.

## [1.5.9] - 2026-07-13

### Fixed

- Dashboard CSS, JavaScript, and fonts now load under HA Ingress. The
  Supervisor strips the ingress prefix from forwarded paths while the app
  sets `root_path` for URL generation; the FastAPI 0.139 / Starlette 1.3
  dependency bump changed static-mount path arithmetic so that mismatch made
  every `/static/*` asset 404 through Ingress (pages rendered with inline
  styles only, in every browser). Static files are now resolved from the raw
  request path, immune to the root-path mismatch, with an end-to-end
  regression test covering direct and Ingress modes.
- Self-hosted fonts are served with the correct `font/woff2` content type
  (Alpine's mimetypes table has no woff2 entry).

## [1.5.8] - 2026-07-13

### Fixed

- Hub sync now recognises when the console's Access app has removed the
  legacy per-device `lock_rule` API (HTTP 404) and surfaces an actionable
  error — "configure a UniFi Access Open API token in Settings to switch to
  the supported API" — instead of a generic traceback. Deployments without
  an Open API token are pinned to the legacy endpoint; recent UniFi Access
  updates have dropped it.
- Repeated permanent rejections of a locked-direction hub drive (removed
  endpoint or explicit legacy-rule rejection) are now retried on a spaced
  30-second cadence after three consecutive failures instead of hammering
  the dead API twice every 5-second poll. Retries never stop — the safe
  locked intent is retained and enforcement resumes the moment the spacing
  expires — and lockdown enforcement is never spaced or delayed. Transient
  faults (timeouts, 5xx) keep full-cadence retry.
- Persistent hub-sync failures now log once at full volume per distinct
  failure (drive errors and Access readback failures), with repeats demoted
  to debug until the lock converges again; previously an unreachable
  endpoint produced two error tracebacks and a warning every five seconds
  indefinitely.

## [1.5.7] - 2026-07-13

### Fixed

- The stylesheet and script are now linked with content-hash version
  queries, and failed static responses are no longer cacheable. Previously
  a browser could keep a stale — or transiently failed — cached `app.css`
  for up to an hour after an add-on update, rendering the dashboard with
  no styles. If you hit this, one hard refresh (Cmd/Ctrl+Shift+R) clears
  the stale entry; it cannot recur after this version.

## [1.5.6] - 2026-07-13

### Fixed

- Hub sync now applies flap suspension, minimum-apply-interval damping, and
  failure backoff on the bidirectional reconcile path, mirroring the legacy
  poll path's contract: only the hold-open (unlock) direction is ever damped,
  failed lock commands keep retrying every poll, and lockdown enforcement is
  never deferred. Previously a pathologically cycling lock could drive hub
  commands on every 5-second poll indefinitely.
- Bounded the hub-sync flap-detection bookkeeping, which grew without limit in
  bidirectional mode (one entry per hub actuation for the install's lifetime).
- The UniFi Protect client no longer replays credentials when two callers race
  to log in at once; the second caller now reuses the fresh session, matching
  the Access client's behavior.
- Signing out is now a CSRF-protected POST; previously a third-party page
  could force-logout a signed-in admin with a bare `GET /logout` image tag.

### Changed

- Added database indexes for the admin audit log (`timestamp`) and visitors
  (`created_at`), removing full-table scans from the Settings page and the
  Visitors page on every load.
- Dashboard polish across all pages: shared component classes for headings,
  labels, chips, buttons, and empty states; consistent table styling on the
  Status, Activity, and Lock History pages; empty-state messages where
  sections previously vanished silently; and a dark-themed admin-required
  page so the Ingress 403 no longer flashes light-mode.
- Dangerous actions are harder to trigger accidentally: manual Unlock now
  asks for confirmation and carries a danger tint, entry-device deletion and
  group-member removal now confirm, and every form disables its submit
  button while a request is in flight (with progress labels on the Settings
  connection tests and service restart).
- Mobile layout: the Locks page action row no longer wraps the Delete button
  into odd positions, visitor extend/delete controls stack on narrow
  screens, and icon-only buttons have larger tap targets.

## [1.5.5] - 2026-07-12

### Added

- Self-hosted the dashboard's three typefaces (Plus Jakarta Sans, Archivo, and
  IBM Plex Mono) as bundled Latin `woff2` files with `@font-face`. They were
  referenced in CSS but never loaded, so the UI silently fell back to system
  fonts; they now render as designed and load with no external CDN, keeping the
  interface CSP-safe under HA Ingress.

### Changed

- Unified the dashboard theme. Pages still using the legacy Tailwind gray
  palette (Locks, Settings, Users, Groups, Activity, and the detail pages) now
  render in the same navy design tokens as the rest of the app via a palette
  bridge in the base template, and dim secondary labels were lifted for
  legibility. The compiled Tailwind bundle is unchanged.

### Fixed

- Removed the tab-switch stall on the Locks and Visitors pages. Their per-page
  device pickers (HA lock entities, Access door locations, Protect cameras)
  blocked the page render on live upstream calls whenever the 30-second cache
  expired — HA's `/api/states` payload alone is 1–5 MB. These caches now use
  stale-while-revalidate: a render serves cached data immediately and refreshes
  in the background, so it never waits on an upstream fetch. Live lock state is
  unchanged, as it still comes from the in-memory WebSocket cache.

## [1.5.4] - 2026-07-12

### Documentation

- Corrected the lockdown API contract to describe persistent `keep_lock`
  enforcement and confirmed locked state rather than `reset`, which is reserved
  for Follow Schedule.
- Documented crash-safe bidirectional-sync ownership of both `keep_unlock` and
  fail-safe `keep_lock`, including door/location metadata, restart recovery,
  and confirmed replacement before ownership is cleared.
- Corrected the Access API-token Settings workflow: a blank token submission is
  rejected; operators must enter a replacement or explicitly choose **Clear
  Token**.
- Updated released changelog references and removed stale “Unreleased” wording
  from the `1.5.3` release notes.

## [1.5.3] - 2026-07-12

End-to-end reliability, performance, security, packaging, and documentation
review.

### Fixed — physical-access correctness

- **Native Access locking is schedule-aware and state-confirmed.** The former
  generic Lock path sent `reset`, which could restore an active unlock schedule
  and leave the door open. Native **Unlock** now applies `keep_unlock`, **Lock**
  applies `lock_now` to terminate a current schedule/temporary unlock, and the
  separate **Follow Schedule** action applies `reset` intentionally. Access
  writes are followed by bounded rule and relay-state reads before success is
  reported.
- **The official Access Open API is supported.** Operators can save a token
  with `view:space` and `edit:space`; calls use HTTPS port `12445`, door/location
  IDs, Bearer authentication, strict response envelopes, and an isolated
  cookieless session. The token is encrypted at rest, can be overridden with
  `ACCESS_CONTROL_ACCESS_API_TOKEN`, and is never silently bypassed with the
  private session API after a configured-token failure. Tokenless installations
  retain compatibility mode with explicitly documented firmware/readback
  limitations.
- **Opt-in HA/Access synchronization is bidirectional.** Confirmed HA-only
  changes propagate to Access, while confirmed Access rule/relay changes—including
  native unlock-schedule activation/deactivation—propagate to HA. Access events
  reduce latency and the periodic authenticated poll catches missed events and
  drift. Persisted origin snapshots prevent feedback loops across restart;
  unreadable state, startup disagreement without a verified active schedule,
  and opposing simultaneous changes resolve locked.
- **Fail-safe locking no longer restores a schedule.** Lockdown, ambiguous
  state, recovery, and conflict handling use `keep_lock`; `reset` is reserved
  for deliberately returning ownership to Access. A configured token or
  controller error remains pending/visible instead of being counted as a
  confirmed safe transition.
- **Enabled incomplete schedules now fail closed.** The form requires days
  and/or a complete start/end range; corrupt rows with one bound or no
  restriction are inactive instead of becoming an all-day grant. Days-only,
  time-only, combined, and overnight schedules remain supported.
- **Alarm uncertainty is conservative.** Literal unknown/unavailable values,
  unrecognized states, and mixed armed modes no longer collapse to
  `disarmed` or a single less-restrictive armed state. Armed-state blocking is
  applied to uncertain/transitional state, including when panels are
  configured but the HA client is unavailable.
- **Closed the lockdown decision race with one physical-command barrier.**
  Lockdown changes, application unlocks, HA re-locks, hub actuations, and live
  client publication are ordered together. Once enabling lockdown returns, an
  event already evaluating under the old state cannot issue its unlock later.
- **Lockdown now locks a hub already held open by sync and continuously
  verifies it.** The `keep_lock` override runs before the unchanged-state fast
  path. Authenticated Access rule/relay and HA state are re-read on later polls,
  so a direct HA unlock or Access schedule/temporary unlock during the same
  incident is closed again. Lifting lockdown does not reopen the hub without a
  verified post-incident source change.
- **Lockdown persistence and enforcement fail closed.** An unreadable persisted
  value restores lockdown as enabled. Enable/disable transitions are serialized;
  failed disable persistence leaves it enabled, while an unresolved immediate
  hub lock returns `503` and remains visible as entity IDs in
  `lockdown_enforcement_pending` health.
- **Missing hub pairings remain unconverged.** Hub sync reports
  `reason=no_paired_hub`, backs off, and retries so a later pairing converges;
  it no longer records a false success.
- **Hub persistent-rule ownership survives crashes.** Door/location identity
  plus bidirectional-sync `keep_unlock` or fail-safe `keep_lock` ownership is
  normally persisted before the physical command and cleared only after
  readback proves the rule was replaced. A persistence failure blocks opening;
  active lockdown still attempts `keep_lock`, reports enforcement unresolved,
  and retries the ownership write. Startup, lockdown, opt-out, and best-effort
  shutdown recovery close uncertain doors without stranding them open or
  silently suppressing future schedules.
- **Untrustworthy HA state and ambiguous hub ownership now lock fail-safe.** A
  disconnect, state-read exception, or value other than exactly
  `locked`/`unlocked` closes any app-owned hold. Pairing changes close removed
  hubs before opening replacements; independent HA entities that resolve to one
  physical hub are locked/suppressed and alert with
  `reason=shared_hub_conflict` until the mapping is one-to-one.
- **Timed re-lock intent is durable before physical unlock.** Buzz and
  device-auth paths persist and arm the new deadline first. A failure or
  timeout retains the earliest applicable deadline because HA may have acted
  before the response was lost. Generation checks prevent late recovery from
  clobbering a newer schedule. Manual overrides without a new
  timer retain/restore their earlier deadline on failure.
- **HA lock success now requires observed-state confirmation.** Manual and
  scheduled re-lock paths perform bounded state reads and clear the durable
  timer only after HA reports exactly `locked`; confirmation/retry sleeps no
  longer monopolize the app-wide physical-command barrier.
- **Remote-unlock re-lock work survives teardown.** Because the upstream event
  says the door is already open, its scheduling task is critical and awaited
  across client swaps/shutdown, and scheduling no longer depends on the
  optional remote actor ID. A timer-persistence failure attempts an immediate
  lock, requires observed `locked` state, audits the result, and emits the
  failure event when recovery cannot be confirmed.
- **Disappeared native Access doors retire without becoming stale targets.** A
  valid non-empty snapshot marks missing native rows dormant and excludes them
  from normal UI/API/authorization/pairing lookups while preserving history;
  rediscovery of the same location revives them. Empty door snapshots cannot
  mass-retire an existing inventory.
- **Visitor wall times now use the HA site timezone.** Daylight-saving gaps and
  ambiguous folds are rejected, and extensions cannot end before a future
  visitor's original start.

### Fixed — reliability and security boundaries

- **Concurrent rate limiting is serialized without overlapping SQLite
  transactions.** Bursts no longer fail with `cannot start a transaction
  within a transaction`; successful API authentication avoids a no-op write.
- **SQLite transaction ownership is explicit.** The long-lived connection now
  autocommits ordinary statements, while topology/config bundles, group
  replacement, pending re-locks, hub ownership, and explicit batches use
  task-owned isolated transactions. One coroutine can no longer accidentally
  commit or roll back another's write.
- **Access/Protect login state is published atomically.** Partial login state is
  not retained after failure; a successful login clears permanent-auth-failure
  state. REST 401 reauthentication no longer awaits aiohttp's synchronous
  `release()` method.
- **Secret-key source is fixed at first setup.** Database-key installs ignore a
  key injected later. Environment-key installs store only a fingerprint and
  require the exact `ACCESS_CONTROL_SECRET_KEY` on every start. Legacy
  databases migrate to database-key mode, preventing late overrides from
  orphaning encrypted credentials.
- **Logical configuration bundles commit atomically.** First-run encryption and
  credential metadata, multi-field console/HA changes, and restart-schedule
  values are serialized and committed as bundles, so a failed write cannot
  expose a partly updated credential or key set.
- **Settings client swaps are tested before promotion.** Home Assistant and
  UniFi credential changes preserve a working client on failure and keep a
  separately configured Access console separate from the primary Protect
  console.
- **Access sessions are bound to the enrolled site namespace.** First setup
  persists a hash derived from all stable console/site identity candidates,
  falling back to authenticated Access-building topology. Every login,
  Settings candidate, REST reauthentication, WebSocket reconnect, and topology
  refresh must match before auth state or identifiers are published. Same-site
  Access-host/target changes remain supported, including single/split mode; a
  different Access site requires fresh initialization. This is not TLS peer
  verification or certificate pinning.
- **HTTP trust boundaries were tightened.** Body limits apply before form
  parsing (including setup/login and chunked requests), early middleware
  responses receive security headers, CSRF validation covers every mutating
  dashboard verb, dynamic responses are non-cacheable, background polling no
  longer extends a direct-mode session forever, logs omit the WebSocket CSRF
  credential and untrusted upstream error bodies, and API responses omit
  encrypted PIN material.
- **Form relationships and enums are validated.** Lock/alarm entity domains,
  API-key scopes, entry-device types/ownership, schedule shapes, and re-lock
  ranges are checked at the request boundary. Visitor names are no longer
  interpolated into inline JavaScript.
- **The packaged scheduled restart is functional.** It requests a self-restart
  through the authenticated Supervisor API, retains an explicit standalone
  fallback, and the manifest enables the required Supervisor API plus a
  `/health/live` watchdog. Ingress continues to direct ordinary manual restarts
  to Home Assistant's app page; direct-host Settings shows its manual control
  and reload banner only when a restart mechanism is available.

### Changed — API

- **`POST /api/lockdown` is now an idempotent setter.** Full-scope callers must
  pass `?enabled=true` or `?enabled=false`; the old bodyless toggle contract is
  rejected with `422`. Duplicate delivery can no longer invert incident state.

### Performance and efficiency

- **Topology sync is one isolated atomic transaction.** A dedicated SQLite
  connection prevents request coroutines from committing or rolling back part
  of a refresh, skips unchanged users/locks, and refuses empty/malformed user
  snapshots as a mass-delete signal.
- **Short-lived UI caches are process-local.** Cache hits/expiry no longer write
  to SQLite, reducing idle flash/SD-card I/O.
- **Visitor polling targets active work.** Every five minutes, status-1 rows
  whose timezone-aware end has passed are expired locally; UniFi is queried
  only when active rows remain. Historical rows no longer keep a one-minute
  upstream loop alive indefinitely.
- **Static browser dependencies are bundled.** Pinned Tailwind input produces a
  committed minified stylesheet; shared JavaScript replaces HTMX home polling
  and injects CSRF form fields, eliminating runtime Tailwind, HTMX, and font CDN
  dependencies.
- **Shutdown owns background work.** Ordinary event and timer tasks are
  cancelled/awaited before clients/database close; safety-critical
  remote-unlock re-lock work is awaited to completion rather than cancelled,
  avoiding both torn-down-state access and an unprotected already-open door.

### CI, release, and packaging

- GitHub Release creation now runs only after successful main-push CI for the
  exact commit, extracts a literal exact-version changelog section, and can
  repair a tag whose release creation failed without moving the tag.
- Ordinary main/manual image builds use immutable `sha-*` tags. Version and
  `latest` move only for a manifest version change; released version tags are
  never overwritten.
- Added an app-local `.dockerignore` because `access_control/` is the build
  context. Local environments, caches, tests, dev requirements, databases, and
  frontend dependencies are excluded from runtime images.

### Documentation

- Rebuilt the documentation as an end-to-end set covering configuration,
  architecture, operations, safe backup/restore, troubleshooting, API
  contracts/scopes, security trust boundaries, development/testing, bundled
  CSS, CI, and releases.
- Marked dated audits and design specs as historical, updated support/version
  references and issue-report guidance, documented split-console setup and
  the fixed secret-key modes, and removed unsafe live-SQLite copy guidance.

### Corrections to historical notes

- The v1.5.1 topology item correctly records the reduction in row rewrites and
  commits at that release, but a later concurrency review found that batching
  on the shared `aiosqlite` connection did not provide transaction ownership.
  The 1.5.3 change moves the refresh to a dedicated atomic connection.
- The v1.5.0/v1.5.2 hub-sync notes describe the intended lockdown behavior at
  those releases. A held-open hub whose HA state had not changed could still
  skip reset through the unchanged-state fast path; the 1.5.3 fix above
  closes that specific gap. Historical release text is preserved rather than
  rewritten.
- The v1.5.0 hub-sync entry says unknown/unavailable/jammed HA states are
  ignored. That was the behavior at that release. Current sync never opens on
  an untrustworthy state and replaces any app-owned unsafe override with
  confirmed fail-safe `keep_lock`, including after an HA disconnect or
  state-read exception.
- The v1.1.0 ingress entry called `X-Ingress-Path` “Supervisor-signed” and said
  another app on the bridge could not forge it. The app validates only the
  header's shape; it cannot verify the opaque ingress token. Co-resident apps
  remain inside the documented HA-host trust boundary. The current security
  model corrects that terminology.
- v1.1.0 removed the manifest watchdog and later restart UI was intentionally
  ineffective in the packaged container. The 1.5.3 change restores an
  explicit `/health/live` watchdog and uses Supervisor's authenticated
  self-restart endpoint for scheduled restarts.

## [1.5.2] - 2026-07-12

### Fixed (hub sync — field report: "sync isn't working")

Three real-world gaps meant hub sync could silently do nothing:

- **Sync now converges instead of waiting for a change.** v1.5.0 acted
  on transitions only and silently adopted the current state on enable
  or restart — so enabling the toggle while the deadbolt was already
  unlocked did nothing until the *next* change. The hub is now driven
  to match the lock's current state within one poll of the option
  being enabled (and after restarts). The hub commands are idempotent
  state-sets, so re-asserting an already-correct state is physically a
  no-op; lockdown still suppresses the hold-open direction, and the
  door still doesn't pop open when lockdown lifts.
- **Hubs hidden from the Locks page now resolve.** Pairing resolution
  filtered `hidden = 0`, so hiding the (redundant-looking) native hub
  card silently broke sync with only a container-log warning.
- **Doors paired via a Protect doorbell now resolve.** Resolution only
  read *Access NFC Reader* entry devices; a lock linked to its door
  through a *Protect Doorbell* entry device (the natural pairing for a
  G6 Entry) found no hub. The doorbell's camera→location mapping is
  now used.

### Changed

- **Flap-protection retuning.** Hub drives are now spaced ≥10 s (was
  30 s), and suspension requires 8+ drives in 5 minutes (was 4+ in 10
  minutes) — the old thresholds could suspend sync for 10 minutes just
  from someone hand-testing the feature or normal leave/return traffic,
  which read as "sync is broken". Sustained pathological cycling still
  suspends, fail-safes the hub to reset, and alerts with
  `reason: flapping`.

## [1.5.1] - 2026-07-12

### Performance (idle I/O + hot-path latency)

Quick wins from the 2026-07-12 end-to-end review. On a 24/7 SD-card
host these cut idle write transactions by roughly 90% and shave
hundreds of ms off the heavier page renders:

- **Topology resync no longer rewrites unchanged rows.** `upsert_user`
  skips the write (and the `synced_at` bump) when upstream data is
  identical, and the whole user+lock sync batches into a single
  committed transaction instead of one per row — previously ~10k
  fsync'd write transactions/day at complete idle. `synced_at` now
  means "last time upstream data changed".
- **`/locks` and `/settings` no longer download HA's entire
  `/api/states` per render.** The filtered lock/alarm entity lists are
  cached for 30s alongside the existing Access/Protect caches (was
  1–5 MB of JSON parsed per page view).
- **Home-page alarm cache TTL raised 5s → 15s** so the 10s dashboard
  auto-refresh actually hits the cache instead of missing it by
  construction (an HA call + a cache write every poll, per open tab).
- **Visitor sync checks the local table before calling the console.**
  With zero visitors it previously made 1,440 TLS requests/day to the
  UNVR forever.
- **`access_log` indexes for history views.** Per-lock and per-user
  history were table scans over 90 days of events; added
  `(lock_id, timestamp)` and `(user_id, timestamp)` indexes and
  dropped the redundant `idx_users_ulp_id` (duplicate of the UNIQUE
  constraint's implicit index).
- **Login/setup password hashing moved off the event loop.** PBKDF2 at
  480k iterations is ~hundreds of ms of pure CPU; it now runs in a
  worker thread so a login attempt can't stall WS door-event dispatch
  or relock timers.

### Fixed

- **`log_level: notice` or `fatal` no longer crash-loops the add-on.**
  Both are valid schema values but not uvicorn log levels; run.sh now
  maps them (notice→info, fatal→critical). The app's own loggers also
  honor the option now (exported as `APP_LOG_LEVEL`) — previously the
  app was pinned to INFO, so `debug` never enabled app debug logs.

## [1.5.0] - 2026-07-12

### Added

- **Opt-in hub sync for third-party locks.** A new per-lock setting on the
  Locks page — "Sync Access hub & door to this lock's state" — mirrors a
  Home Assistant lock entity's state onto its associated UniFi Access
  hub/door: when the HA lock reports `unlocked` the hub is held open
  (`keep_unlock`), and when it reports `locked` the hub is reset to normal
  locked behaviour. Off by default; only HA-external locks show the
  toggle, and it requires the lock to be associated with an Access
  location (via Entry Devices → Access NFC Reader, or the legacy
  `access_location_id`). Sync is one-way (HA → hub), acts on observed
  locked/unlocked transitions only (a restart or enabling the option
  never moves a door by itself), and ignores `unavailable`/`unknown`/
  `jammed` states so radio hiccups can't trigger spurious hub changes.
  Failed syncs are retried with backoff until the hub converges, and an
  `access_control_hub_sync_failed` HA event is fired (once per failing
  transition, with a `reason` field) so automations can alert.
  Successful syncs appear in the hub's lock history as `hub_sync`
  entries. Safety rails, added after an adversarial review of the
  feature: **lockdown overrides sync** (an HA state write can never
  hold a hub open during lockdown, and the door doesn't pop open when
  lockdown lifts); **flap protection** (applied transitions are spaced
  ≥30 s apart, and 4+ transitions in 10 minutes suspends sync for that
  lock for 10 minutes, fail-safes the hub to reset, and alerts with
  `reason: flapping`); and **release-on-drop** (disabling the option,
  hiding, or deleting a synced lock while its hub is held open drives
  the hub back to reset — retried until it lands — instead of
  stranding the door open).

### Fixed

- **Saving lock settings no longer wipes the Access-location pairing.**
  The lock settings form has never rendered `access_location_id`, but
  the save handler passed a blank form default through and NULLed the
  column on every save — silently breaking tap-to-unlock (and hub
  sync) for legacy-paired doors the next time any setting was toggled.
  `update_lock_settings` now preserves the pairing unless a caller
  passes it explicitly; covered by regression tests against a real
  SQLite database.

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
