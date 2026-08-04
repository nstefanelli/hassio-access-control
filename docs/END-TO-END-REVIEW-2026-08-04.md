# End-to-End Engineering Review — 2026-08-04

Subagent-driven bug and performance review of the full codebase. Six parallel
subsystem reviews (hub sync, web/API, database, external clients, core
lifecycle, frontend/packaging) produced 49 candidate findings; each significant
claim was re-verified against source (the hub-sync findings additionally with
executable reproductions) before fixing. 31 findings were fixed on this branch,
each with regression coverage; the remainder were refuted, historical-only, or
are recorded below as open recommendations. The full test suite grew from
472 tests + 111 subtests to 565 tests + 117 subtests, all passing.

## Fixed — safety and correctness

| ID | Area | Issue |
|---|---|---|
| HS-1 (high) | hub_sync.py | A transiently failed drive of a genuine HA unlock (or Access schedule mirror) recorded the divergent observation as the confirmed baseline, so the next 5s poll classified the unchanged mismatch as a concurrent conflict and **physically re-locked the door** instead of retrying the unlock. Failed drives now keep the pre-change baselines and retry after backoff. Reproduced before/after with a runnable script. |
| HS-3 | hub_sync.py | The persist-failure compensation recorded an app-owned `keep_lock` without latching `_fail_safe_reset_eids`, stranding a rule that suppressed all future Access schedules until restart. |
| CORE-1 | auth_engine.py | Lockdown enable set memory state, awaited the global command-barrier drain (potentially long), and only then persisted — a crash in that window restarted with lockdown OFF mid-incident. Now persisted write-ahead. |
| CORE-2 | auth_engine.py, main.py | The resolved HA timezone was never persisted; an HA-down boot evaluated schedules in container UTC (wrong local hours for grants/denials). Last-known timezone is now stored and loaded at boot. |
| CORE-3 | main.py | `ws_last_event` was stamped before event-type filtering, so routine WS chatter kept the "someone at the door" guard perpetually fresh and the scheduled maintenance reboot never fired. Only door-relevant events stamp now. |
| CORE-4 | main.py | A failed topology sync during Access bring-up left `event_topology_ready=False` (all door events fail-closed dropped) with no retry faster than the 900s resync loop. Bring-up failures now retry single-flight with 15s→300s backoff. |
| CLI-1 (high) | protect_client.py | Protect REST calls never re-authenticated on 401 and returned `[]` silently — an expired UNVR session produced empty camera lists forever. Now clears auth state and retries once after re-login. |
| CLI-2 (high) | protect_client.py | The WS frame parser ignored the deflate header flag; zlib-compressed door/ring/NFC frames (current Protect firmware) were dropped as parse errors while the connection reported healthy. Frames are now decompressed per the flag; repeated parse failures escalate log level. |
| CLI-11 | access_client.py, ha_client.py | The operation-lease release awaited the lifecycle lock inside `finally`; a cancellation delivered there leaked the lease count and hung `close()` (add-on shutdown/settings swap) forever. Release is now shielded. |
| CLI-12 | both WS clients | The 401 latch counted non-consecutive 401s interleaved with ordinary network errors, wrongly declaring credentials permanently failed during flaky console reboots. |
| CLI-3/CLI-4 | protect_client.py, main.py | Missing closed-state guard and missing `close()` of replaced stale clients leaked aiohttp sessions per recovery cycle. |
| CLI-9/CLI-10 | access_client.py, main.py | `list_visitors`/`get_bootstrap` assumed well-formed envelopes; a list/null/malformed payload crashed the sync pass unwrapped. Now validated, wrapped in `AccessClientError`, malformed rows skipped. |
| WEB-1 | web_routes.py, web_auth.py | CSRF tokens were minted with cookie-first identity while validators used ingress-first — a client with both a session cookie and ingress SSO headers got tokens that never validated, and the per-render cookie refresh made the 403 lockout self-sustaining. One shared identity resolver now serves both. |
| WEB-2 | web_auth.py | The session cookie was hardcoded `Secure`; browsers discard it on the documented plain-HTTP direct-port path, producing an infinite login loop. Secure flag now derives from ingress/scheme/forwarded proto. |
| FE-1 (high) | group_detail.html | Stored XSS: the group name was interpolated into an inline `onsubmit` JS string where HTML entity decoding runs before JS compilation, so `|e` did not protect the JS context. Moved to the `data-*` pattern used everywhere else. |
| FE-2 | web_routes.py, locks.html | Lock-action failures redirected with `?error=` which the locks page never read — denied/failed physical commands showed no feedback. Error banner now rendered. |
| DB-1 | database.py | Migrations 1 and 16 cycled (add then drop `api_keys.key_encrypted`) on **every startup**, rewriting the table each boot and hard-failing on SQLite < 3.35. |
| DB-2 | database.py | `rate_limits` rows that never reached lockout were never pruned — unbounded growth, one permanent row per probing client IP on exposed installs. |
| FE-3/FE-4/FE-7 | app.js, settings.html, web_routes.py | Double-submit guard disabled the wrong button on two-button forms; 429 login page rendered the authenticated app shell; restart poller gave up after 63s leaving a stuck banner. |
| deps | requirements.txt | aiohttp 3.14.1 → 3.14.3 and cryptography 48.0.1 → 50.0.0, clearing 6 known CVEs flagged by pip-audit (matches the open Dependabot high alert on the default branch). |

## Fixed — performance

| ID | Area | Change |
|---|---|---|
| HS-4 | hub_sync.py | Steady-state convergence wrote a durable per-entity SQLite transaction (new connection + `BEGIN IMMEDIATE` + fsync) every 5s — ~17,280/entity/day with zero information change. Now skipped when desired/rule/pairing are unchanged since the last successful persist. |
| HS-2 | hub_sync.py | During an HA outage, every 5s poll re-issued `hold_locked` + a durable DB write + an audit row per hub. Now driven once per outage per pairing. |
| CORE-6 | hub_sync.py | With hub sync disabled on all locks (the default), the 5s poll still ran a full `SELECT * FROM locks`. Idle now backs off to a 60s re-check, invalidated by events. |
| CLI-5 | ha_client.py | Lock/camera/alarm entity getters each downloaded HA's entire `/api/states` (multi-MB). Now one shared snapshot behind a 10s TTL cache. |
| CLI-7 | both WS clients | Reconnect backoff reset to the 5s base after any successful upgrade, so accept-then-close failure modes churned at 5s forever (plus per-cycle identity verification). Backoff resets only after 30s of stable connection. |
| CLI-13 | ha_client.py | Status-only responses (30s health probe, every lock command) never drained the body, defeating keep-alive — fresh TCP/TLS handshake per call. |
| DB-4 | database.py | WAL ran with default `synchronous=FULL`; now `NORMAL` on all connections (durable across app crash; only power loss risks the final transaction), cutting fsync cost on SD-card hosts. |
| DB-8 | database.py | Per-tap lookups (`entry_devices` by type+device, `group_members` by user) had no usable index — full scans on every doorbell/NFC event. Indexes added (migration 29). |
| DB-3 | database.py | Dead `ui_cache` table (cache moved in-process) dropped via migration 28. |
| WEB-4 | web_routes.py | `/setup` ran three 480k-iteration PBKDF2 derivations inline on the event loop; now in a thread like the neighboring `hash_password`. |
| WEB-5 | web_routes.py | Settings renders blocked on a full `/api/states` fetch on every 30s cache miss; now stale-while-revalidate like the locks page. |
| WEB-6/WEB-8 | database.py, web_routes.py | `/visitors` rendered every row ever created (now bounded, newest-first); per-visitor operation locks accumulated forever (now retired after delete). |
| FE-6/FE-8 | app.js, settings.html | 10s auto-refresh no longer swaps identical DOM or interrupts in-progress interaction; dead `toggleKey` secret-display helper removed. |

## Refuted or no-action findings

- **FE-5 (refuted):** `httpx2` in requirements-dev.txt is the real successor
  package; the FastAPI TestClient works with it and the integration tests run
  (verified: 6 passed, not skipped).
- **WEB-3 (stale):** the unique index on `access_rules(user_id, lock_id)`
  already exists via migration 26; `add_rule`'s `INSERT OR IGNORE` is live.
  A regression test was added.
- **DB-6 (historical):** migration 13's blanket `buzz_duration 5→30` rewrite
  already ran on upgraded installs; nothing to fix retroactively.

## Open recommendations

1. **CLI-6 — HA WebSocket push.** **RESOLVED on this branch.** Hub sync polled
   HA lock state over REST every 5s per lock (~17k requests/day/lock).
   Implemented in the follow-up commits on this same branch:
   `HAClient.start_websocket` subscribes to `state_changed` and drives
   `HubSyncManager.notify_ha_state_change`; the REST poll is now a 60s
   reconciliation backstop (`BACKSTOP_POLL_INTERVAL`) that falls back to 5s
   whenever the push feed is down, REST health is bad, or deferred work is
   pending.
2. **CORE-5 — relock cancellation semantics.** A granted credential tap on an
   HA lock with `relock_on_device_auth=0` (the default) cancels a pre-existing
   durable relock from an earlier buzz/remote unlock, converting a bounded
   temporary unlock into an indefinite hold-open. The code marks this
   intentional ("a confirmed hold-open supersedes the paused older timer"),
   but it silently voids a persisted safety deadline. Recommend making it an
   explicit per-lock option or resuming the prior deadline. Product decision.
3. **CLI-8 — WS 401 replay cap.** The "5 credential replays then stop" latch
   is cleared by the 60s supervisor loop's successful REST login, so a stuck
   WS endpoint sees ~5 replays/minute indefinitely. A sticky latch would match
   the documented intent but risks requiring operator action after transient
   console faults — worth an explicit decision.
4. **CORE-7 — per-tap query fan-out.** Each auth decision runs ~8–12
   sequential SQLite queries (per-group lock lists, per-lock rules, entry-device
   lookups, alarm-panel re-read). DB-8's indexes reduce the per-query cost;
   folding them into a joined/cached read remains available if tap latency
   matters under burst.
5. **DB-5 — isolated-writer connection churn.** Hub-hold/pending-relock/config
   writers open a fresh SQLite connection per call by design (isolation).
   HS-4/HS-2 removed most of the call volume; a long-lived dedicated writer
   connection is the next step only if profiling still shows churn.
6. **HS-5 — event-burst coalescing.** A schedule transition across N doors
   queues N sequential full reconcile passes; coalescing to one trailing pass
   (or consuming `_dirty_locations` for scoped passes) would bound burst
   latency. *Partially addressed on this branch:* HA-origin event bursts now
   coalesce (`notify_ha_state_change` is single-flight with at most one
   trailing pass); Access-event burst coalescing remains open.
7. **DB-7 — legacy `commit=False` batch API.** An abandoned batch leaks an
   open `BEGIN IMMEDIATE` connection until shutdown. Production code no longer
   uses the path (tests only); remove it or add a task-done rollback callback.

## Verification

- Full suite: `python -m pytest access_control/tests -q` from
  `access_control/rootfs/opt` — **565 passed, 117 subtests passed**.
- Hub-sync fixes additionally verified with before/after executable
  reproductions of HS-1 (unlock revert), HS-2/HS-4 (write churn), and HS-3
  (stranded keep_lock).
- `pip-audit` clean for the two bumped packages at the new pins.

### Follow-up (same branch)

After this report was written, the CLI-6 recommendation was implemented on the
same branch (HA WebSocket push driving hub sync, with the 5s poll relaxed to a
60s reconciliation backstop). The new feature was itself adversarially
reviewed by two independent reviewers; their findings — shutdown ownership of
the push-reconcile task, `mark_app_initiated_unlock` TTL sizing against the
backstop interval, making the backstop REST-health- and pending-work-aware,
and HA WebSocket lifecycle races (stop/start/close ordering, post-jitter
backoff clamp) — were fixed with regression tests. Final suite after the
follow-up work: **637 passed, 122 subtests passed**.
