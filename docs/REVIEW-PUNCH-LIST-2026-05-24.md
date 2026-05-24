# Codebase review — deferred items punch list

**Branch:** `review/codebase-2026-05-24` (this PR fixes 17 findings; this
file tracks the remaining items that were considered and deliberately
deferred, with rationale and triggers for revisiting.)

## What this PR fixed

Critical:
- `/setup` POST now refuses after first-run (C1) — closed re-takeover hole
- `/setup` POST rate-limited (C2) — closed UNVR/HA brute-force via setup
- `protect_client.py` `logger` → `_LOGGER` — closed runtime `NameError` on Protect 401

High:
- `update_ha` / `update_access_console` / `update_unvr` no longer echo
  raw upstream exception strings to the dashboard (H1)
- CSRF middleware now trusts SSO user identity, applying CSRF binding to
  HA-Ingress POSTs that have no session cookie
- CSRF middleware caps request body at 1 MiB (was: unbounded; could OOM)
- WS reconnect loop on both Access + Protect clients now counts
  consecutive WS-upgrade 401s and sets `_auth_permanently_failed`
  after 5 — closes credential-replay storm on stuck endpoints
- TLS-verification-disabled is now documented with explicit trade-offs
  in `access_client.py` / `protect_client.py`
- Timestamp format consistency: new `_utc_now_sqlite()` helper produces
  output identical to the schema-default `datetime('now')`; all 5
  Python-side writes converted (was: mixed `T`-format vs space-format
  in same column, breaking `prune_logs` + `since` range queries)

Medium:
- `add_visitor` / `extend_visitor`: `strptime` wrapped in try/except so
  malformed date/time returns 422 instead of 500
- `update_schedule` / `create_group` / `update_group`: time strings
  validated against `^([01]\d|2[0-3]):[0-5]\d$` before persistence
- `set_group_locks`: non-integer `lock_ids` form values dropped with a
  warning instead of raising 500
- `mark_deleted_users([])` now logs and returns 0 instead of mass-marking
  every user as `deleted_upstream` (operational footgun)
- Float type annotations on `delay` / `max_delay` in WS reconnect loops
- Removed unused imports (`auth_engine.HAClientError`, `main.FormData`)
- `auth_engine` `can_disarm` now iterates schedule-active groups instead
  of raw `user_groups` — closes the "Cleaner whose disarm group is
  outside its 9-5 window still bypasses an armed-away block from a
  different group" edge case
- `circuit_breaker` now reserves the HALF_OPEN probe slot via
  `_probe_in_flight` so two concurrent callers can't both probe
- `_client_ip()` defensive `getattr` for test stand-ins missing `.client`

Plus new regression tests for the security-critical fixes:
- `test_setup_post_refuses_when_already_configured`
- `test_only_first_caller_gets_half_open_probe`
- `test_probe_failure_releases_slot_and_reopens`

## Deferred — code-quality / structural

| Item | Why deferred | Trigger to revisit |
|---|---|---|
| **Split `web_routes.py` into a package** | 1900 LOC + ~70 routes; would dwarf this PR. Out-of-scope per PR charter. | Next time a route change requires editing more than ~3 callsites |
| **Replace Tailwind CDN with bundled CSS** | Closes CSP `unsafe-inline` for `style-src` but requires inline-style → class refactor across 12 templates. Sizable rework with low security benefit (`unsafe-inline` already deemed acceptable for an ingress-only admin app). | A security scanner flags CSP `unsafe-inline` as critical, OR Tailwind CDN goes down |
| **Refactor `setup_post`** into named sub-helpers | Radon flagged as one of the highest-complexity functions. Touching it now means re-doing the C1/C2 guards in the new shape. | Next functional change to setup |
| **mypy `--strict` enforcement** | 76 mypy errors today, most are non-bugs (untyped third-party stubs, kwargs forwarding, attribute polymorphism). Closing them all means adding annotations throughout; out of scope. | Decision to accept type-checking as a hard CI gate |

## Deferred — security hardening above current bar

| Item | Why deferred | Trigger to revisit |
|---|---|---|
| **`is_rate_limited()` hot-path optimization** | The reviewer noted it opens BEGIN IMMEDIATE even on the read-only common path. Real-world impact is small (rate-limit checks happen at human-tap frequency, not millisecond bursts), and changing the txn shape risks correctness regressions. | Observable lock contention under load |
| **`get_user_count` / `get_lock_count`** filter `hidden` rows | Today these don't, and `get_all_users(include_hidden=False)` does. UI doesn't display these counts side-by-side with the filtered list, so the inconsistency is internal. | UI surfaces both side-by-side |
| **`secure=True` cookie under HTTP dev** | Default ingress-only deployment is always HTTPS via HA's frontend. Direct-port HTTP deployments are explicitly off-spec; documenting in `SECURITY.md` already covers it. | Anyone reports getting locked out under direct-port HTTP |
| **`relock_manager.rehydrate()` storm-protection** | Sequential past-due relock retries at 1.5s × 2 = 3s per row would take 5 min for 100 rows. In practice rehydrate operates on << 10 rows. | Operator reports slow recovery after HA outage |
| **`circuit_breaker` 401 escape valve** | Sustained 401s never trip the breaker (by design — HA is reachable, the token is just bad). Operator gets nothing automated; manual settings-page rotate fixes it. | Operator wants alerting on token expiry |
| **`access_client.login()` partial-state reset on non-`ClientError`** | Reviewer noted a `UnicodeDecodeError` / `TimeoutError` mid-login could leave `_csrf_token` half-set. Real-world frequency: never observed. | One real occurrence in the wild |
| **Pin HA base image by SHA256 digest** | Would lock the v1.x train. Dependabot Docker updates already track upstream. | First time someone needs to reproduce an exact v1.1.x image months later |

## Out of scope

| Item | Why |
|---|---|
| **HA Custom Integration companion** | Roadmap feature, not a fix |
| **Push notifications** (Telegram / mobile) | Roadmap feature |
| **Localization (i18n)** | Roadmap feature, no demand yet |
| **HA Community Add-ons submission** | Roadmap step after some real-world soak time |

## Methodology snapshot (for the next audit)

This review combined:
- `ruff check --select E,F,B,S` (bugs + style)
- `bandit -r ... --severity-level medium --confidence-level medium` (SAST)
- `pip-audit -r requirements.txt` (dep CVEs)
- `vulture --min-confidence 70` (dead code)
- `radon cc -nc -a` (cyclomatic complexity hotspots)
- `radon mi -nb` (maintainability index)
- `mypy --ignore-missing-imports --check-untyped-defs`
- 4 parallel reviewer-agent passes scoped by code domain
  (database, routes, auth/middleware, async clients)
- 1 templates+config pass

`bandit` + `pip-audit` are now CI-gated (since the May 24 quick-wins PR);
the rest were one-shot for this review. Next audit can rerun the same
tool list.
