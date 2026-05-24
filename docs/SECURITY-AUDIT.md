# Security Audit — 2026-05-24

**Branch:** `security/audit-2026-05-24`
**Reviewer:** Maintainer-led audit with assistance from automated tools
and a security-focused code-review agent.
**Repo state at start of audit:** main @ `11971ec` (tier 2 polish merged)

## Scope

Full-surface audit of the public repo:

- Authentication + authorization (`web_auth.py`, `ingress.py`,
  `api_auth.py`, `auth_engine.py`)
- Cryptography (`config.py` — Fernet, PBKDF2, password + API-key hashing)
- Input validation (form parsing, HA entity IDs, alarm PINs, visitor PINs)
- SQL layer (`database.py` — parameterized query review)
- Template safety (`templates/*.html` — escape-bypass audit)
- Container security (`Dockerfile`, `apparmor.txt`, `build.yaml`,
  `run.sh`, `config.yaml`)
- HA Ingress trust boundary
- Session management (cookie flags, path scoping, signing, timeout)
- CSRF (middleware + per-route dep)
- Rate limiting (login + API)
- Subprocess execution
- Logging (PII / credential leak)
- WebSocket clients (credential handling, reconnect under attack)
- Container image deps (CVE scan)
- Committed-secrets scan

## Methodology

| Tool / pass | Purpose | Result |
|---|---|---|
| **Bandit 1.9.4** | Python SAST | 11 findings → 0 actionable (3 false positives suppressed with documented `# nosec`; the rest fixed) |
| **pip-audit 2.10.0** | CVE scan of pinned Python deps | 22 vulnerabilities across 6 packages → **0** after dep bumps |
| **Trivy** | Container image vuln scan | 12 Go-runtime DoS CVEs in HA base image — **deferred** (waiting for HA base bump) |
| **Gitleaks** | Committed-secrets scan | No matches |
| **Manual code review** | Threat-model walk-through of every in-scope file by a security-focused agent | 1 Medium, 1 Medium-Low, 1 Low, 3 Info → all fixed or documented |

## Findings + remediation

### Critical / High

None.

### Medium

#### M1 — `/api/health` lacked an explicit scope guard

**Found by:** code-review agent.
**File:** `access_control/rootfs/opt/access_control/api_routes.py:21`.
**Issue:** Every other `/api/*` endpoint calls `_require_scope()` to gate by
key scope. `/health` did not, so any valid key — including `locks_only` —
could read connection state, user count, and lock count.
**Realistic exploit:** a key issued narrowly for a single HA automation
could enumerate users/locks. Low severity in absolute terms; matters as
defense-in-depth because the next person adding a new scope (e.g.
`metrics`) might be surprised that `/health` is implicitly open.
**Fix:** added explicit `_require_scope(auth, "full", "read_only", "locks_only")`
so future scopes have to opt in.

#### M2 — `uvicorn --forwarded-allow-ips='*'` enabled XFF spoofing

**Found by:** code-review agent.
**File:** `access_control/rootfs/run.sh`
**Issue:** Trusting `X-Forwarded-For` from any upstream means
`request.client.host` (used as the rate-limit key in `web_routes.py`
and `api_auth.py`) was attacker-controlled. Under HA Ingress alone
this is harmless because Supervisor controls XFF, but direct-port
deployments or deployments behind a non-stripping reverse proxy were
exposed: rate-limit buckets could be rotated per request to evade the
5/5min login and 10/5min API lockout, enabling full-speed brute force.
**Fix:** restricted to `127.0.0.1,172.30.32.2` (Supervisor's hassio
bridge address). Inline comment documents the rationale.

#### M3 — Dependency CVEs

**Found by:** pip-audit.
**Affected (runtime):**

| Package | From | To | CVEs closed |
|---|---|---|---|
| `fastapi` | 0.115.0 | 0.136.3 | (transitive pin, brings starlette 1.1.0) |
| `uvicorn[standard]` | 0.30.0 | 0.32.1 | minor patches |
| `aiohttp` | 3.10.0 | 3.13.4 | CVE-2025-69225/26/27/30, CVE-2026-22815, CVE-2026-34514 |
| `jinja2` | 3.1.4 | 3.1.6 | CVE-2024-56326, CVE-2024-56201, CVE-2025-27516 |
| `python-multipart` | 0.0.9 | 0.0.27 | CVE-2024-53981, CVE-2026-24486/40347/42561 |
| `cryptography` | 43.0.0 | 46.0.7 | GHSA-h4gh-qq45-vh27, CVE-2024-12797, CVE-2026-26007, PYSEC-2026-35, PYSEC-2026-36 |
| `starlette` (transitive via fastapi) | 0.38.6 | 1.1.0 | PYSEC-2026-161 (Host-header path bypass), CVE-2024-47874, CVE-2025-54121, CVE-2025-62727 |

**Affected (dev):**

| Package | From | To | CVEs closed |
|---|---|---|---|
| `pytest` | 8.3.3 | 9.0.3 | CVE-2025-71176 |

**Verification:** `pip-audit -r requirements.txt` now reports
"No known vulnerabilities found". All 48 tests still pass after the
bumps. Container builds clean.

### Low

#### L1 — Raw UNVR error bodies surfaced in the in-app UI

**Found by:** code-review agent.
**Files:** `access_client.py:128-135`, `protect_client.py:82-88`.
**Issue:** `AccessClientError(f"Login failed with HTTP {status}: {text}")`
displayed the raw response body on the Settings page. Today this is
benign UniFi text ("Unauthorized") but future firmware could include
internal hostnames or version strings.
**Fix:** log the raw response body at warning level (truncated to 500
chars), show users a sanitized message ("UniFi rejected the credentials
(HTTP 401)" etc.).

#### L2 — `try / except / pass` patterns suppressed diagnostics

**Found by:** Bandit B110, x2.
**File:** `web_routes.py:1481, 1492`.
**Issue:** Settings-page-rendering code silently swallowed exceptions on
optional decryption and HA-entity fetch paths. Not a security issue per
se but blind to operational problems.
**Fix:** replaced both with `except Exception as exc: logger.warning(...)`.
Behavior unchanged; failures now leave a trail.

#### L3 — `random.random()` for WebSocket reconnect backoff jitter

**Found by:** Bandit B311.
**Files:** `access_client.py:606`, `protect_client.py:190`.
**Issue:** Backoff jitter used the non-CSPRNG `random` module. The jitter
is not security-critical (its only job is to spread reconnect
collisions), so this was always a false-positive-grade finding. Fixed
anyway, since the cost is one line.
**Fix:** swapped to `secrets.SystemRandom().random()`.

### Documented operational risks (no code fix)

#### O1 — First-run setup race on direct-port deployments

**Found by:** code-review agent.
**Issue:** `/setup` is correctly exempt from CSRF and from `require_login`
(it's the only POST that can run without authentication — it's the path
that *creates* the admin). Under HA Ingress this is gated by
`panel_admin: true` + Supervisor's `X-Remote-User-Is-Admin` check, so
only HA admins can reach it. **For direct-port deployments**, an
attacker on the same LAN could race the maintainer and POST `/setup`
first, claiming admin.
**Mitigation:** documented in `SECURITY.md` under "Known operational
guidance → Direct-port deployments need a trusted network during
first-run setup." The default add-on configuration is ingress-only, so
this risk does not apply to standard installs.

#### O2 — `/data/access_control.db` is equivalent to the keychain

**Found by:** code-review agent.
**Issue:** The SQLite database stores the plaintext `secret_key` and
`encryption_salt`. Anyone with read access to the file can derive the
Fernet key and decrypt every stored credential and visitor PIN.
**Mitigation:** documented in `SECURITY.md` under "Known operational
guidance → Treat `/data/access_control.db` as a secret." The
`ACCESS_CONTROL_SECRET_KEY` env-var override is documented as the
recommended hardening for users who want the signing key out of the
database.

### False positives suppressed

| Finding | File:Line | Reason | Suppression |
|---|---|---|---|
| Bandit B608 (SQL injection via f-string) | `database.py:962` | `placeholders` is a `?`-only string; values bound via parameter list | `# nosec B608 — placeholders only` + multi-line comment |
| Bandit B608 | `database.py:1383, 1388` | `cutoff_sql` contains only an `int()`-cast integer | `# nosec B608` + comment |
| Bandit B608 | `database.py:413` | `where` is a hardcoded `""` or `"WHERE u.hidden = 0"` | `# nosec B608 — \`where\` is a literal` |
| Bandit B608 | `database.py:469` | `placeholders` is a `?`-only string | `# nosec B608 — placeholders only` |
| Bandit B608 | `database.py:755` | `conditions` only contains hardcoded `"col = ?"` fragments | `# nosec B608 — hardcoded fragments` |

Each suppression has an inline comment explaining the rationale so a
future reader (or auditor) can verify without re-running the analysis.

### Deferred / external

| Issue | Source | Why deferred |
|---|---|---|
| Go runtime CVEs in HA base image (12 HIGH) | Trivy | Bundled in `ghcr.io/home-assistant/{arch}-base-python:3.12-alpine3.21`. Will fix when HA bumps the base image; tracking via Dependabot's Docker ecosystem updates. |
| WAL file retention of pre-checkpoint pages | code-review agent | Informational only. `PRAGMA wal_checkpoint(TRUNCATE)` recommended in docs after a `secret_key` rotation. |

## Verification summary

After all fixes:

- ✅ `pytest` — 48 passed, 2 skipped (same as before audit; no regressions)
- ✅ `bandit -r access_control/rootfs/opt/access_control` — 0 Medium, 0 High, 1 Low (B311 in tests we don't scan; Run metrics confirm 6 nosec suppressions applied)
- ✅ `pip-audit -r requirements.txt` — "No known vulnerabilities found"
- ✅ `gitleaks` — no leaks
- ✅ Container builds cleanly; `/health/live` returns 200
- ✅ uvicorn process verified running with `--forwarded-allow-ips=127.0.0.1,172.30.32.2`

## Outstanding items + recommended cadence

| Item | Owner | Recommended cadence |
|---|---|---|
| HA base image CVEs | Dependabot Docker updates | Weekly Monday auto-PR |
| Python dep CVEs | Dependabot pip updates | Weekly Monday auto-PR |
| GitHub Actions updates | Dependabot github-actions group | Weekly Monday auto-PR |
| Manual security audit | Maintainer | Annually, or after any major change to the auth / ingress / crypto code paths |
| Bandit/pip-audit in CI | TODO — future enhancement | Add to `ci.yaml` so every PR runs them |

## Threat model assumptions

- **HA admin** is the trust boundary for everything in the dashboard. A
  malicious HA admin can do anything this app does (it's their app). We
  do not defend against this.
- **HA Supervisor** is trusted. We trust the `X-Remote-User-*` headers
  it sets, conditioned on a valid `X-Ingress-Path`. If Supervisor itself
  is compromised, the SSO model collapses — but so does HA at that
  point.
- **The UniFi Console** is trusted to enforce its own access decisions
  on the physical relay. This app rides on UniFi's events and uses HA's
  locks for the physical action; it doesn't replace UniFi's auth.
- **The host network** is **not** trusted. The default ingress-only
  deployment means the only traffic the app sees is from Supervisor's
  proxy; this is the safe baseline.

## Acknowledgements

- The `pr-review-toolkit:code-reviewer` agent for the manual code review
  pass.
- The Python community for `bandit`, `pip-audit`.
- Aqua Security for `trivy`.
- Zricethezav for `gitleaks`.
