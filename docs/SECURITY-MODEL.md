# Security model

Access Control can issue physical unlock and alarm commands. Treat its Home
Assistant host, UniFi account, database, backups, API keys, and release images
as security-sensitive infrastructure.

For private vulnerability reporting and supported versions, see the repository
[Security Policy](../SECURITY.md).

## Assets

The application protects or handles:

- authority to unlock configured HA locks and UniFi-native doors;
- authority to arm/disarm configured alarm panels;
- UniFi Access/Protect credentials, the optional Access Open API token, and an
  optional remote HA token;
- API keys, dashboard sessions, CSRF tokens, alarm PINs, and visitor PINs;
- household identities, schedules, door topology, and access/admin history;
- persistent lockdown, pending re-lock state, hub hold-open ownership, and
  confirmed bidirectional-sync origin snapshots.

The SQLite database and a usable encryption key together are equivalent to the
application keychain. A full HA backup containing the app should receive the
same protection.

## Trust boundaries

### Trusted

- **Home Assistant administrators.** Every HA admin can operate the dashboard.
  There is no second role model inside the app.
- **Home Assistant Supervisor and Core.** The default deployment trusts
  Ingress identity headers and the Supervisor-provided HA token.
- **The configured Home Assistant instance.** Its entity state and service
  calls can affect physical locks, alarms, and optional hub sync.
- **The configured UniFi consoles.** Their events identify the credential,
  person, location, and action that enter the authorization engine.
- **The application container and host.** Root/host access can read runtime
  memory, environment variables, and `/data`.

### Not independently defended

- A malicious HA administrator.
- A compromised Supervisor/Core host.
- A malicious or compromised co-resident Home Assistant app with network
  access to this container.
- A compromised UniFi console or stolen UniFi service account.
- An on-path attacker between the app and a UniFi console on a network where
  TLS verification is disabled.
- Physical attacks on readers, locks, relays, or wiring.

## Dashboard authentication

The supplied manifest exposes the dashboard only through HA Ingress and marks
the panel admin-only. Middleware accepts an Ingress-shaped request, rejects a
non-admin HA identity, and passes the HA display name into audit records.

The `X-Ingress-Path` check validates format and configures the per-session URL
prefix; it does **not** cryptographically validate the opaque token. A
co-resident app that can reach port `8080` directly may be able to forge the
expected headers. This is an accepted Home Assistant host/app trust boundary,
not a claim that the headers are secure against a compromised neighboring app.

Direct-container mode uses a signed, four-hour sliding session cookie. Cookies
are `HttpOnly`, `Secure`, `SameSite=Lax`, and scoped to the current Ingress
prefix so they are not sent to unrelated HA paths. Background page polling does
not refresh the cookie indefinitely.

All state-changing dashboard routes require a signed CSRF token tied to the
authenticated identity. First-run setup is the exception because no session
exists yet; it is available only before configuration, is rate limited, and
cannot be replayed after `admin_username` exists.

In an unsupported/direct-port deployment, that unauthenticated first-run POST
creates the initial administrator. Complete setup while the port is bound to
localhost or a trusted maintenance network; rate limiting does not prevent a
different reachable client from winning the first-setup race. Standard HA
Ingress keeps the port unexposed and relies on the HA-admin gate.

Request-body limits are enforced before form parsing, including requests that
use chunked transfer encoding. Dynamic/authenticated responses are marked
non-cacheable, and static assets use an explicit cache policy. Security headers
apply to ordinary and early middleware responses.

## External API authentication

Every `/api/*` route requires a Bearer key. Keys are generated with a
cryptographically secure random source; only a SHA-256 digest is stored. The raw
key is displayed once. Scope checks are endpoint-specific:

- `full`: all current endpoints;
- `read_only`: health, log, locks, and users;
- `locks_only`: health plus explicit lock/unlock/follow-schedule operations;
  it cannot change authorization schedules, lockdown, or alarm state.

`PUT /api/locks/{id}/mode` directly operates a lock through the same confirmed
command path as the dashboard. Only `full` API keys retain the dashboard's
optional alarm auto-disarm side effect; `locks_only` keys never disarm panels.
`POST /api/lockdown` is a `full`-scope administrative action and requires an
explicit `enabled=true` or `enabled=false` query value. It sets desired state;
repeating the same request cannot accidentally invert lockdown as the former
toggle contract could.

Invalid API-key values are rate limited by the trusted client IP. Successful
requests clear an existing failure record but do not write a new record on the
normal hot path. API keys are bearer secrets: TLS and a trusted path are still
required wherever the API is exposed.

## Encryption and key management

Credentials, the Access Open API token, alarm codes, and optional PINs are
encrypted with Fernet. Its 32-byte key is derived using
PBKDF2-HMAC-SHA256 with a per-installation salt and 480,000 iterations. The same
installation secret signs dashboard session/CSRF values.

The first setup permanently selects one mode:

- **Database-key mode:** a random secret is stored in SQLite. This protects
  values from casual plaintext inspection but not from an attacker who obtains
  the whole database.
- **Environment-key mode:** `ACCESS_CONTROL_SECRET_KEY` is supplied during
  first setup, is not stored in SQLite, and must match a stored fingerprint on
  every start. Database and external key must be backed up separately.

A database-mode installation ignores an environment key added later. An
environment-mode installation refuses to start with a missing/mismatched key.
This avoids silent decryption under the wrong key. There is no supported
in-place mode switch or automatic key rotation.

Environment variables can also override decrypted upstream credentials at
runtime, but the stored database must remain structurally complete and
decryptable. Do not assume environment overrides let you discard the database
copy of existing configuration.

`ACCESS_CONTROL_ACCESS_API_TOKEN` is the runtime override for the encrypted
Access Open API token. A non-empty value selects official API mode just as a
stored token does. Configured-token authentication, permission, transport, and
schema errors never downgrade to the private session endpoint; an operator
must repair or explicitly clear the token. This avoids silently changing rule
semantics at a physical-access boundary.

Related configuration fields are serialized and committed as one logical
bundle. First-run secret metadata/credentials and multi-field Settings changes
are not intentionally exposed in a partly updated state. Candidate upstream
clients are authenticated before their live references replace known-good
clients.

The first authenticated Access setup also persists a SHA-256 namespace identity
derived from stable console/site/host-ID/unique-ID candidates, with authenticated
Access-building IDs as the topology fallback. Initial login, Settings
candidates, REST reauthentication, WebSocket reconnect, and topology refresh
must match that persisted value before credentials/cookies or site-scoped
identifiers are published to runtime callers.
Only same-site Access host or single/split-console changes are supported in
place. A different site requires fresh initialization and a policy/mapping
review so reused upstream IDs cannot inherit grants, visitor records, or hub
ownership from the old site.

## UniFi TLS trade-off

The Access and Protect clients connect to console HTTPS endpoints with
certificate verification disabled because typical UniFi consoles use locally
issued/self-signed certificates and the client has no configured CA/pinning
workflow.

This includes the Access Open API on port `12445`. Its Bearer token is isolated
in a cookieless HTTP session, but it still traverses the same unverified TLS
trust boundary. Encryption without peer authentication does not protect the
token from an on-path console impersonator.

The persisted Access site identity is a site-scoped application-namespace
check, not certificate validation or a cryptographic peer proof. The observed
certificate fingerprint is diagnostic only and is neither pinned nor used as
the site binding. An on-path attacker able to intercept login and present an
identity payload matching the enrolled namespace is not stopped by this check.

Consequences:

- encryption without peer verification does not stop an on-path console
  impersonator;
- an attacker in that position can capture the UniFi username/password during
  login or reconnect;
- WebSocket authentication retry limits reduce replay storms but do not repair
  an untrusted network.

Place HA and UniFi management traffic on a trusted, controlled network. Use a
dedicated local UniFi account and grant only the permissions needed by the
features you enable. Do not reuse the UniFi owner account.

## Physical-safety properties

The application deliberately chooses conservative behavior at critical
boundaries:

- lockdown changes and application physical commands share one barrier; once
  enabling lockdown completes, an older unlock cannot issue afterward;
- lockdown is checked at event entry and again under that barrier immediately
  before every unlock;
- lockdown persists across restart, and a persistence read error restores it
  fail-closed as enabled;
- unknown, unavailable, mixed, and transitional alarm states apply armed-state
  restrictions conservatively;
- enabled incomplete schedules fail closed;
- official Access rule writes require strict success envelopes and bounded
  rule/relay readback; a configured-token failure cannot fall back to a less
  authoritative private endpoint;
- native Lock uses `lock_now`, not `reset`; Follow Schedule alone uses `reset`
  and is documented as potentially reopening during an active native schedule;
- HA or Access states other than a confirmed `locked`/`unlocked` never drive
  hold-open and force the bidirectional pair toward locked;
- a hub-sync lockdown-state read exception behaves as enabled rather than
  allowing hold-open;
- hub-sync ownership is stored before `keep_unlock`, cleared only after a
  confirmed safe transition, and fail-safed from durable state after restart;
- Access rule events are wake-up hints only; authenticated polling/readback is
  authoritative and repairs dropped events or drift;
- an unbaselined mismatch, unreadable side, multi-hub disagreement, or opposing
  concurrent HA/Access changes resolves locked; only a verified active Access
  schedule with an unlocked relay can establish an unlocked startup baseline;
- lockdown uses `keep_lock` to close a hub previously held open by sync rather
  than `reset`, which could reactivate a schedule;
- unresolved lockdown hub locks keep lockdown enabled, return `503` to the
  API caller, and remain visible in `lockdown_enforcement_pending` health;
- pairing changes make removed hubs safe before opening replacement pairings,
  and shared-hub ownership conflicts lock/suppress every involved pairing;
- failed manual lock actions retain and restore an earlier pending re-lock;
- timed unlocks commit their replacement re-lock before physical unlock; an
  ambiguous failure retains the earliest applicable re-lock intent;
- pending re-locks persist, retry after recovery/restart, and emit a failure
  event when immediate attempts fail;
- manual and automatic HA lock commands clear durable safety state only after
  bounded reads report exactly `locked` (HA-observed state, not an independent
  mechanical sensor);
- critical remote-unlock re-lock scheduling is awaited during swaps/shutdown;
  a persistence failure attempts immediate lock and alerts if state cannot be
  confirmed;
- an empty/malformed topology response cannot deactivate every local user or
  retire every native door; valid disappearance retires a native lock from
  operation without deleting its row/history and later reappearance revives it;
- duplicate Access/Protect reports are suppressed before issuing a command.

These properties reduce risk but do not turn the app into a certified life-
safety or access-control system. Egress, fire-code behavior, fail-safe/fail-
secure hardware, and local emergency procedures remain the installer's
responsibility.

## Storage, logs, and backups

`/data/access_control.db` can contain:

- the database-managed secret or environment-key fingerprint, KDF salt, and
  hashed Access site-namespace identity;
- encrypted UniFi/HA credentials, alarm codes, visitor PINs, and user PIN data;
- the encrypted Access Open API token when configured in the dashboard;
- user names/emails, door associations, schedules, and visitor notes;
- access and administrative history;
- rate-limit, lockdown, pending re-lock, and hub hold-ownership state.

The shared SQLite connection uses autocommit for ordinary statements. Logical
multi-statement safety/configuration transitions use isolated, task-owned
connections and explicit transactions so a concurrent coroutine cannot commit
or roll back another workflow's state.

Do not attach the database, its WAL, a Supervisor backup, or unredacted logs to
a public issue. SQLite WAL pages can retain older values until checkpointed;
deleting or rotating a value at the logical layer is not a guarantee that every
old page disappeared from existing media or backups.

Use the consistent [backup and restore procedure](OPERATIONS.md#backup). A live
copy of the main database without its WAL is unsafe and may also omit committed
state.

## Container and supply chain

The app runs under an AppArmor profile that permits the broad file access
needed by the HA base image/s6 overlay and limits network families to IPv4/IPv6
TCP/UDP plus bind capability. It does not claim fine-grained filesystem
isolation inside the container. Container and host boundaries remain important.

Runtime and development Python dependencies are pinned and audited in CI.
GitHub Actions are pinned by commit SHA. CI runs tests, Bandit, `pip-audit`,
shell/YAML/Dockerfile linting, and both supported architecture builds. Release
image version tags move only during a version bump; ordinary builds use an
immutable commit-derived tag.

Container images are not currently signed (`cosign: false` in CI). Consumers
rely on GHCR/GitHub repository controls and the published tag/commit metadata.
For higher-assurance environments, mirror and verify an image digest before
deployment.

## Hardening checklist

- Keep Home Assistant, Supervisor, UniFi applications, and Access Control
  current.
- Limit HA administrator accounts and protect them with strong authentication.
- Install only trusted co-resident apps.
- Keep the default Ingress-only networking; do not publish port `8080` without
  an authenticated TLS reverse proxy and a deliberate first-run procedure.
- Use dedicated UniFi and remote-HA identities; rotate them after suspected
  exposure.
- Use an Access Open API token limited to `view:space` and `edit:space`, keep
  port `12445` on the trusted management network, and rotate the token after
  suspected exposure.
- Use narrowly scoped API keys, store them outside automations/config committed
  to source control, and revoke unused keys.
- Segment HA-to-UniFi management traffic from untrusted clients.
- Alert on re-lock/hub-sync failures and degraded connection state.
- Protect backups and test recovery. In environment-key mode, verify that the
  separate key escrow is recoverable.
- Review every mapping and schedule after restoring onto a different HA or
  UniFi installation.

## Security non-goals

- Defending against an HA administrator or host root.
- Providing per-HA-user authorization inside the dashboard.
- Validating UniFi's claim that a physical credential belongs to a particular
  person.
- Replacing certified door controllers, emergency egress, or alarm logic.
- Making a directly published HTTP port safe by default.
- Guaranteeing availability when HA, Supervisor, the LAN, or UniFi is down.
