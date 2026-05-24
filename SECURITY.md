# Security Policy

## Supported versions

Security fixes are applied to the latest minor release on `main`. Older
versions are not patched separately; upgrading to the latest release is
the supported way to receive fixes.

| Version | Status |
|---------|--------|
| 1.1.x   | ✅ supported |
| 1.0.x   | ❌ superseded by 1.1.0 — please upgrade |

This is a hobby project maintained in spare time. There is **no SLA**.
Best-effort response targets are listed below; please don't read them as
guarantees.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use **GitHub's Private Vulnerability Reporting** instead:

1. Go to <https://github.com/nstefanelli/hassio-access-control/security>
2. Click **Report a vulnerability**
3. Fill in what you found, how to reproduce, and impact

A private advisory is created that only you and the maintainer can see.
Patches and CVE coordination happen in that thread; the advisory is
published when (and if) a fix ships.

### Out-of-band contact

If GitHub Private Vulnerability Reporting is unavailable to you for some
reason, you can also message [@nstefanelli](https://github.com/nstefanelli)
on GitHub directly with the subject line "SECURITY:" and a request for a
private channel.

## Known operational guidance

Two things are worth knowing before you deploy:

### Treat `/data/access_control.db` as a secret

The SQLite database at `/data/access_control.db` contains:

- The `secret_key` used to sign session cookies and derive the Fernet
  key for encrypting UniFi + HA credentials at rest
- The `encryption_salt` used in PBKDF2 key derivation
- Encrypted-but-recoverable UniFi service-account credentials and HA
  long-lived token (recoverable if you have `secret_key` + salt)
- Encrypted visitor PINs (same recoverability)
- The bcrypt-equivalent hash of the in-app admin password

**Anyone with read access to this file recovers the entire keychain.**
Treat backup copies of the database the same way you treat the secrets
themselves. Don't email it, don't drop it in a public bug report,
don't store it on shared drives.

For hardened deployments, override the signing key via the
`ACCESS_CONTROL_SECRET_KEY` environment variable (read by `main.py` at
startup) and keep that value in your secrets manager rather than in
`/data`.

### Direct-port deployments need a trusted network during first-run setup

The setup wizard (`/setup`) is the only POST route that can run without
authentication — the first successful POST sets the admin credentials.
Inside HA Ingress, this is gated by Supervisor's `auth_api: true` flow
(only HA admins can reach `/setup` at all). But if you deploy this app
with a direct host-port mapping (not the default) and your container is
reachable over a shared LAN before you complete setup, an attacker on
the same network could race you and create the admin account first.

Mitigations:

- The default add-on configuration uses HA Ingress only — no host port,
  so this race doesn't apply
- For direct-port deployments, complete setup over a trusted network
  (e.g. localhost via SSH tunnel) before exposing the port

## What's in scope

- The Access Control app's Python code (`access_control/rootfs/opt/access_control/`)
- The HA app packaging (`access_control/config.yaml`, `Dockerfile`, `run.sh`,
  `apparmor.txt`)
- The middleware stack (ingress, CSRF, session, rate-limiting)
- Authentication / authorization logic (`auth_engine.py`, `web_auth.py`,
  `ingress.py`)
- Credential handling and encryption-at-rest (`config.py`, the SQLite
  `config` table)
- The published container images on `ghcr.io`

## What's out of scope

- Vulnerabilities in Home Assistant itself, Home Assistant Supervisor, or
  HAOS — please report those upstream at
  <https://github.com/home-assistant/core/security>
- Vulnerabilities in UniFi Access, UniFi Protect, or UniFi OS — report at
  <https://www.ui.com/security>
- Vulnerabilities in third-party dependencies (FastAPI, aiohttp, etc.) —
  report upstream first; if you believe a fix needs to be backported into
  this app, open a separate report after upstream confirmation
- Issues that require an attacker to already have HA admin access (HA
  admin is the trust boundary for this app)
- Denial-of-service that requires unrealistic conditions (e.g., sending
  millions of requests per second from inside the HA container network)

## Response targets

Best-effort, not promises:

| Stage | Target |
|-------|--------|
| Acknowledge report | 1 week |
| Initial triage | 2 weeks |
| Patch released (critical) | within 30 days of confirmation |
| Patch released (non-critical) | next minor release |
| Public advisory | after a patch is available, with reporter credit |

If you don't hear back within 2 weeks of an acknowledgement, feel free
to ping the report or use the out-of-band contact above.

## Credit

Reporters who follow this policy are credited in the GitHub Security
Advisory and the release notes for the fix, unless you ask to remain
anonymous.

Thank you for helping keep this project safe.
