# Security Policy

Access Control can issue physical door and alarm commands. Please report
security problems privately so users can update before technical details become
public.

## Supported versions

Security fixes are made on `main` and released in the newest stable line. Older
lines do not receive backports; upgrading to the latest release is the supported
remediation.

| Version | Status |
|---|---|
| Latest `1.5.x` release | Supported until superseded |
| `1.4.x` and older | Unsupported; upgrade |
| Unreleased `main` | Development branch; fixes land here first |

This is a spare-time project with no SLA. The targets below are best-effort,
not guarantees.

## Report a vulnerability

Do **not** open a public issue, discussion, or pull request for an undisclosed
vulnerability.

Use [GitHub Private Vulnerability
Reporting](https://github.com/nstefanelli/hassio-access-control/security/advisories/new)
and include:

- affected version/commit and deployment type;
- required attacker position or privileges;
- reproducible steps or a minimal proof of concept;
- physical/security impact and whether exploitation was observed;
- any suggested mitigation;
- whether you want public credit.

Remove real credentials, tokens, PINs, cookies, visitor details, and household
identifiers. If a database is essential to reproduce the issue, describe the
required rows first; do not upload a production database or backup without an
explicit private handling agreement.

If Private Vulnerability Reporting is unavailable, contact
[@nstefanelli](https://github.com/nstefanelli) on GitHub with the subject
`SECURITY:` and request a private channel. Do not put exploit details in the
initial public message.

## Response targets

| Stage | Best-effort target |
|---|---|
| Acknowledge | Within 7 days |
| Initial triage | Within 14 days |
| Confirmed critical fix | Within 30 days when feasible |
| Other confirmed fix | Next suitable release |
| Public disclosure | After a fix is available and users have a reasonable update window |

If there is no response two weeks after acknowledgement, update the private
report or use the out-of-band contact above.

## Scope

In scope:

- Python application, templates, static assets, and middleware;
- authorization, alarm, lockdown, re-lock, hub-sync, visitor, and API paths;
- Home Assistant app manifest, image, entrypoint, and AppArmor profile;
- credential encryption, sessions, CSRF, API keys, SQLite state, and backups;
- CI/release automation and published project images.

Report upstream first when the issue is wholly within Home Assistant, UniFi, or
a third-party dependency. If this project needs a mitigation or pinned update,
explain that impact in a private report here as well.

The following are normally outside this project's security boundary unless
they reveal a distinct application flaw:

- an attacker who already controls an HA administrator, Supervisor/host root,
  or the configured UniFi console;
- physical compromise of readers, relays, locks, or wiring;
- denial of service requiring unrealistic traffic from inside the trusted app
  network;
- unsupported direct-port exposure without a trusted TLS/authentication layer.

## Operational security baseline

Before deployment, read the complete [security
model](docs/SECURITY-MODEL.md). Important accepted risks include:

- Ingress identity headers are not a cryptographic boundary against another
  compromised co-resident HA app.
- UniFi console TLS certificates are not verified; management traffic must use
  a trusted network.
- The persisted Access site identity prevents accidental cross-site namespace
  reuse, but it is not a TLS certificate pin or cryptographic peer proof.
- In database-key mode, a copy of `/data/access_control.db` contains the key
  material needed to recover encrypted credentials.
- Environment-key mode is fixed at first setup, requires the exact external key
  on every start, and has no automatic rotation/mode-switch path.
- Container images are not currently signed.

Use the [operations runbook](docs/OPERATIONS.md#backup) for consistent SQLite
backup and recovery. Never publish a database, WAL, Supervisor backup, API key,
HA/UniFi credential, or environment secret.

## Credit and disclosure

Coordinated reporters are credited in the advisory and release notes unless
they request anonymity. Please allow a remediation window before publishing
technical details. The project will aim to describe the impact, affected
versions, fix, and upgrade guidance clearly without exposing unrelated user
data.

Thank you for helping keep physical-access deployments safer.
