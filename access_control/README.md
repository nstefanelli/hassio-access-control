# Access Control

Home Assistant app for coordinating **UniFi Access + Protect** credential
events with UniFi-native doors, Home Assistant `lock.*` entities, and alarm
panels.

## Features

- HA admin-only Ingress dashboard and SSO
- Face, NFC, PIN, and fingerprint authorization through groups, schedules, and
  individual rules
- Alarm-aware grants, optional auto-disarm, and persistent, barrier-ordered
  lockdown
- Pre-unlock durable timed re-lock intents with restart/recovery retry and
  physical `locked`-state confirmation
- Optional bidirectional HA-lock/Access-door synchronization, including native
  unlock schedules, event-plus-poll drift detection, and locked-wins conflicts
- Schedule-aware native controls: persistent **Unlock**, immediate **Lock**,
  and **Follow Schedule** to restore Access-native behavior
- Time-windowed UniFi visitors using HA's configured timezone
- Split Access/Protect consoles
- Persisted Access site-namespace binding across login, reconnect, and
  same-site host changes
- Activity history, health/diagnostics, and scoped Bearer API keys
- Self-hosted CSS/JavaScript with no runtime UI CDN dependency

## Quick start

1. Add this repository under **Settings → Apps → App store → ⋮ →
   Repositories**:

   ```text
   https://github.com/nstefanelli/hassio-access-control
   ```

2. Install and start **Access Control**.
3. Open the sidebar panel as an HA administrator.
4. Complete setup with the primary UNVR/Protect console and, when different,
   the optional separate Access console. With the default Supervisor option,
   HA credentials are supplied automatically. For authoritative schedule-aware
   door control, also enter an Access API token with `view:space` and
   `edit:space`; existing installations can add one later under Settings.
5. Add/map locks, then create groups and schedules before testing a physical
   grant.

## Options

| Option | Default | Description |
|---|---:|---|
| `log_level` | `info` | `trace`, `debug`, `info`, `notice`, `warning`, `error`, or `fatal` |
| `use_supervisor_api` | `true` | Use Supervisor's HA Core proxy and rotating token. Disable only for a different HA instance. |

The UI uses internal port `8080` through HA Ingress. The supplied manifest has
no host port.

First setup binds the database to the authenticated Access site namespace.
Later Access host or single/split-console changes must verify as that same site;
use a fresh initialization for a different site so its user/door identifiers
cannot inherit existing grants. This is a namespace safety check, not TLS
certificate verification; keep UniFi management traffic on a trusted network.

The recommended Access API token is created under **Access → Settings →
General → Advanced → API Token**. The app calls the official local HTTPS API on
port `12445`, stores the token encrypted, and never displays it again. A custom
deployment may supply `ACCESS_CONTROL_ACCESS_API_TOKEN` as a runtime override.
If a configured token expires or lacks permission, commands fail visibly and
do not fall back to the private session API. With no token, compatibility mode
retains the older private endpoint, but firmware-dependent rule readback cannot
always prove the physical result of returning a door to its native schedule.

For native doors, **Unlock** applies `keep_unlock`; **Lock** uses `lock_now` to
end an active unlock schedule or temporary unlock; **Follow Schedule** uses
`reset` and can immediately reopen the door if its Access schedule is active.
Opted-in HA/Access pairs synchronize in both directions. Access rule events
and HA WebSocket push events wake reconciliation immediately; an authenticated
poll catches missed events and drift, running as a 60-second backstop while
push is healthy and every five seconds otherwise. Simultaneous disagreement
or unreadable state resolves
locked; a verified active Access schedule is the only startup mismatch allowed
to establish an unlocked baseline. Lockdown always suppresses opening and
drives the safe locked direction.

Use the Home Assistant app page for manual restart. Scheduled restart is
available in the packaged Supervisor deployment; the in-dashboard manual
restart control appears only in direct-host mode when Supervisor restart or an
explicit trusted `RESTART_COMMAND` is available.

## Persistence and backups

Durable state is stored at `/data/access_control.db`. It contains sensitive
topology/history and encrypted credentials; database-key installations also
store the key required to decrypt them. The enrolled Access site identity,
pending re-locks, and app-owned bidirectional-sync `keep_unlock`/`keep_lock`
hub overrides with their door/location metadata also live there so startup can
reject a namespace change and recover physical state safely. Prefer
a Home Assistant backup that includes this app. Related credential and secret
metadata fields are committed as one serialized bundle. Never make a live raw
copy of only the SQLite main file, because committed data may still be in its
WAL.

Environment-key mode is advanced and must be selected by providing
`ACCESS_CONTROL_SECRET_KEY` during the very first setup. That exact external
key is then required on every start and must be backed up separately.

## Documentation and support

- [Full documentation](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/README.md)
- [Configuration](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/CONFIGURATION.md)
- [Operations, backup, and troubleshooting](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/OPERATIONS.md)
- [Security model](https://github.com/nstefanelli/hassio-access-control/blob/main/docs/SECURITY-MODEL.md)
- [Issues](https://github.com/nstefanelli/hassio-access-control/issues)
- [Private vulnerability reporting](https://github.com/nstefanelli/hassio-access-control/security/advisories/new)

MIT licensed.
