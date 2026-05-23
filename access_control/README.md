# Home Assistant Add-on: Access Control

Unified access control dashboard bridging **UniFi Access + Protect** with
**Home Assistant** locks and alarm panels. Built for the G6 Entry Pro +
HA-controlled smart lock workflow, but works with any UniFi Access deployment
plus any HA `lock.*` and `alarm_control_panel.*` entities.

## What it does

- Listens to **UniFi Access** events (face / PIN / NFC / fingerprint at
  readers) and **UniFi Protect** events (doorbell ring, NFC at G6 Entry Pro)
  via dual deduplicated WebSocket paths
- Runs an authorization engine (groups, per-user rules, schedules, alarm
  gating) and unlocks the matching HA lock entity
- Provides a web dashboard for users, groups, schedules, visitor PINs,
  locks, activity log, and live health
- Wraps every HA call with a circuit breaker, and every WebSocket client
  with supervised reconnect + zombie watchdog so it survives UNVR / HA
  reboots without manual intervention
- Persists pending re-locks across add-on restarts (so an unlock-then-relock
  that was scheduled before a crash still fires)

## Quick start

1. Add this repository in **Settings → Add-ons → ⋮ → Repositories**:

   ```text
   https://github.com/nstefanelli/hassio-access-control
   ```

   *(If the repository is private, see "Manual install" below.)*

2. Install the **Access Control** add-on.

3. Start it. Open the Web UI (button on the add-on page).

4. Complete the on-screen setup wizard:
   - Admin username + password (stored hashed)
   - UNVR (UniFi Access) host + service-account credentials
   - Home Assistant URL + long-lived token *(skip if the add-on is running
     with `use_supervisor_api: true` — defaults to on — and the HA
     connection is already healthy)*
   - Optionally split Access and Protect across two consoles

5. Visit **Locks** to wire HA lock entities to physical doors / readers.

## Configuration options

| Option | Default | Description |
|--------|---------|-------------|
| `log_level` | `info` | One of `trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal` |
| `use_supervisor_api` | `true` | Auto-configure HA URL + token from `SUPERVISOR_TOKEN`. Set to `false` if you want to point the add-on at a different HA instance. |

The web UI binds to port `8080` inside the container. If you need a
different host port, remap it in the **Network** section of the add-on
page — the watchdog and "Open Web UI" button track the remap automatically.

UNVR credentials and all other settings are entered through the in-app
Settings page (encrypted in the SQLite DB on `/data`). They are intentionally
*not* exposed as add-on options to keep them out of Supervisor's plaintext
add-on config.

## Manual install (private repository)

The Supervisor "Add repository" UI clones over anonymous git, which does
not work for private repos. To install manually:

```bash
# SSH into HAOS (Advanced SSH & Web Terminal add-on, with Protection Mode off)
cd /addons
git clone https://github.com/nstefanelli/hassio-access-control.git
```

Then in the HA UI: **Settings → Add-ons → Add-on Store → ⋮ → Reload**.
The "Access Control" add-on will appear under the "Local add-ons" section.

## Networking

The add-on needs to reach:

- Your UniFi Console (UNVR / UDM Pro / etc.) on TCP/443
- Home Assistant on its REST port (8123) — handled automatically via
  `http://supervisor/core` when `use_supervisor_api` is on

Make sure those routes work from the HA host's container network. If you
run UniFi on a separate VLAN with firewall rules between it and your HA
host's subnet, you'll need to allow that traffic.

## Persistence

All state lives in `/data/access_control.db` (SQLite with WAL). This volume
survives add-on restarts and updates, but **not** uninstalls. Back it up:

```bash
# From HAOS
cp /usr/share/hassio/addons/data/<slug>_access_control/access_control.db \
   /backup/access_control-$(date +%F).db
```

## Backups

The add-on participates in the Supervisor's snapshot system out of the box —
including a full snapshot will capture `/data`.

## Architecture

See the [main README](https://github.com/nstefanelli/hassio-access-control)
for the full architecture diagram, resilience semantics, and event flow.

## Support

This add-on is published as-is. For issues, please open a GitHub issue at
<https://github.com/nstefanelli/hassio-access-control/issues>.

## License

MIT — see [LICENSE](https://github.com/nstefanelli/hassio-access-control/blob/main/LICENSE).
