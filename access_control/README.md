# Home Assistant Add-on: Access Control

Unified access control dashboard bridging **UniFi Access + Protect** with
**Home Assistant** locks and alarm panels.

## Quick start

1. Add the repository in **Settings → Add-ons → ⋮ → Repositories**:

   ```text
   https://github.com/nstefanelli/hassio-access-control
   ```

2. Install **Access Control** from the add-on store. Start it.

3. Open it from the HA sidebar (admins only) or via "Open Web UI" on the
   add-on page.

4. Complete the on-screen setup wizard (UniFi Console host + service
   account). HA URL + token are auto-configured by default.

5. Visit **Locks** to wire HA lock entities to physical doors / readers.

## Configuration options

| Option | Default | Description |
|--------|---------|-------------|
| `log_level` | `info` | One of `trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal` |
| `use_supervisor_api` | `true` | Auto-configure HA URL + token from `SUPERVISOR_TOKEN`. Set to `false` to point the add-on at a different HA instance. |

The web UI binds to port `8080` inside the container and is reached
through HA Ingress — there's no host-side port mapping by default.
Credentials and per-installation settings are entered through the in-app
**Settings** page (encrypted in `/data`).

## Manual install (private repository)

If the repository is private (the Supervisor "Add repository" UI can't
clone private repos):

```bash
# Via the Advanced SSH & Web Terminal add-on (Protection Mode off)
cd /addons
git clone https://github.com/nstefanelli/hassio-access-control.git
```

Then in HA: **Settings → Add-ons → Add-on Store → ⋮ → Reload**.
The add-on appears under **Local add-ons**.

## Persistence

All state lives in `/data/access_control.db` (SQLite with WAL). The
volume survives add-on restarts and updates; Supervisor backups include
`/data` automatically.

## Architecture and security

See the [main README](https://github.com/nstefanelli/hassio-access-control)
for the full architecture diagram, security model, and resilience details.

## Support

Issues: <https://github.com/nstefanelli/hassio-access-control/issues>

## License

MIT — see [LICENSE](https://github.com/nstefanelli/hassio-access-control/blob/main/LICENSE).
