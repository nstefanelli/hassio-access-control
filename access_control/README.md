# Access Control

Unified access control dashboard bridging **UniFi Access + Protect** with
**Home Assistant** locks and alarm panels.

This is a Home Assistant **app** *(formerly called "add-on")* — see the
[main README](https://github.com/nstefanelli/hassio-access-control) for
full features, use cases, configuration deep-dive, and screenshots.

## Quick start

1. Add the repository in **Settings → Apps → ⋮ → Repositories**:

   ```text
   https://github.com/nstefanelli/hassio-access-control
   ```

2. Install **Access Control** from the app store and start it.

3. Open it from the HA sidebar (admin users only) or via **Open Web UI**
   on the app page.

4. Complete the on-screen setup wizard (UniFi Console host + service
   account). HA URL + token are auto-configured by default.

5. Visit **Locks** to wire HA lock entities to physical doors and readers.

## Configuration options

| Option | Default | Description |
|--------|---------|-------------|
| `log_level` | `info` | One of `trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal` |
| `use_supervisor_api` | `true` | Auto-configure HA URL + token from `SUPERVISOR_TOKEN`. Set to `false` to point the app at a different HA instance. |

The web UI binds to port `8080` inside the container and is reached
through HA Ingress — there's no host-side port mapping by default.
UniFi credentials and per-installation settings are entered through the
in-app **Settings** page and stored encrypted at `/data`.

## Manual install (private repository)

If the repository is private (the Supervisor "Add repository" UI can't
clone private repos):

```bash
# Via the Advanced SSH & Web Terminal app (Protection Mode off)
cd /addons
git clone https://github.com/nstefanelli/hassio-access-control.git
```

Then in HA: **Settings → Apps → App Store → ⋮ → Reload**.
The app appears under **Local apps**.

## Persistence

All state lives in `/data/access_control.db` (SQLite + WAL). The
volume survives app restarts and updates; Supervisor backups include
`/data` automatically.

## Architecture and security

See the [main README](https://github.com/nstefanelli/hassio-access-control)
for the full architecture diagram, security model, and resilience details.

## Support

Issues: <https://github.com/nstefanelli/hassio-access-control/issues>

## License

MIT — see [LICENSE](https://github.com/nstefanelli/hassio-access-control/blob/main/LICENSE).
