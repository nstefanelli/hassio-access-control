# Access Control — REST API

External programs (Home Assistant automations, scripts, dashboards on
other hosts) can drive the app through a small Bearer-token REST API.
Use it to:

- Mirror the app's connection state into HA sensors
- Trigger lockdown mode from an automation
- Pull the recent access log into your dashboards
- Build per-user reporting outside the app

The dashboard itself does **not** use this API — it uses a separate
session-cookie + CSRF path under `/locks`, `/users`, etc. The two
paths share the underlying database but have different auth.

## Reaching the API

The app's web UI is reached through HA Ingress and has no host-side
port. Reach the REST API the same way:

- **From inside HA** — automations using `rest_command` /
  `rest` sensors, or other add-ons on the Supervisor's `hassio` network,
  can hit `http://<container-name>:8080/api/...` directly.
- **From outside HA** — proxy through HA's own REST API. Easiest path:
  configure a `rest_command` in HA and call that from your external
  client via HA's standard token authentication. The Access Control
  request stays inside the HA network.

Direct external access to the app's API is not supported by default —
flip `ports` back on in `config.yaml` if you absolutely need it, and
expect to wear the security cost (no HA SSO, no ingress proxy).

## Authentication

Every `/api/*` request needs an `Authorization: Bearer <api-key>`
header. Generate API keys on the in-app **Settings** page. The raw
key value is shown **once** at creation; only the SHA-256 hash is
stored. Lose the key, you generate a new one.

```http
GET /api/health HTTP/1.1
Authorization: Bearer ac_3xampleK3y_aBcDeF...
```

### Scopes

Each key has one of three scopes:

| Scope | What it can do |
|-------|----------------|
| `full` | All endpoints, including admin actions (lockdown, debug). Default scope; use sparingly. |
| `read_only` | All GET endpoints (health, log, locks, users). Cannot toggle lockdown. |
| `locks_only` | GET `/api/locks` + GET `/api/health` only. For automations that need lock state but shouldn't see user data. |

Insufficient scope → `403 Forbidden` with `{"detail": "API key scope 'X' insufficient"}`.

### Rate limiting

10 authentication failures per IP per 5 minutes triggers a 60-second
lockout — `429 Too Many Requests`. Successful requests reset the
counter. There is **no rate limit on successful authenticated
requests**; you can poll as often as you want, within reason.

## Endpoints

### `GET /api/health`

System health snapshot. Any scope.

**Response 200:**

```json
{
  "status": "ok",
  "unvr_connected": true,
  "protect_connected": true,
  "ha_connected": true,
  "ha_last_error": null,
  "ha_circuit_state": "closed",
  "websocket_connected": true,
  "user_count": 14,
  "lock_count": 3,
  "lockdown": false
}
```

| Field | Meaning |
|-------|---------|
| `status` | Always `"ok"` if the request was authenticated. Use HTTP status for liveness. |
| `unvr_connected` | Most recent state of the UniFi Access REST session. |
| `protect_connected` | Most recent state of the UniFi Protect WebSocket. |
| `ha_connected` | Last test result against HA. False during a Supervisor restart. |
| `ha_last_error` | Last error string from a failed HA call, or `null`. |
| `ha_circuit_state` | `"closed"`, `"open"`, or `"half_open"`. See the circuit-breaker section in the main README. |
| `websocket_connected` | Access WebSocket open. False during a UNVR restart. |
| `user_count` | Distinct users in the local DB. Includes hidden users. |
| `lock_count` | Configured locks (HA-external + UniFi native), including hidden. |
| `lockdown` | True if lockdown mode is active. All grants are denied while true. |

**Use case:** wire this into an HA REST sensor that polls every minute
and you'll get a single status badge on your dashboard.

---

### `GET /api/log`

Recent access events. Scope: `full` or `read_only`.

**Query parameters:**

| Param | Type | Default | Range | Meaning |
|-------|------|---------|-------|---------|
| `limit` | int | 50 | 1–1000 | Number of most recent entries to return. |

**Response 200:**

```json
{
  "entries": [
    {
      "id": 4218,
      "timestamp": "2026-05-23T15:29:34+00:00",
      "user_id": 1,
      "user_name": "Alex Morgan",
      "lock_id": 1,
      "lock_name": "Front Door (Aqara U400)",
      "method": "face",
      "result": "granted",
      "reason": "Family group"
    },
    {
      "id": 4217,
      "timestamp": "2026-05-23T15:18:12+00:00",
      "user_id": 3,
      "user_name": "Sam Rivera",
      "lock_id": 1,
      "lock_name": "Front Door (Aqara U400)",
      "method": "pin_code",
      "result": "denied",
      "reason": "Cleaning Service: outside schedule"
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `id` | Auto-incrementing primary key. Stable across restarts. |
| `timestamp` | ISO 8601 in UTC. |
| `method` | One of `face`, `nfc`, `pin_code`, `fingerprint`, `remote_unlock`, `device_auth`. |
| `result` | `granted`, `denied`, or `error`. |
| `reason` | Human-readable explanation (group name, denial cause, etc.). |

Log entries are retained for 90 days. Older entries are pruned by the
nightly retention loop.

**Use case:** populate an HA dashboard with the last N events, or
forward to a SIEM via a small relay script.

---

### `GET /api/locks`

All configured locks with current state. Scope: `full`, `read_only`, or
`locks_only`.

**Response 200:**

```json
{
  "locks": [
    {
      "id": 1,
      "name": "Front Door (Aqara U400)",
      "type": "ha_external",
      "entity_id": "lock.front_door",
      "location_id": "loc-001",
      "buzz_enabled": 1,
      "buzz_duration": 5,
      "relock_on_remote": 0,
      "relock_on_device_auth": 0,
      "relock_duration": 30,
      "hidden": 0
    }
  ]
}
```

`type` is either `ha_external` (HA `lock.*` entity driven via the HA
REST API) or `native` (UniFi Access lock_rule driven via UniFi's API).

**Use case:** dynamically populate a dashboard of all door-state
indicators. Pair with HA's own `lock.*` state listeners so you don't
have to poll for state changes — this endpoint gives you the *config*,
not live state.

---

### `GET /api/users`

All users known to the app. Scope: `full` or `read_only`.

**Response 200:**

```json
{
  "users": [
    {
      "id": 1,
      "ulp_id": "u-001",
      "name": "Alex Morgan",
      "email": "alex@example.com",
      "status": "ACTIVE",
      "hidden": 0
    },
    {
      "id": 4,
      "ulp_id": "u-004",
      "name": "Casey Park - Visitor",
      "email": "",
      "status": "ACTIVE",
      "hidden": 0
    }
  ]
}
```

`ulp_id` is the UniFi Access user-platform ID — useful for correlating
across UniFi's own API. `status` reflects UniFi's "active" /
"deactivated" state.

---

### `POST /api/lockdown`

Toggle lockdown mode. Scope: `full` only.

While lockdown is active, **every** access event is denied at the auth
engine, regardless of group / schedule / individual rules. Locks
controlled directly via HA still work (e.g., a manual unlock from the
HA dashboard) — lockdown only affects the auth-engine path.

**Request:** no body required.

**Response 200:**

```json
{ "lockdown": true }
```

(The new state. The endpoint is a toggle — call again to disable.)

**Use case:** an HA automation tied to a panic button on a HASS keypad,
or a "leaving for vacation" scene. Pair with HA's alarm panel for the
canonical secure-the-house workflow.

---

### `GET /api/debug`

Internal diagnostic snapshot — connection reconnect counters, circuit
breaker state, seconds since last event per WebSocket client, pending
re-lock divergence. Scope: `full` only.

**Response 200:**

```json
{
  "access_closed_connections": 4,
  "protect_closed_connections": 2,
  "access_ws_connected": true,
  "protect_ws_connected": true,
  "access_secs_since_last_event": 18.3,
  "protect_secs_since_last_event": 245.1,
  "ha_connected": true,
  "ha_last_error": null,
  "ha_circuit_state": "closed",
  "ws_last_event": "2026-05-23T15:29:34+00:00",
  "pending_relocks_live": 1,
  "pending_relocks_db": 1
}
```

Notable signals:

- `access_secs_since_last_event > 14400` (4 hours) — the WS zombie
  watchdog will force a reconnect on its next 5-minute tick.
- `pending_relocks_db > pending_relocks_live` — the difference is stuck
  re-lock rows that need HA-side recovery. Should drop to 0 when HA
  reconnects.
- `ha_circuit_state != "closed"` — HA REST calls are paused; check
  `ha_last_error`.

**Use case:** an HA template sensor that watches for stuck re-locks or
prolonged WS silence, with an alert on either condition.

---

## Unauthenticated endpoint

### `GET /health/live`

Liveness probe. No auth, no scope. Returns `{"status":"ok"}` 200 as long
as the FastAPI process is up and serving. Use this for external uptime
monitors; do not use it for application-level health (it will report
"ok" even if UNVR and HA are both down — for that, use `GET /api/health`
with a key).

---

## Examples

### HA REST sensor for health

```yaml
sensor:
  - platform: rest
    name: Access Control health
    resource: http://<container>:8080/api/health
    headers:
      Authorization: !secret access_control_api_key
    value_template: >-
      {{ 'ok' if value_json.unvr_connected and value_json.ha_connected else 'degraded' }}
    json_attributes:
      - unvr_connected
      - protect_connected
      - ha_connected
      - ha_circuit_state
      - lockdown
      - user_count
      - lock_count
    scan_interval: 60
```

Add to `secrets.yaml`:

```yaml
access_control_api_key: "Bearer ac_yourkey..."
```

### HA `rest_command` for lockdown toggle

```yaml
rest_command:
  access_control_toggle_lockdown:
    url: http://<container>:8080/api/lockdown
    method: POST
    headers:
      Authorization: !secret access_control_api_key
```

Then call `rest_command.access_control_toggle_lockdown` from any
automation.

### Shell script: tail the last 5 events

```bash
curl -s \
  -H "Authorization: Bearer $ACCESS_CONTROL_KEY" \
  "http://<host>:8080/api/log?limit=5" \
  | jq -r '.entries[] | "\(.timestamp) \(.result) \(.user_name // "?") at \(.lock_name)"'
```

### Python: poll for stuck re-locks

```python
import httpx

r = httpx.get(
    "http://<host>:8080/api/debug",
    headers={"Authorization": f"Bearer {API_KEY}"},
    timeout=5,
)
r.raise_for_status()
data = r.json()
stuck = data["pending_relocks_db"] - data["pending_relocks_live"]
if stuck > 0:
    raise RuntimeError(f"{stuck} stuck re-lock rows — HA may be unreachable")
```

## Error responses

All endpoints return JSON for errors except where the response is a
plain text from FastAPI's default handlers.

| Status | When |
|--------|------|
| `200` | Success |
| `401` | Missing or invalid API key |
| `403` | API key scope insufficient for this endpoint |
| `422` | Invalid query parameter (e.g. `limit=0`) |
| `429` | Rate limit hit (10 auth failures / 5 min from same IP) |
| `500` | Internal error — check the app log |

## Versioning

The API surface is small and is treated as part of the app's public
contract. Breaking changes will:

- Bump the minor version (`1.1.x` → `1.2.0`)
- Be called out in `CHANGELOG.md` under a **Breaking** subsection
- Keep the old shape working for at least one minor release where
  practical

Adding a new field to an existing response is **not** considered a
breaking change. Removing or renaming a field is.
