# REST API

Access Control exposes a JSON API for monitoring, reporting, explicit lock
control, local authorization schedules, and lockdown automation. The dashboard
does not use these credentials; it has a separate HA Ingress/session and CSRF
security path. Dashboard and API lock commands nevertheless run through the
same command barrier, confirmation, re-lock, and audit service. Alarm
auto-disarm is an additional `full`-scope capability and is never performed for
`locks_only` calls.

## Reachability

The supplied Home Assistant app is Ingress-only and does not publish port
`8080` on the HA host. Therefore it does not promise a stable public API URL.
Use the API only from a client that can reach the app's internal container
hostname/port, or place a deliberate authenticated TLS proxy in front of it.
Do not hard-code HA's per-session `/api/hassio_ingress/...` browser URL into an
automation.

Examples below use `http://<reachable-app-host>:8080`. Substitute a hostname
that is actually resolvable from the calling network. Publishing the port
directly changes the threat model described in
[Security model](SECURITY-MODEL.md).

## Authentication

Every `/api/*` request requires an API key:

```http
Authorization: Bearer <api-key>
```

Create a key on the dashboard **Settings** page. Its random value is shown once
and only its SHA-256 digest is stored. Store the value as a secret; create and
revoke a replacement if it is lost.

### Scopes

| Endpoint | `full` | `read_only` | `locks_only` |
|---|:---:|:---:|:---:|
| `GET /api/health` | yes | yes | yes |
| `GET /api/locks` | yes | yes | yes |
| `GET /api/log` | yes | yes | no |
| `GET /api/users` | yes | yes | no |
| `GET /api/debug` | yes | no | no |
| `PUT /api/locks/{lock_id}/mode` | yes | no | yes |
| `PUT /api/rules/{rule_id}/schedule` | yes | no | no |
| `POST /api/lockdown` | yes | no | no |

`locks_only` can inspect locks and set their explicit operating mode, but
cannot read identities/logs, modify authorization schedules, or control
lockdown or alarm panels. There is intentionally no Bearer API buzz endpoint: a
momentary unlock is not an idempotent desired-state operation.

An authenticated key with insufficient scope receives `403`. Missing or
invalid credentials receive `401`.

### Authentication failure rate limit

Invalid API-key values are tracked per client IP. Ten failures in a five-minute
window cause a 60-second lockout and `429 Too Many Requests`.
A valid request clears an existing failure row. Successfully authenticated
requests are otherwise not quota limited.

The client IP is meaningful only behind the trusted proxy configuration used
by the packaged app. Do not deploy behind an arbitrary forwarding proxy without
reviewing which peer can set `X-Forwarded-For`.

## Endpoint summary

All timestamps originating in SQLite are UTC strings formatted as
`YYYY-MM-DD HH:MM:SS` with no suffix. Treat response additions as compatible;
consumers should ignore unknown fields.

### `GET /api/health`

Returns a health snapshot. All three scopes are accepted.

```json
{
  "status": "ok",
  "unvr_connected": true,
  "access_open_api_configured": true,
  "access_open_api_ready": true,
  "access_open_api_error": null,
  "protect_connected": true,
  "ha_connected": true,
  "ha_last_error": null,
  "ha_circuit_state": "closed",
  "websocket_connected": true,
  "user_count": 14,
  "lock_count": 3,
  "lockdown": false,
  "lockdown_enforcement_pending": [],
  "pending_relocks": {"total": 1, "overdue": 0}
}
```

| Field | Type | Meaning |
|---|---|---|
| `status` | string | Always `ok` when the authenticated route completed. It is not aggregate upstream health. |
| `unvr_connected` | boolean | Current Access REST/session connection state. The historical field name is retained for compatibility. |
| `access_open_api_configured` | boolean | Whether the active Access client has an official Bearer token configured. |
| `access_open_api_ready` | boolean | Whether the configured official API passed its latest startup/settings validation. |
| `access_open_api_error` | string/null | Sanitized validation error class when the official API is configured but not ready. |
| `protect_connected` | boolean | Current Protect client connection state. |
| `ha_connected` | boolean | Current HA client connection state. |
| `ha_last_error` | string/null | Most recent HA error, if any. |
| `ha_circuit_state` | string | HA circuit breaker: `closed`, `open`, or `half_open`. |
| `websocket_connected` | boolean | Access WebSocket state. |
| `user_count` | integer | All local user rows, including hidden/deleted-upstream rows. |
| `lock_count` | integer | Operable configured lock rows, including hidden rows but excluding upstream-missing native locks. |
| `lockdown` | boolean | Current authorization-engine lockdown state. It normally matches persistence; on a failed transition the safer in-memory state can remain enabled while the request reports `503`. |
| `lockdown_enforcement_pending` | array of strings | HA entity IDs whose synced Access hubs are not yet confirmed locked under the active lockdown. A non-empty list requires operator attention/retry. |
| `pending_relocks` | object | Durable re-lock intent counts: `total` rows and how many are `overdue` (past their deadline and still retrying). Counts only — entity IDs are deliberately omitted so the lowest-privilege scope stays safe. A non-zero `overdue` means a door the app promised to re-lock is not confirmed locked; see the Locks page badges and the `access_control_relock_failed` event. |

Use `GET /health/live` for process liveness and this endpoint for component
health. Do not alert from `status` alone.

### `GET /api/log`

Returns recent access/activity rows. Scope: `full` or `read_only`.

Query:

| Parameter | Default | Constraint |
|---|---:|---|
| `limit` | 50 | Integer from 1 through 1000 |

```json
{
  "entries": [
    {
      "id": 4218,
      "timestamp": "2026-07-12 15:29:34",
      "user_id": 1,
      "user_name": "Alex Morgan",
      "lock_id": 1,
      "lock_name": "Front Door",
      "method": "face",
      "result": "granted",
      "reason": null
    }
  ]
}
```

Rows can also represent denials, errors, manual actions, hub sync, doorbell
rings, and system information. Do not build an enum from the example values
without allowing future methods/results. Nullable identity/lock fields are
expected for events that cannot be attributed to a user or lock.

Access-log retention is 90 days.

### `GET /api/locks`

Returns non-hidden, operable lock configuration. Scope: all three scopes.

```json
{
  "locks": [
    {
      "id": 1,
      "type": "ha_external",
      "device_id": null,
      "location_id": null,
      "entity_id": "lock.front_door",
      "name": "Front Door",
      "door_name": null,
      "buzz_enabled": 1,
      "buzz_duration": 30,
      "remote_buzz_enabled": 0,
      "access_location_id": "location-id",
      "sync_hub_state": 0,
      "relock_on_remote": 1,
      "relock_on_device_auth": 1,
      "relock_duration": 30,
      "hidden": 0
    }
  ]
}
```

The schema is migration-aware, so current rows may contain compatibility
columns in addition to those shown. Boolean configuration values are currently
serialized as SQLite integers. `type` is `access_native` or `ha_external`.
Native rows retained for history after disappearing from a valid Access
topology snapshot are upstream-missing and omitted; they return automatically
if the same location is rediscovered.

This endpoint returns configuration, not an authoritative live state for every
lock. Read HA entity state or the relevant upstream system when live state is
required.

### `PUT /api/locks/{lock_id}/mode`

Sets an explicit desired operating mode. Scope: `full` or `locks_only`.
The JSON body is:

```json
{
  "mode": "force_locked"
}
```

`mode` is exactly one of:

| Mode | HA external lock | Native UniFi Access lock |
|---|---|---|
| `force_locked` | Calls HA lock and confirms the entity becomes exactly `locked`. | Issues Access's immediate-lock operation, ending an active scheduled/temporary unlock, and confirms the door is locked. |
| `hold_unlocked` | Calls HA unlock and confirms the entity becomes exactly `unlocked`. A pending app re-lock is canceled only after confirmation. | Applies Access `keep_unlock` and confirms both its rule and unlocked state. |
| `follow_schedule` | Rejected with `409`; HA schedules are outside this app's override model. | Clears the app's native override and confirms Access accepted the reset, returning control to the Access schedule. |

Restoring an Access schedule can immediately open a door when its unlock window
is active. Consequently, lockdown rejects both `hold_unlocked` and
`follow_schedule` with `409`; `force_locked` remains available as a fail-safe
direction. The lockdown decision is checked again inside the shared physical-
command barrier immediately before the command.

Success returns `200` only after confirmation:

```json
{
  "lock_id": 1,
  "mode": "hold_unlocked",
  "result": "granted",
  "confirmed": true,
  "confirmed_state": "unlocked",
  "reason": null
}
```

For `follow_schedule`, `confirmed_state` is `scheduled`: this confirms that the
override was cleared, not that the physical door is necessarily closed. The
active Access schedule determines its resulting state.

The endpoint is idempotent desired-state control. Repeating the same mode does
not invert it. A repeat may still reassert and re-confirm the upstream state,
which makes bounded automation retries safe. Commands are audited as
`api_lock`, `api_unlock`, or `api_restore_schedule`, attributed to the API key
name without recording its Bearer secret.

Failures use the same response shape with `confirmed: false` and a sanitized
`reason`: `404` means the configured/operable lock does not exist, `409` means
the requested mode conflicts with lockdown or the lock type, and `503` means
the required client was unavailable, rejected the command, or did not confirm
the requested result. A `503` must not be treated as proof that no physical
transition occurred; inspect the authoritative controller state before an
unsafe compensating action.

### `GET /api/users`

Returns non-hidden synchronized users. Scope: `full` or `read_only`.

```json
{
  "users": [
    {
      "id": 1,
      "ulp_id": "upstream-user-id",
      "name": "Alex Morgan",
      "email": "alex@example.invalid",
      "status": "ACTIVE",
      "hidden": 0,
      "synced_at": "2026-07-12 15:20:00",
      "rule_count": 2
    }
  ]
}
```

`ulp_id` is the UniFi Access user identifier. `status` is synchronized from
UniFi or set by an app-level administrative action. `rule_count` counts direct
individual access rules; group membership is separate. Sensitive encrypted PIN
material is not part of the public response contract.

### `PUT /api/rules/{rule_id}/schedule`

Replaces the local authorization schedule on one individual user/lock rule.
Scope: `full` only. This is the JSON equivalent of the schedule editor on the
user detail page; both paths use the same validation and SQLite fields.

```json
{
  "enabled": true,
  "days": ["mon", "tue", "wed", "thu", "fri"],
  "start": "08:30",
  "end": "18:00"
}
```

Allowed day values are `mon` through `sun`. Duplicate/input-order day values
are normalized into week order. Times use 24-hour `HH:MM`. Days without times
mean all day on those days; times without days mean every day. A start later
than the end is an overnight window. An enabled schedule must have at least
one day or a complete start/end pair, and a lone time bound is always rejected.

Success returns the normalized persisted schedule while preserving the rule's
separate enabled flag:

```json
{
  "rule_id": 42,
  "user_id": 7,
  "enabled": true,
  "schedule": {
    "enabled": true,
    "days": ["mon", "fri"],
    "start": "22:00",
    "end": "06:00"
  }
}
```

Unknown rules return `404`. Invalid schedules return `422` without modifying
the existing row. Repeating an identical `PUT` leaves the same schedule.
Changing this local authorization schedule does not immediately operate a
door; it changes whether future reader credentials processed by this app may
unlock that rule's lock. It does not edit the schedule stored in UniFi Access.
Use a native lock's `follow_schedule` mode only to clear an app override and
resume the already-configured Access schedule. Group schedules are not exposed
by this endpoint.

### `POST /api/lockdown`

Sets lockdown to an explicit desired state. Scope: `full` only. The request
has no body and requires the boolean `enabled` query parameter:

```http
POST /api/lockdown?enabled=true
```

```json
{
  "lockdown": true
}
```

The returned boolean is the resulting state. Repeating the same request keeps
that state, so duplicate delivery cannot accidentally invert lockdown. Use
`enabled=false` deliberately to clear it; omitting `enabled` returns `422`.

Lockdown is persisted across restart. Its state change shares a physical-
command barrier with application unlocks, HA re-locks, and hub-sync commands:
once an enable request completes, no older application unlock can issue later.
Enabling lockdown applies persistent Access `keep_lock` to paired hubs the app
may have held open and confirms the paired HA lock is closed when that command
path is available. Authenticated rule/relay and HA state are re-read while
lockdown remains active, so a later direct unlock is detected and `keep_lock`
is safely reasserted. `reset` is not used because it could resume an active
native unlock schedule.

If enabling cannot persist the desired value or cannot confirm every required
hub lock, the endpoint returns `503` while retaining the safer enabled
in-memory state. `GET /api/health` lists unresolved HA entity IDs in
`lockdown_enforcement_pending`; retry `enabled=true` after restoring the
database/Access path or correcting a pairing conflict. If `enabled=false`
cannot be persisted, lockdown likewise remains enabled and the request returns
`503`. On startup, an error reading the persisted value is interpreted
fail-closed as enabled until an explicit disable succeeds.

Disabling lockdown does not synchronously clear persistent hub rules in the
API response. The next authenticated reconciliation confirms both sides locked,
replaces an app-owned `keep_lock` with `lock_now`, and clears ownership only
after rule/relay confirmation. A removed pairing returns to its native rule
after lockdown. Failed replacement remains durable and retries.

Lockdown cannot prevent a separate HA user/integration or direct UniFi operator
from issuing a command outside this application's authorization path. For
opted-in HA/Access pairs, event wakeups plus authenticated polling detect that
drift and drive the pair locked again; unpaired devices remain the upstream
operator's responsibility.

### `GET /api/debug`

Returns internal recovery signals. Scope: `full` only.

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
  "ws_last_event": {
    "access": "2026-07-12T15:29:34+00:00",
    "protect": "2026-07-12T15:29:30+00:00"
  },
  "pending_relocks_live": 1,
  "pending_relocks_db": 1
}
```

The `*_secs_since_last_event` values are `null` until that client has received
an event in the current process. `ws_last_event` contains wall-clock UTC values
for each source. Reconnect counters are diagnostic, not failure totals.

A durable re-lock count larger than the live-task count can be transient during
startup, HA recovery, or an overdue retry. If it persists while HA is healthy,
inspect process logs and the `access_control_relock_failed` HA event.

## Unauthenticated liveness

### `GET /health/live`

Returns:

```json
{
  "status": "ok"
}
```

No API key is required. This proves only that the web process is serving. It
does not query SQLite, HA, Access, or Protect and intentionally exposes no
topology.

## Examples

Check component health:

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${ACCESS_CONTROL_API_KEY}" \
  "http://<reachable-app-host>:8080/api/health" | jq .
```

Fetch the five newest log rows:

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${ACCESS_CONTROL_API_KEY}" \
  "http://<reachable-app-host>:8080/api/log?limit=5" \
  | jq -r '.entries[] | [.timestamp, .result, .user_name, .lock_name] | @tsv'
```

Hold lock 1 unlocked and require confirmation:

```bash
curl --fail --silent --show-error \
  -X PUT \
  -H "Authorization: Bearer ${ACCESS_CONTROL_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"mode":"hold_unlocked"}' \
  "http://<reachable-app-host>:8080/api/locks/1/mode" \
  | jq '{result, confirmed_state}'
```

Restore a native Access lock to its existing upstream schedule by sending
`{"mode":"follow_schedule"}` to the same endpoint. Use `force_locked` to
terminate an active scheduled unlock and confirm the locked state.

Replace individual rule 42's local overnight authorization schedule:

```bash
curl --fail --silent --show-error \
  -X PUT \
  -H "Authorization: Bearer ${ACCESS_CONTROL_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"enabled":true,"days":["mon","fri"],"start":"22:00","end":"06:00"}' \
  "http://<reachable-app-host>:8080/api/rules/42/schedule" \
  | jq .schedule
```

Set lockdown deliberately:

```bash
curl --fail --silent --show-error \
  -X POST \
  -H "Authorization: Bearer ${ACCESS_CONTROL_API_KEY}" \
  "http://<reachable-app-host>:8080/api/lockdown?enabled=true" \
  | jq .lockdown
```

Use the same request for a bounded retry; it cannot toggle lockdown off. To
clear lockdown, make the separate explicit request with `enabled=false`.

## Errors

Validation/authentication errors use JSON such as `{"detail":"..."}`. Lock-
mode command errors retain the structured command response documented above.

| Status | Meaning |
|---:|---|
| 200 | Request completed. Inspect component booleans for degraded health. |
| 401 | Bearer credential missing, malformed, or invalid. |
| 403 | Authenticated key lacks the endpoint's scope. |
| 404 | A requested operable lock or authorization rule does not exist. |
| 409 | A lock mode conflicts with lockdown or is unsupported by that lock type. |
| 422 | Query or JSON validation failed, including an invalid mode, lockdown value, day, or incomplete schedule. |
| 429 | Invalid-key lockout is active. |
| 500 | Unexpected application error; inspect process logs. |
| 503 | A required component is unavailable, a lock command was rejected/unconfirmed, or a lockdown persistence/physical-enforcement transition is incomplete. Inspect authoritative state, health, and logs. |

Dynamic API responses are non-cacheable. Clients should use bounded timeouts,
must not log Bearer keys, and should retry only operations whose desired-state
semantics they understand.

## Compatibility

The changelog calls out breaking API changes. Adding fields is compatible;
consumers should ignore unknown keys. Removing/renaming fields, changing scope
requirements, or changing an endpoint's mutation semantics requires a
documented release change. The `1.5.3` release notes record the lockdown
endpoint's change from a toggle to this explicit desired-state contract.
