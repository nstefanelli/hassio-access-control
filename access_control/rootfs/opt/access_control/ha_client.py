"""Home Assistant REST API client for lock control."""
from __future__ import annotations

import asyncio
import logging
import os

import aiohttp

# Every `except` block that handles an HA REST call below catches both
# `aiohttp.ClientError` AND `asyncio.TimeoutError`. The latter is NOT a
# subclass of ClientError in aiohttp 3.x; without catching it
# explicitly, a TimeoutError would bypass `_circuit.record_failure()`
# and the circuit-breaker's `_probe_in_flight` slot (HALF_OPEN guard)
# would stay reserved forever → permanent wedge. Audit 2026-05-24
# (codebase review), final-pass finding.

from .circuit_breaker import CircuitBreaker

_LOGGER = logging.getLogger(__name__)


class HAClientError(Exception):
    """HA client error."""


class HAClient:
    """Home Assistant REST API client."""

    def __init__(self, url: str, token: str) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._session: aiohttp.ClientSession | None = None
        self._connected = False
        self._last_error: str | None = None
        self._circuit: CircuitBreaker = CircuitBreaker("ha_client")

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def circuit_state(self) -> str:
        """Current state of the HA-call circuit breaker (closed/open/half_open)."""
        return self._circuit.state

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    def _headers(self) -> dict[str, str]:
        # Resolve the token env-first on EVERY call. Supervisor rotates
        # SUPERVISOR_TOKEN periodically; run.sh re-exports it as
        # ACCESS_CONTROL_HA_TOKEN, but the value captured at construction
        # goes stale and would 401 every lock/unlock until an add-on
        # restart (the circuit breaker treats 401 as "HA responded", so it
        # never opens and never self-recovers). Env presence means the
        # Supervisor-proxy path is active — mirror the app's env-first
        # credential precedence and always use the freshest value.
        # Non-Supervisor deployments have no env var and fall back to the
        # DB-configured long-lived token captured at construction.
        token = os.environ.get("ACCESS_CONTROL_HA_TOKEN") or self._token
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> bool:
        """Test HA connectivity."""
        await self._ensure_session()
        try:
            async with self._session.get(
                f"{self._url}/api/",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    self._connected = True
                    self._last_error = None
                    return True
                if resp.status == 401:
                    _LOGGER.error("HA 401 — token may be revoked or expired")
                self._connected = False
                self._last_error = f"HTTP {resp.status}"
                return False
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            self._connected = False
            self._last_error = str(err)
            return False

    async def check_health(self) -> dict:
        """Check HA connectivity and return a health summary dict."""
        await self.test_connection()
        return {
            "connected": self._connected,
            "last_error": self._last_error,
            "circuit_state": self._circuit.state,
        }

    async def unlock(self, entity_id: str) -> bool:
        """Unlock a lock entity."""
        return await self._call_service("lock", "unlock", entity_id)

    async def lock(self, entity_id: str) -> bool:
        """Lock a lock entity."""
        return await self._call_service("lock", "lock", entity_id)

    async def _call_service(
        self, domain: str, service: str, entity_id: str, extra_data: dict | None = None
    ) -> bool:
        """Call an HA service."""
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping %s.%s for %s", domain, service, entity_id)
            return False
        payload = extra_data if extra_data else {"entity_id": entity_id}
        try:
            await self._ensure_session()
            async with self._session.post(
                f"{self._url}/api/services/{domain}/{service}",
                headers=self._headers(),
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 401:
                    _LOGGER.error("HA 401 on %s.%s — token may be revoked or expired", domain, service)
                    self._connected = False
                    self._last_error = "HTTP 401 — token revoked?"
                elif resp.status != 200:
                    _LOGGER.error("HA service call failed: %s %s/%s -> %s",
                                  entity_id, domain, service, resp.status)
                self._circuit.record_success()
                return resp.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.error("HA request failed: %s", err)
            self._last_error = str(err)
            self._circuit.record_failure()
            return False
        finally:
            self._circuit.abort_probe()

    async def get_entity_state(self, entity_id: str) -> str | None:
        """Get the current state of any HA entity."""
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping get_entity_state for %s", entity_id)
            return None
        try:
            await self._ensure_session()
            async with self._session.get(
                f"{self._url}/api/states/{entity_id}",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._circuit.record_success()
                    return data.get("state")
                if resp.status == 401:
                    _LOGGER.error("HA 401 on get_entity_state %s — token may be revoked", entity_id)
                    self._connected = False
                    self._last_error = "HTTP 401 — token revoked?"
                else:
                    _LOGGER.warning("HA get_entity_state %s returned HTTP %s", entity_id, resp.status)
                self._circuit.record_success()  # HA responded — not a network failure
                return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("HA get_entity_state %s failed: %s", entity_id, err)
            self._last_error = str(err)
            self._circuit.record_failure()
            return None
        finally:
            self._circuit.abort_probe()

    async def get_timezone(self) -> str | None:
        """
        Return HA's configured IANA timezone (``/api/config`` →
        ``time_zone``), or None if unavailable. Used to align schedule
        evaluation with the site's local time.
        """
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping get_timezone")
            return None
        try:
            await self._ensure_session()
            async with self._session.get(
                f"{self._url}/api/config",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._circuit.record_success()
                    return data.get("time_zone") or None
                _LOGGER.warning("HA get_timezone returned HTTP %s", resp.status)
                self._circuit.record_success()  # HA responded — not a network failure
                return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("HA get_timezone failed: %s", err)
            self._last_error = str(err)
            self._circuit.record_failure()
            return None
        finally:
            self._circuit.abort_probe()

    async def get_lock_entities(self) -> list[dict]:
        """Fetch all lock.* entities from HA with friendly name and state."""
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping get_lock_entities")
            return []
        try:
            await self._ensure_session()
            async with self._session.get(
                f"{self._url}/api/states",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    _LOGGER.warning("HA get_lock_entities returned HTTP %s", resp.status)
                    self._circuit.record_success()  # HA responded
                    return []
                states = await resp.json()
                self._circuit.record_success()
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("HA get_lock_entities failed: %s", err)
            self._circuit.record_failure()
            return []
        finally:
            self._circuit.abort_probe()

        locks = []
        for entity in states:
            eid = entity.get("entity_id", "")
            if not eid.startswith("lock."):
                continue
            attrs = entity.get("attributes", {})
            locks.append({
                "entity_id": eid,
                "friendly_name": attrs.get("friendly_name", eid),
                "state": entity.get("state", "unknown"),
            })
        locks.sort(key=lambda x: x["friendly_name"])
        return locks

    async def get_camera_entities(self) -> list[dict]:
        """Fetch all camera.* entities from HA (doorbells + cameras)."""
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping get_camera_entities")
            return []
        try:
            await self._ensure_session()
            async with self._session.get(
                f"{self._url}/api/states",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    _LOGGER.warning("HA get_camera_entities returned HTTP %s", resp.status)
                    self._circuit.record_success()  # HA responded
                    return []
                states = await resp.json()
                self._circuit.record_success()
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("HA get_camera_entities failed: %s", err)
            self._circuit.record_failure()
            return []
        finally:
            self._circuit.abort_probe()

        cameras = []
        for entity in states:
            eid = entity.get("entity_id", "")
            if not eid.startswith("camera."):
                continue
            attrs = entity.get("attributes", {})
            cameras.append({
                "entity_id": eid,
                "friendly_name": attrs.get("friendly_name", eid),
                "state": entity.get("state", "unknown"),
            })
        cameras.sort(key=lambda x: x["friendly_name"])
        return cameras

    async def get_alarm_entities(self) -> list[dict]:
        """Fetch all alarm_control_panel.* entities from HA."""
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping get_alarm_entities")
            return []
        try:
            await self._ensure_session()
            async with self._session.get(
                f"{self._url}/api/states",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    _LOGGER.warning("HA get_alarm_entities returned HTTP %s", resp.status)
                    self._circuit.record_success()  # HA responded
                    return []
                states = await resp.json()
                self._circuit.record_success()
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("HA get_alarm_entities failed: %s", err)
            self._circuit.record_failure()
            return []
        finally:
            self._circuit.abort_probe()

        alarms = []
        for entity in states:
            eid = entity.get("entity_id", "")
            if not eid.startswith("alarm_control_panel."):
                continue
            attrs = entity.get("attributes", {})
            alarms.append({
                "entity_id": eid,
                "friendly_name": attrs.get("friendly_name", eid),
                "state": entity.get("state", "unknown"),
                "code_arm_required": attrs.get("code_arm_required", False),
                "supported_features": attrs.get("supported_features", 0),
            })
        alarms.sort(key=lambda x: x["friendly_name"])
        return alarms

    async def alarm_arm_away(self, entity_id: str, code: str | None = None) -> bool:
        data = {"entity_id": entity_id}
        if code:
            data["code"] = code
        return await self._call_service("alarm_control_panel", "alarm_arm_away", entity_id, extra_data=data)

    async def alarm_arm_home(self, entity_id: str, code: str | None = None) -> bool:
        data = {"entity_id": entity_id}
        if code:
            data["code"] = code
        return await self._call_service("alarm_control_panel", "alarm_arm_home", entity_id, extra_data=data)

    async def alarm_disarm(self, entity_id: str, code: str | None = None) -> bool:
        data = {"entity_id": entity_id}
        if code:
            data["code"] = code
        return await self._call_service("alarm_control_panel", "alarm_disarm", entity_id, extra_data=data)

    async def fire_event(self, event_type: str, data: dict) -> bool:
        """Fire an event on the HA event bus."""
        if self._circuit.is_open():
            _LOGGER.warning("HA circuit open — skipping fire_event %s", event_type)
            return False
        try:
            await self._ensure_session()
            async with self._session.post(
                f"{self._url}/api/events/{event_type}",
                headers=self._headers(),
                json=data,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                self._circuit.record_success()
                if resp.status != 200:
                    _LOGGER.warning("HA fire_event %s returned HTTP %s", event_type, resp.status)
                return resp.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("HA fire_event %s failed: %s", event_type, err)
            self._circuit.record_failure()
            return False
        finally:
            self._circuit.abort_probe()

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        self._connected = False
