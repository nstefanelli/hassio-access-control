"""UniFi Protect client for doorbell ring events and camera listing."""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import re
import ssl
import struct
import zlib
from typing import Callable, List, Optional

import aiohttp

_LOGGER = logging.getLogger(__name__)

API_BOOTSTRAP = "/proxy/protect/api/bootstrap"
API_CAMERAS = "/proxy/protect/api/cameras"
API_WS = "/proxy/protect/ws/updates"

WS_RECONNECT_DELAY = 5  # base delay, exponential backoff up to 300s

# Only reset the reconnect backoff after the socket stayed up this long. A
# server that accepts the upgrade and then immediately drops the connection
# used to reset the delay to the 5s base on every cycle, churning forever at
# a fixed cadence instead of backing off.
_WS_STABLE_CONNECTION_SECS = 30.0

# After this many un-parseable WS frames on one connection, escalate the
# parse-error log from warning to error — a healthy-looking ws_connected with
# every event dropped is otherwise invisible.
_WS_PARSE_FAILURE_ESCALATE = 5

# Bound REST calls — aiohttp defaults to no total timeout, so a half-open
# socket to the UNVR would hang login()/get_cameras() indefinitely (login
# holds _login_lock). The WebSocket has its own heartbeat + backoff loop.
# (Audit 2026-07-05.)
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)


class ProtectClient:
    """UniFi Protect API client — camera listing and doorbell ring WebSocket."""

    def __init__(self, host: str, username: str, password: str) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._csrf_token: Optional[str] = None
        self._auth_cookie: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._ws_task: Optional[asyncio.Task] = None
        self._ws_connected = False
        self._running = False
        self._callbacks: List[Callable] = []
        self._auth_permanently_failed = False
        self._login_lock: asyncio.Lock = asyncio.Lock()
        self._last_event_at: float = 0.0
        self._reconnect_count: int = 0
        self._closed = False
        self._ws_parse_failures: int = 0

        # See AccessClient.__init__ for the full TLS-trust trade-off
        # discussion. Short version: UNVR ships self-signed certs; we
        # don't verify them; LAN trust is assumed. Audit 2026-05-24, clients-#5.
        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    @property
    def connected(self) -> bool:
        return self._csrf_token is not None

    @property
    def ws_connected(self) -> bool:
        return self._ws_connected

    @property
    def last_event_at(self) -> float:
        return self._last_event_at

    @property
    def reconnect_count(self) -> int:
        return self._reconnect_count

    def _get_session(self) -> aiohttp.ClientSession:
        # A concurrent REST call resuming after close() must not silently
        # recreate the session (leaking it) and re-log-in with retired
        # credentials. Mirrors AccessClient._get_session / HAClient.
        if self._closed:
            raise RuntimeError("UniFi Protect client is closed")
        if self._session is None or self._session.closed:
            jar = aiohttp.CookieJar(unsafe=True)
            connector = aiohttp.TCPConnector(ssl=self._ssl_ctx)
            self._session = aiohttp.ClientSession(connector=connector, cookie_jar=jar)
        return self._session

    def _base_url(self) -> str:
        return f"https://{self._host}"

    async def login(self) -> None:
        """Authenticate to the UNVR console (shared with Access)."""
        if self._closed:
            raise RuntimeError("UniFi Protect client is closed")
        async with self._login_lock:
            # Concurrent-login short-circuit (mirrors AccessClient.login). Two
            # callers can both find ``connected`` false and queue on the lock;
            # the second must not re-POST credentials once the first has
            # established a full session. ``connected`` tracks the CSRF token;
            # require the paired auth cookie too so a half-populated state still
            # re-authenticates.
            if self.connected and self._auth_cookie is not None:
                return
            url = self._base_url() + "/api/auth/login"
            session = self._get_session()
            async with session.post(
                url, json={"username": self._username, "password": self._password},
                ssl=self._ssl_ctx, timeout=_HTTP_TIMEOUT,
            ) as resp:
                if resp.status == 401:
                    self._auth_permanently_failed = True
                    self._csrf_token = None
                    self._auth_cookie = None
                    await resp.text()
                    _LOGGER.warning("Protect login returned HTTP 401")
                    raise RuntimeError(
                        "UniFi Protect rejected the credentials (HTTP 401). "
                        "Double-check the service-account username + password."
                    )
                if resp.status not in (200, 201):
                    await resp.text()
                    _LOGGER.warning("Protect login returned HTTP %d", resp.status)
                    raise RuntimeError(
                        f"UniFi Protect returned HTTP {resp.status} during login. "
                        "Check the app log for the full upstream response."
                    )
                csrf_token = (
                    resp.headers.get("X-Updated-CSRF-Token")
                    or resp.headers.get("X-CSRF-Token")
                )
                if not csrf_token:
                    raise RuntimeError("Protect login succeeded but no CSRF token found in response headers")
                # Extract TOKEN cookie via regex — SimpleCookie silently
                # drops cookies with the 'Partitioned' attribute (newer
                # UniFi firmware), so parse the raw header directly.
                token_match = re.search(
                    r"(?:^|;\s*)TOKEN=([^;]+)",
                    resp.headers.get("Set-Cookie", ""),
                )
                if token_match:
                    auth_cookie = token_match.group(1)
                else:
                    raise RuntimeError("TOKEN cookie not found in login response")
                self._csrf_token = csrf_token
                self._auth_cookie = auth_cookie
                self._auth_permanently_failed = False
                _LOGGER.info("Protect: logged in to %s", self._host)

    def _headers(self) -> dict:
        h = {"X-CSRF-Token": self._csrf_token}
        if self._auth_cookie:
            h["Cookie"] = f"TOKEN={self._auth_cookie}"
        return h

    async def _rest_get(self, path: str):
        """Authenticated REST GET with one 401 re-auth retry.

        Mirrors AccessClient._request: ``connected`` only tracks the CSRF
        token, which a REST 401 never clears, so an expired UNVR session
        would otherwise return empty results forever without ever
        re-authenticating. Returns the decoded JSON, or None on a non-200
        response (logged with its status).
        """
        if not self.connected:
            await self.login()
        session = self._get_session()
        for attempt in range(2):
            async with session.get(
                self._base_url() + path,
                headers=self._headers(), ssl=self._ssl_ctx, timeout=_HTTP_TIMEOUT,
            ) as resp:
                if resp.status == 401 and attempt == 0:
                    _LOGGER.warning(
                        "Protect REST 401 from %s — re-authenticating", path
                    )
                    self._csrf_token = None
                    self._auth_cookie = None
                    await self.login()
                    continue
                if resp.status != 200:
                    _LOGGER.warning(
                        "Protect REST %s returned HTTP %d", path, resp.status
                    )
                    return None
                return await resp.json(content_type=None)
        return None  # unreachable — kept for symmetry with the retry loop

    async def get_cameras(self) -> list[dict]:
        """Fetch all cameras, return list of {id, name, type, is_doorbell, connected}."""
        cameras = await self._rest_get(API_CAMERAS)
        if cameras is None:
            return []

        # Defensive: the endpoint normally returns a JSON array, but an error
        # object or {"data": [...]} wrapper (firmware change) would make the
        # loop below iterate dict keys (str) and crash on cam.get(). Match the
        # list-vs-dict guarding access_client already does for user fetch.
        if not isinstance(cameras, list):
            _LOGGER.warning("Protect cameras response was %s, not a list — returning []", type(cameras).__name__)
            return []

        result = []
        for cam in cameras:
            if not isinstance(cam, dict):
                _LOGGER.warning(
                    "Protect cameras response contained a non-object row"
                )
                continue
            name = cam.get("name") or "Unknown"
            result.append({
                "id": cam.get("id", ""),
                "name": name,
                "type": cam.get("type", ""),
                "is_doorbell": cam.get("featureFlags", {}).get("isDoorbell", False),
                "connected": cam.get("isConnected", False),
            })
        result.sort(key=lambda x: x["name"] or "")
        return result

    async def get_doorbells(self) -> list[dict]:
        """Return only doorbell cameras."""
        cameras = await self.get_cameras()
        return [c for c in cameras if c["is_doorbell"]]

    # ------------------------------------------------------------------
    # WebSocket listener
    # ------------------------------------------------------------------

    def register_callback(self, callback: Callable) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    async def start_websocket(self) -> None:
        if self._ws_task is not None and not self._ws_task.done():
            return
        self._running = True
        self._ws_task = asyncio.create_task(self._ws_loop(), name="protect-ws")

    async def stop_websocket(self) -> None:
        self._running = False
        if self._ws_task:
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass
            except Exception:
                _LOGGER.exception("Protect WebSocket task raised during shutdown")
            self._ws_task = None
        self._ws_connected = False

    async def _ws_loop(self) -> None:
        delay: float = float(WS_RECONNECT_DELAY)
        max_delay: float = 300.0
        ws_401_count = 0  # consecutive WS-upgrade 401s; see _ws_connect

        loop = asyncio.get_running_loop()
        while self._running:
            if self._auth_permanently_failed:
                _LOGGER.error("Auth permanently failed — WebSocket will not reconnect")
                break
            try:
                attempt_started = loop.time()
                await self._ws_connect()
                self._reconnect_count += 1  # connection closed normally, will reconnect
                # Only reset the backoff when the connection actually stayed
                # up; an accept-then-immediate-close server must keep
                # doubling toward the max, not churn at the 5s base forever.
                if loop.time() - attempt_started >= _WS_STABLE_CONNECTION_SECS:
                    delay = float(WS_RECONNECT_DELAY)
                ws_401_count = 0  # successful upgrade — auth is fine
            except asyncio.CancelledError:
                break
            except aiohttp.ClientResponseError as exc:
                if exc.status == 401:
                    # Persistent WS 401s indicate something stuck server-side
                    # (token reuse against a moved endpoint, attacker echoing
                    # 401s, etc.). Bound the retry storm — after N consecutive
                    # WS 401s, stop reconnecting and stop reposting the
                    # service-account password. Audit 2026-05-24, clients-#6.
                    ws_401_count += 1
                    if ws_401_count >= 5:
                        _LOGGER.error(
                            "Protect WS returned 401 %d times in a row — refusing "
                            "to continue. Re-enter credentials in Settings to clear.",
                            ws_401_count,
                        )
                        self._auth_permanently_failed = True
                        break
                else:
                    # A non-401 upstream error breaks any 401 streak — only
                    # genuinely consecutive upgrade-401s may trip the latch.
                    ws_401_count = 0
                _LOGGER.exception("Protect WS error — retry in %.0fs", delay)
            except Exception:
                ws_401_count = 0  # non-401 failure — the 401s were not consecutive
                _LOGGER.exception("Protect WS error — retry in %.0fs", delay)
            finally:
                self._ws_connected = False

            if self._running:
                await asyncio.sleep(delay)
                delay = min(delay * 2, max_delay) * (0.75 + secrets.SystemRandom().random() * 0.5)

    async def _ws_connect(self) -> None:
        if not self.connected:
            await self.login()

        session = self._get_session()
        ws_url = f"wss://{self._host}{API_WS}?lastUpdateId="

        _LOGGER.info("Connecting to Protect WebSocket")
        try:
            ws = await session.ws_connect(
                ws_url, headers=self._headers(), ssl=self._ssl_ctx, heartbeat=30,
            )
        except aiohttp.ClientResponseError as exc:
            if exc.status == 401:
                _LOGGER.warning("Protect WS 401 — session expired, will re-auth")
                self._csrf_token = None
                self._auth_cookie = None
            raise

        self._ws_connected = True
        self._ws_parse_failures = 0
        # Seed activity age for API diagnostics. aiohttp heartbeat and the
        # reconnect loop own protocol liveness; quiet doors are not failures.
        self._last_event_at = asyncio.get_running_loop().time()
        _LOGGER.info("Protect WebSocket connected")

        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY and len(msg.data) > 8:
                    self._parse_ws_message(msg.data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    _LOGGER.warning("Protect WS error message: %r", msg.data)
                    break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    _LOGGER.info("Protect WS closed (type=%s)", msg.type)
                    break
        finally:
            await ws.close()

    @staticmethod
    def _decode_ws_frame(data: bytes, offset: int):
        """Decode one Protect WS frame starting at ``offset``.

        Each frame carries an 8-byte header: packet type (0), payload format
        (1), deflated flag (2), reserved (3), then the payload size as a
        big-endian uint32 (4:8). Current Protect firmware zlib-compresses
        action/data payloads and sets the deflated flag; feeding those raw
        bytes to json.loads silently dropped every event.

        Returns (payload, next_offset) or None for a truncated frame.
        """
        if offset + 8 > len(data):
            return None
        deflated = data[offset + 2]
        payload_size = struct.unpack(">I", data[offset + 4:offset + 8])[0]
        start = offset + 8
        if payload_size <= 0 or start + payload_size > len(data):
            return None
        raw = data[start:start + payload_size]
        if deflated:
            raw = zlib.decompress(raw)
        return json.loads(raw), start + payload_size

    def _parse_ws_message(self, data: bytes) -> None:
        """Parse Protect binary WS frame: action header + data payload."""
        try:
            frame = self._decode_ws_frame(data, 0)
            if frame is None:
                return
            action_payload, data_offset = frame

            model = action_payload.get("modelKey", "")
            if model != "event":
                self._ws_parse_failures = 0
                return

            # Parse data frame
            frame = self._decode_ws_frame(data, data_offset)
            if frame is None:
                return
            event_data, _ = frame
            self._ws_parse_failures = 0
            event_type = event_data.get("type", "")
            camera_id = event_data.get("camera", "")
            metadata = event_data.get("metadata", {})

            callback_msg = None

            if event_type == "doorAccess":
                ulp_id = metadata.get("uniqueId", "")
                action = metadata.get("action", "")
                if action == "open_door" and ulp_id:
                    display_name = f"{metadata.get('firstName', '')} {metadata.get('lastName', '')}".strip()
                    open_success = metadata.get("openSuccess", False)
                    _LOGGER.info("Door access: %s at %s (camera %s, openSuccess=%s)", display_name, metadata.get("doorName", ""), camera_id, open_success)
                    callback_msg = {
                        "event": "door_access",
                        "camera_id": camera_id,
                        "ulp_id": ulp_id,
                        "display_name": display_name,
                        "door_name": metadata.get("doorName", ""),
                        "open_success": open_success,
                        "data": event_data,
                    }

            elif event_type == "ring":
                _LOGGER.info("Doorbell ring from camera %s", camera_id)
                callback_msg = {"event": "ring", "camera_id": camera_id, "data": event_data}

            elif event_type == "nfcCardScanned":
                nfc_meta = metadata.get("nfc", {})
                nfc_id = nfc_meta.get("nfcId", "")
                user_id = nfc_meta.get("userId", "")
                _LOGGER.info("NFC scan on camera %s: nfc_id=%s user_id=%s", camera_id, nfc_id, user_id)
                callback_msg = {
                    "event": "nfc",
                    "camera_id": camera_id,
                    "nfc_id": nfc_id,
                    "ulp_id": user_id,
                    "data": event_data,
                }

            elif event_type == "fingerprintIdentified":
                fp_meta = metadata.get("fingerprint", {})
                ulp_id = fp_meta.get("ulpId", "")
                _LOGGER.info("Fingerprint identified on camera %s: ulp_id=%s", camera_id, ulp_id)
                callback_msg = {
                    "event": "fingerprint",
                    "camera_id": camera_id,
                    "ulp_id": ulp_id,
                    "identified": bool(ulp_id),
                    "data": event_data,
                }

            if callback_msg:
                self._last_event_at = asyncio.get_running_loop().time()
                for cb in list(self._callbacks):
                    try:
                        cb(callback_msg)
                    except Exception:
                        _LOGGER.exception("Protect callback error")

        except (
            json.JSONDecodeError,
            struct.error,
            zlib.error,
            ValueError,
            IndexError,
            AttributeError,
            TypeError,
        ) as exc:
            # Repeated failures mean every event is being dropped while
            # ws_connected still reports healthy — escalate the log level.
            self._ws_parse_failures += 1
            log = (
                _LOGGER.error
                if self._ws_parse_failures >= _WS_PARSE_FAILURE_ESCALATE
                else _LOGGER.warning
            )
            log(
                "Protect WS frame parse error (%s): %d bytes "
                "(%d consecutive failures)",
                type(exc).__name__,
                len(data),
                self._ws_parse_failures,
            )

    async def close(self) -> None:
        self._closed = True
        await self.stop_websocket()
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
