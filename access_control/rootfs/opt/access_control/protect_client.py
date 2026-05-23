"""UniFi Protect client for doorbell ring events and camera listing."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import ssl
import struct
from typing import Callable, List, Optional

import aiohttp

_LOGGER = logging.getLogger(__name__)

API_BOOTSTRAP = "/proxy/protect/api/bootstrap"
API_CAMERAS = "/proxy/protect/api/cameras"
API_WS = "/proxy/protect/ws/updates"

WS_RECONNECT_DELAY = 5  # base delay, exponential backoff up to 300s


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
        if self._session is None or self._session.closed:
            jar = aiohttp.CookieJar(unsafe=True)
            connector = aiohttp.TCPConnector(ssl=self._ssl_ctx)
            self._session = aiohttp.ClientSession(connector=connector, cookie_jar=jar)
        return self._session

    def _base_url(self) -> str:
        return f"https://{self._host}"

    async def login(self) -> None:
        """Authenticate to the UNVR console (shared with Access)."""
        async with self._login_lock:
            url = self._base_url() + "/api/auth/login"
            session = self._get_session()
            async with session.post(
                url, json={"username": self._username, "password": self._password},
                ssl=self._ssl_ctx,
            ) as resp:
                if resp.status == 401:
                    self._auth_permanently_failed = True
                    text = await resp.text()
                    raise RuntimeError(f"Protect login failed: HTTP 401 (bad credentials): {text}")
                if resp.status not in (200, 201):
                    text = await resp.text()
                    raise RuntimeError(f"Protect login failed: HTTP {resp.status}: {text}")
                self._csrf_token = (
                    resp.headers.get("X-Updated-CSRF-Token")
                    or resp.headers.get("X-CSRF-Token")
                )
                if not self._csrf_token:
                    raise RuntimeError("Protect login succeeded but no CSRF token found in response headers")
                # Extract TOKEN cookie via regex — SimpleCookie silently
                # drops cookies with the 'Partitioned' attribute (newer
                # UniFi firmware), so parse the raw header directly.
                token_match = re.search(
                    r"(?:^|;\s*)TOKEN=([^;]+)",
                    resp.headers.get("Set-Cookie", ""),
                )
                if token_match:
                    self._auth_cookie = token_match.group(1)
                else:
                    raise RuntimeError("TOKEN cookie not found in login response")
                _LOGGER.info("Protect: logged in to %s", self._host)

    def _headers(self) -> dict:
        h = {"X-CSRF-Token": self._csrf_token}
        if self._auth_cookie:
            h["Cookie"] = f"TOKEN={self._auth_cookie}"
        return h

    async def get_cameras(self) -> list[dict]:
        """Fetch all cameras, return list of {id, name, type, is_doorbell, connected}."""
        if not self.connected:
            await self.login()
        session = self._get_session()
        async with session.get(
            self._base_url() + API_CAMERAS,
            headers=self._headers(), ssl=self._ssl_ctx,
        ) as resp:
            if resp.status != 200:
                return []
            cameras = await resp.json(content_type=None)

        result = []
        for cam in cameras:
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
            except (asyncio.CancelledError, Exception):
                pass
            self._ws_task = None
        self._ws_connected = False

    async def _ws_loop(self) -> None:
        delay = WS_RECONNECT_DELAY
        max_delay = 300

        while self._running:
            if self._auth_permanently_failed:
                _LOGGER.error("Auth permanently failed — WebSocket will not reconnect")
                break
            try:
                await self._ws_connect()
                self._reconnect_count += 1  # connection closed normally, will reconnect
                delay = WS_RECONNECT_DELAY
            except asyncio.CancelledError:
                break
            except Exception:
                _LOGGER.exception("Protect WS error — retry in %ds", delay)
            finally:
                self._ws_connected = False

            if self._running:
                await asyncio.sleep(delay)
                delay = min(delay * 2, max_delay) * (0.75 + random.random() * 0.5)

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
        # Reset the "last event seen" timestamp on every (re)connect — see
        # AccessClient._ws_connect for the rationale (watchdog re-fire loop).
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

    def _parse_ws_message(self, data: bytes) -> None:
        """Parse Protect binary WS frame: action header + data payload."""
        try:
            payload_size = struct.unpack(">I", data[4:8])[0]
            if payload_size <= 0 or 8 + payload_size > len(data):
                return
            action_payload = json.loads(data[8:8 + payload_size])

            model = action_payload.get("modelKey", "")
            if model != "event":
                return

            # Parse data frame
            data_offset = 8 + payload_size
            if data_offset + 8 > len(data):
                return
            data_payload_size = struct.unpack(">I", data[data_offset + 4:data_offset + 8])[0]
            data_start = data_offset + 8
            if data_payload_size <= 0 or data_start + data_payload_size > len(data):
                return

            event_data = json.loads(data[data_start:data_start + data_payload_size])
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

        except (json.JSONDecodeError, struct.error, ValueError, IndexError) as exc:
            _LOGGER.warning("Protect WS frame parse error (%s): %d bytes", type(exc).__name__, len(data))

    async def close(self) -> None:
        await self.stop_websocket()
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
