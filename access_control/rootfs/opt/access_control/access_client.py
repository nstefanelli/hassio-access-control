"""
UniFi Access API client for the Access Control App.

Handles session auth, topology bootstrap, user fetch, lock control,
and WebSocket notifications from the UNVR console.
"""

import asyncio
import json
import logging
import re
import secrets
import ssl
from typing import Callable, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

# API paths
API_LOGIN = "/api/auth/login"
API_BOOTSTRAP = "/proxy/access/api/v2/devices/topology4"
API_ACCESS_INFO = "/proxy/access/api/v2/access/info"
API_DEVICE_LOCK_RULE = "/proxy/access/api/v2/device/{device_id}/lock_rule"
API_LOCATION_UNLOCK = "/proxy/access/api/v2/location/{location_id}/unlock"
API_WEBSOCKET = "/proxy/access/api/v2/ws/notification"
API_USER = "/proxy/access/api/v2/users"

SUPPORTED_DEVICE_TYPES = ("UA-Hub-Door-Mini", "UAH", "UA-ULTRA", "UVC G6 Pro Entry")

# Bound every REST call. aiohttp's default is no total timeout, so a
# half-open socket to the UNVR (console reboot, firewall silently dropping)
# would hang login()/_request() indefinitely. login() holds _login_lock, so
# one hung call would stall every subsequent door event. The WebSocket keeps
# its own liveness via heartbeat= + the reconnect backoff loop, so this
# applies to REST only. (Audit 2026-07-05.)
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)

WS_RECONNECT_DELAY = 5  # seconds


class AccessClientError(Exception):
    """Raised for errors communicating with the UniFi Access API."""


class AccessClient:
    """
    Client for the UniFi Access API on the UNVR console.

    Manages:
    - Session authentication (cookie + CSRF token)
    - REST requests with auto-reauth on 401
    - Bootstrap topology and user fetching
    - Lock control (persistent unlock, lock, momentary unlock)
    - WebSocket notification listener with auto-reconnect
    """

    def __init__(self, host: str, username: str, password: str) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._csrf_token: Optional[str] = None
        self._auth_cookie: Optional[str] = None  # TOKEN cookie from login
        self._session: Optional[aiohttp.ClientSession] = None
        self._ws_task: Optional[asyncio.Task] = None
        self._ws_connected = False
        self._running = False
        self._callbacks: List[Callable] = []
        self._auth_permanently_failed = False
        self._login_lock: asyncio.Lock = asyncio.Lock()
        self._last_event_at: float = 0.0
        self._reconnect_count: int = 0

        # SSL context: TLS but no certificate verification — UNVR ships
        # with a self-signed certificate by default. We accept this in
        # exchange for the simpler operator UX of not requiring users to
        # pin a fingerprint or import a CA.
        #
        # SECURITY TRADE-OFF: a DNS-rebinding or on-path attacker who
        # can intercept LAN traffic to the UNVR host can present any
        # certificate and harvest the service-account credentials at
        # every WebSocket reconnect. Mitigations:
        #   1. Deploy the UNVR and the HA host on a trusted, isolated
        #      VLAN where on-path attacks are not part of the threat model.
        #   2. The WS-401 storm counter (this file's _ws_loop) caps
        #      credential replays to 5 before refusing to reconnect.
        # Audit 2026-05-24, clients-#5.
        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def connected(self) -> bool:
        """True if an authenticated session exists (CSRF token set)."""
        return self._csrf_token is not None

    @property
    def ws_connected(self) -> bool:
        """True if the WebSocket notification stream is active."""
        return self._ws_connected

    @property
    def last_event_at(self) -> float:
        return self._last_event_at

    @property
    def reconnect_count(self) -> int:
        return self._reconnect_count

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _get_session(self) -> aiohttp.ClientSession:
        """Return (or lazily create) the underlying aiohttp session."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_ctx)
            jar = aiohttp.CookieJar(unsafe=True)
            self._session = aiohttp.ClientSession(connector=connector, cookie_jar=jar)
        return self._session

    def _base_url(self) -> str:
        return f"https://{self._host}"

    async def login(self) -> None:
        """
        POST credentials to the UNVR console and capture the CSRF token.

        The CSRF token is returned in the X-Updated-CSRF-Token or
        X-CSRF-Token response header.

        Raises:
            AccessClientError: if login fails (non-2xx response).
        """
        async with self._login_lock:
            url = self._base_url() + API_LOGIN
            payload = {"username": self._username, "password": self._password}
            session = self._get_session()
            session.cookie_jar.clear()

            try:
                async with session.post(url, json=payload, ssl=self._ssl_ctx, timeout=_HTTP_TIMEOUT) as resp:
                    if resp.status == 401:
                        self._auth_permanently_failed = True
                        text = await resp.text()
                        # Log the raw response for diagnostics, but surface a
                        # sanitized message to the user (the UI displays this
                        # on the Settings page; future UniFi firmware could
                        # include internal hostnames or version strings in
                        # error bodies). Audit 2026-05-24, L1.
                        logger.warning("UniFi login 401 — response body: %s", text[:500])
                        raise AccessClientError(
                            "UniFi rejected the credentials (HTTP 401). "
                            "Double-check the service-account username + password."
                        )
                    if resp.status not in (200, 201):
                        text = await resp.text()
                        logger.warning("UniFi login HTTP %d — response body: %s", resp.status, text[:500])
                        raise AccessClientError(
                            f"UniFi returned HTTP {resp.status} during login. "
                            "Check the app log for the full upstream response."
                        )
                    # Extract CSRF token — prefer the "updated" variant
                    token = (
                        resp.headers.get("X-Updated-CSRF-Token")
                        or resp.headers.get("X-CSRF-Token")
                    )
                    if not token:
                        raise AccessClientError(
                            "Login succeeded but no CSRF token found in response headers"
                        )
                    self._csrf_token = token

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
                        raise AccessClientError("TOKEN cookie not found in login response")

                    logger.info("Logged in to UniFi Access at %s", self._host)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                # asyncio.TimeoutError (from _HTTP_TIMEOUT) is NOT an
                # aiohttp.ClientError subclass — catch it explicitly, and
                # clear any half-set auth state so the next call re-logs in
                # cleanly rather than sending a stale CSRF token / cookie.
                self._csrf_token = None
                self._auth_cookie = None
                raise AccessClientError(f"Network error during login: {exc}") from exc

    # ------------------------------------------------------------------
    # Core request helper
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        """
        Make an authenticated REST request.

        Automatically re-authenticates and retries once on a 401 response.

        Args:
            method: HTTP method (GET, PUT, POST, …).
            path:   API path (e.g. "/proxy/access/api/v2/user").
            **kwargs: passed directly to aiohttp session.request().

        Returns:
            The aiohttp.ClientResponse (caller must use as context manager
            or read .json()/.text() immediately — do not close it).

        Raises:
            AccessClientError: on non-2xx responses or network errors.
        """
        if not self.connected:
            await self.login()

        url = self._base_url() + path
        headers = kwargs.pop("headers", {})
        headers["X-CSRF-Token"] = self._csrf_token
        if self._auth_cookie:
            headers["Cookie"] = f"TOKEN={self._auth_cookie}"

        session = self._get_session()

        for attempt in range(2):
            try:
                resp = await session.request(
                    method,
                    url,
                    headers=headers,
                    ssl=self._ssl_ctx,
                    timeout=kwargs.pop("timeout", _HTTP_TIMEOUT),
                    **kwargs,
                )
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                raise AccessClientError(f"Network error for {method} {path}: {exc}") from exc

            if resp.status == 401 and attempt == 0:
                logger.warning("Got 401 from %s — re-authenticating", path)
                await resp.release()
                self._csrf_token = None
                await self.login()
                headers["X-CSRF-Token"] = self._csrf_token
                if self._auth_cookie:
                    headers["Cookie"] = f"TOKEN={self._auth_cookie}"
                continue

            if resp.status >= 400:
                text = await resp.text()
                raise AccessClientError(
                    f"HTTP {resp.status} from {method} {path}: {text}"
                )

            return resp

        # Should never reach here
        raise AccessClientError(f"Unexpected state after retries for {method} {path}")

    # ------------------------------------------------------------------
    # Data fetching
    # ------------------------------------------------------------------

    async def get_access_info(self) -> dict:
        """
        Fetch general access info from the UNVR console.

        Returns:
            Parsed JSON response as a dict.
        """
        resp = await self._request("GET", API_ACCESS_INFO)
        async with resp:
            return await resp.json(content_type=None)

    async def get_bootstrap(self) -> dict:
        """
        Fetch the full device topology (bootstrap).

        Returns:
            Parsed JSON topology response.
        """
        resp = await self._request("GET", API_BOOTSTRAP)
        async with resp:
            return await resp.json(content_type=None)

    async def fetch_users(self) -> List[dict]:
        """
        Fetch all UniFi Access users.

        Returns:
            List of dicts with keys: ulp_id, name, email, status.
        """
        resp = await self._request("GET", API_USER)
        async with resp:
            data = await resp.json(content_type=None)

        users = []
        # The API may return a top-level list or {"data": [...]}
        raw_list = data if isinstance(data, list) else data.get("data", [])
        for user in raw_list:
            ulp_id = user.get("unique_id") or user.get("id") or user.get("ulp_id", "")
            name = (
                user.get("full_name")
                or f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
                or user.get("name", "")
            )
            users.append(
                {
                    "ulp_id": ulp_id,
                    "name": name,
                    "email": user.get("email") or user.get("user_email", ""),
                    "status": user.get("status", ""),
                }
            )
        return users

    # ------------------------------------------------------------------
    # Topology parsing
    # ------------------------------------------------------------------

    def parse_doors_and_devices(self, bootstrap: dict) -> List[dict]:
        """
        Extract door/hub device entries from a topology bootstrap response.

        Only devices whose device_type is in SUPPORTED_DEVICE_TYPES are included.

        The topology nests: data[buildings] → floors[] → doors[] → device_groups[[devices]].

        Args:
            bootstrap: Raw topology response from get_bootstrap().

        Returns:
            List of dicts with keys:
                device_id   — unique device identifier
                location_id — location/door identifier
                name        — device display name
                door_name   — name of the associated door/location
        """
        results = []

        raw = bootstrap if isinstance(bootstrap, list) else bootstrap.get("data", [])

        for building in raw:
            for floor in building.get("floors", []):
                for door in floor.get("doors", []):
                    door_id = door.get("unique_id", "")
                    door_name = door.get("name", "")

                    for device_group in door.get("device_groups", []):
                        for device in device_group:
                            device_type = device.get("device_type", "")
                            if device_type not in SUPPORTED_DEVICE_TYPES:
                                continue

                            device_id = device.get("unique_id", "")
                            location_id = device.get("location_id", "") or door_id
                            device_name = device.get("alias") or device.get("name", f"{door_name} ({device_type})")

                            results.append(
                                {
                                    "device_id": device_id,
                                    "location_id": location_id,
                                    "name": device_name,
                                    "door_name": door_name,
                                    "device_type": device_type,
                                    "is_camera": device.get("is_camera", False),
                                }
                            )

        return results

    def parse_door_locations(self, bootstrap: dict) -> List[dict]:
        """
        Extract door locations from a topology bootstrap response.

        Returns:
            List of dicts with keys: id, name (for use in entry-device dropdowns).
        """
        locations = []
        raw = bootstrap if isinstance(bootstrap, list) else bootstrap.get("data", [])

        for building in raw:
            for floor in building.get("floors", []):
                for door in floor.get("doors", []):
                    door_id = door.get("unique_id", "")
                    # Use the alias of the first device as a friendlier name, or the door name
                    door_name = door.get("name", door_id)
                    for device_group in door.get("device_groups", []):
                        for device in device_group:
                            alias = device.get("alias") or device.get("name", "")
                            if alias:
                                door_name = alias
                                break
                        if door_name != door.get("name", door_id):
                            break
                    if door_id:
                        locations.append({"id": door_id, "name": door_name})

        return locations

    # ------------------------------------------------------------------
    # Lock control
    # ------------------------------------------------------------------

    async def unlock_persistent(self, device_id: str) -> None:
        """
        Set the lock rule to keep_unlock (persistent/hold-open).

        Args:
            device_id: ID of the hub device to unlock.
        """
        path = API_DEVICE_LOCK_RULE.format(device_id=device_id)
        resp = await self._request("PUT", path, json={"lock_rule": "keep_unlock"})
        async with resp:
            pass
        logger.info("Persistent unlock sent to device %s", device_id)

    async def lock(self, device_id: str) -> None:
        """
        Reset the lock rule (re-lock, clear hold-open).

        Args:
            device_id: ID of the hub device to lock.
        """
        path = API_DEVICE_LOCK_RULE.format(device_id=device_id)
        resp = await self._request("PUT", path, json={"lock_rule": "reset"})
        async with resp:
            pass
        logger.info("Lock sent to device %s", device_id)

    async def unlock_momentary(self, location_id: str) -> None:
        """
        Trigger a momentary (timed) unlock for a location/door.

        Args:
            location_id: ID of the location to unlock momentarily.
        """
        path = API_LOCATION_UNLOCK.format(location_id=location_id)
        resp = await self._request("POST", path, json={})
        async with resp:
            pass
        logger.info("Momentary unlock sent to location %s", location_id)

    # ------------------------------------------------------------------
    # Visitor management
    # ------------------------------------------------------------------

    async def create_visitor(
        self,
        first_name: str,
        last_name: str,
        start_time: int,
        end_time: int,
    ) -> dict:
        """Create a visitor in UniFi Access. Returns visitor data dict."""
        resp = await self._request(
            "POST",
            "/proxy/access/api/v2/visitor",
            json={
                "first_name": first_name,
                "last_name": last_name,
                "status": 1,
                "start_time": start_time,
                "end_time": end_time,
            },
        )
        async with resp:
            data = await resp.json(content_type=None)
            return data.get("data", {})

    async def update_visitor(self, visitor_id: str, **fields) -> dict:
        """Update a visitor (PIN, location, time window). Returns updated data."""
        resp = await self._request(
            "PUT",
            f"/proxy/access/api/v2/visitor/{visitor_id}",
            json=fields,
        )
        async with resp:
            data = await resp.json(content_type=None)
            return data.get("data", {})

    async def delete_visitor(self, visitor_id: str) -> None:
        """Delete a visitor from UniFi Access."""
        resp = await self._request("DELETE", f"/proxy/access/api/v2/visitor/{visitor_id}")
        async with resp:
            pass
        logger.info("Deleted visitor %s", visitor_id)

    async def list_visitors(self) -> list[dict]:
        """Fetch all visitors from UniFi Access."""
        resp = await self._request("GET", "/proxy/access/api/v2/visitors")
        async with resp:
            data = await resp.json(content_type=None)
            return data.get("data", [])

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    async def create_user(self, first_name: str, last_name: str) -> dict:
        """Create a user in UniFi Access. Returns user data dict."""
        resp = await self._request(
            "POST",
            "/proxy/access/api/v2/user",
            json={"first_name": first_name, "last_name": last_name, "status": "ACTIVE"},
        )
        async with resp:
            data = await resp.json(content_type=None)
            return data.get("data", {})

    # ------------------------------------------------------------------
    # User PIN management
    # ------------------------------------------------------------------

    async def set_user_pin(self, user_id: str, pin_code: str) -> dict:
        """Set a PIN code for a UniFi Access user. Returns updated user data."""
        resp = await self._request(
            "PUT",
            f"/proxy/access/api/v2/user/{user_id}",
            json={"pin_code": pin_code},
        )
        async with resp:
            data = await resp.json(content_type=None)
            return data.get("data", {})

    async def remove_user_pin(self, user_id: str) -> dict:
        """Remove a user's PIN code."""
        resp = await self._request(
            "PUT",
            f"/proxy/access/api/v2/user/{user_id}",
            json={"pin_code": ""},
        )
        async with resp:
            data = await resp.json(content_type=None)
            return data.get("data", {})

    # ------------------------------------------------------------------
    # WebSocket callbacks
    # ------------------------------------------------------------------

    def register_callback(self, callback: Callable) -> Callable:
        """
        Register a callback to receive WebSocket notification events.

        The callback is called with a single dict argument (the parsed
        JSON message from the WebSocket stream).

        Args:
            callback: Callable accepting one dict argument.

        Returns:
            An unregister function — call it to remove this callback.
        """
        self._callbacks.append(callback)

        def unregister() -> None:
            try:
                self._callbacks.remove(callback)
            except ValueError:
                pass

        return unregister

    def _dispatch(self, message: dict) -> None:
        """Invoke all registered callbacks with a parsed message."""
        self._last_event_at = asyncio.get_running_loop().time()
        for cb in list(self._callbacks):
            try:
                cb(message)
            except Exception:
                logger.exception("Callback %r raised an exception", cb)

    # ------------------------------------------------------------------
    # WebSocket management
    # ------------------------------------------------------------------

    async def start_websocket(self) -> None:
        """
        Start the background WebSocket listener task.

        Idempotent — calling while already running is a no-op.
        """
        if self._ws_task is not None and not self._ws_task.done():
            return
        self._running = True
        self._ws_task = asyncio.create_task(self._ws_loop(), name="access-ws-loop")
        logger.debug("WebSocket listener task started")

    async def stop_websocket(self) -> None:
        """Stop the background WebSocket listener task."""
        self._running = False
        if self._ws_task is not None:
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass
            self._ws_task = None
        self._ws_connected = False
        logger.debug("WebSocket listener task stopped")

    async def _ws_loop(self) -> None:
        """
        Outer reconnect loop for the WebSocket connection.

        Uses exponential backoff (5s → 10s → 20s → … → 300s max) on repeated failures.
        Resets to base delay after a successful connection.
        """
        delay: float = float(WS_RECONNECT_DELAY)
        max_delay: float = 300.0  # 5 minutes max
        ws_401_count = 0  # consecutive WS-upgrade 401s; see _ws_connect

        while self._running:
            if self._auth_permanently_failed:
                logger.error("Auth permanently failed — WebSocket will not reconnect")
                break
            try:
                await self._ws_connect()
                # If we get here, connection was established and then closed normally
                self._reconnect_count += 1  # connection closed normally, will reconnect
                delay = float(WS_RECONNECT_DELAY)  # reset on success
                ws_401_count = 0
            except asyncio.CancelledError:
                break
            except aiohttp.ClientResponseError as exc:
                if exc.status == 401:
                    # Bound the credential-replay storm on a stuck 401 loop.
                    # See ProtectClient._ws_loop for the same logic + rationale.
                    # Audit 2026-05-24, clients-#6.
                    ws_401_count += 1
                    if ws_401_count >= 5:
                        logger.error(
                            "Access WS returned 401 %d times in a row — refusing "
                            "to continue. Re-enter UNVR credentials in Settings.",
                            ws_401_count,
                        )
                        self._auth_permanently_failed = True
                        break
                logger.exception("WebSocket error — will retry in %.0fs", delay)
            except Exception:
                logger.exception("WebSocket error — will retry in %.0fs", delay)
            finally:
                self._ws_connected = False

            if self._running:
                logger.info("WebSocket disconnected, reconnecting in %ds…", delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, max_delay) * (0.75 + secrets.SystemRandom().random() * 0.5)

    async def _ws_connect(self) -> None:
        """
        Connect to the WebSocket notification endpoint and process messages.

        - Skips "Hello" heartbeat messages.
        - Parses JSON payloads and dispatches to callbacks.
        - On 401 during WS upgrade, re-authenticates before raising.
        """
        if not self.connected:
            await self.login()

        # Build wss:// URL with CSRF token as a query parameter (UniFi requirement)
        ws_url = (
            f"wss://{self._host}{API_WEBSOCKET}"
            f"?x-csrf-token={self._csrf_token}"
        )
        headers = {"X-CSRF-Token": self._csrf_token}
        if self._auth_cookie:
            headers["Cookie"] = f"TOKEN={self._auth_cookie}"

        session = self._get_session()

        logger.info("Connecting to WebSocket at %s", ws_url)
        try:
            ws = await session.ws_connect(
                ws_url,
                headers=headers,
                ssl=self._ssl_ctx,
                heartbeat=30,
            )
        except aiohttp.ClientResponseError as exc:
            if exc.status == 401:
                logger.warning("Access WS 401 — session expired, will re-auth")
                self._csrf_token = None
                self._auth_cookie = None
            raise

        self._ws_connected = True
        # Reset the "last event seen" timestamp on every (re)connect.
        # The watchdog measures silence from this value — without the reset,
        # a forced reconnect (or a midnight restart) would leave the old
        # stale timestamp and the watchdog would re-fire on every tick.
        self._last_event_at = asyncio.get_running_loop().time()
        logger.info("WebSocket connected")

        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    raw = msg.data
                    # Skip "Hello" heartbeats sent by the server
                    if raw.strip() == "Hello" or raw.strip() == '"Hello"':
                        continue
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        logger.debug("Non-JSON WebSocket message: %r", raw)
                        continue
                    self._dispatch(payload)

                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.warning("WebSocket error message: %r", msg.data)
                    break

                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    logger.info("WebSocket closed (type=%s)", msg.type)
                    break
        finally:
            self._ws_connected = False
            await ws.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """
        Shut down the WebSocket listener and close the HTTP session.

        Safe to call multiple times.
        """
        await self.stop_websocket()
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None
        self._csrf_token = None
        logger.info("AccessClient closed")
