"""
UniFi Access API client for the Access Control App.

Handles session auth, topology bootstrap, user fetch, lock control,
and WebSocket notifications from the UNVR console.
"""

import asyncio
import hashlib
import json
import logging
import re
import secrets
import ssl
from typing import Callable, List, Optional
from urllib.parse import urlsplit

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

# UniFi Access Open API (API token, HTTPS port 12445). Unlike the private
# console-session endpoints above, these routes are keyed by the *door* ID
# (our ``location_id``), not by the hub ``device_id``.
API_OPEN_DOORS = "/api/v1/developer/doors"
API_OPEN_DOOR = "/api/v1/developer/doors/{location_id}"
API_OPEN_DOOR_LOCK_RULE = "/api/v1/developer/doors/{location_id}/lock_rule"

SUPPORTED_DEVICE_TYPES = ("UA-Hub-Door-Mini", "UAH", "UA-ULTRA", "UVC G6 Pro Entry")

# Bound every REST call. aiohttp's default is no total timeout, so a
# half-open socket to the UNVR (console reboot, firewall silently dropping)
# would hang login()/_request() indefinitely. login() holds _login_lock, so
# one hung call would stall every subsequent door event. The WebSocket keeps
# its own liveness via heartbeat= + the reconnect backoff loop, so this
# applies to REST only. (Audit 2026-07-05.)
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)

# A successful PUT means only that Access accepted the request. Bound the
# subsequent readback so a slow/offline controller cannot strand the global
# physical-command barrier indefinitely.
_LOCK_CONFIRM_ATTEMPTS = 3
_LOCK_CONFIRM_DELAY = 0.25

_LOCK_RULE_TYPES = frozenset(
    {
        "schedule",
        "keep_lock",
        "keep_unlock",
        "custom",
        "lock_early",
        # The Open API documents these as input-only, but the private API on
        # some firmware echoes them from GET. Recognizing them keeps legacy
        # readback strict without rejecting a known command value.
        "lock_now",
        "reset",
    }
)
_UNLOCKED_RULE_TYPES = frozenset({"schedule", "keep_unlock", "custom"})
_LOCKED_RULE_TYPES = frozenset({"keep_lock", "lock_early", "lock_now"})

WS_RECONNECT_DELAY = 5  # seconds


class AccessClientError(Exception):
    """Raised for errors communicating with the UniFi Access API.

    ``status`` carries the HTTP status code when the error originates from a
    non-2xx REST response, so callers can react structurally (e.g. detect a
    removed endpoint) instead of parsing the human-readable message.
    """

    def __init__(self, *args: object, status: int | None = None) -> None:
        super().__init__(*args)
        self.status = status


class AccessLegacyEndpointGoneError(AccessClientError):
    """Raised when a legacy per-device lock_rule endpoint returns HTTP 404.

    A UNVR Access app update removed the private
    ``/proxy/access/api/v2/device/{id}/lock_rule`` route. Deployments without
    an Open API token are pinned to that path, so every legacy read/write now
    404s. This typed error lets the sync layer recognise the condition as a
    permanent, operator-actionable misconfiguration rather than a transient
    fault.
    """


# Actionable guidance surfaced whenever a legacy lock_rule endpoint 404s.
_LEGACY_ENDPOINT_GONE_MESSAGE = (
    "legacy Access API endpoint not found — the console's Access app likely "
    "removed it; configure a UniFi Access Open API token in Settings to switch "
    "to the supported API"
)


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

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        expected_identity: str | None = None,
        api_token: str | None = None,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._csrf_token: Optional[str] = None
        self._auth_cookie: Optional[str] = None  # TOKEN cookie from login
        self._session: Optional[aiohttp.ClientSession] = None
        # Keep Bearer-token traffic in a separate, cookieless session. Cookies
        # are scoped to a host rather than a port, so reusing the console
        # session would unnecessarily send its TOKEN cookie to port 12445.
        self._api_session: Optional[aiohttp.ClientSession] = None
        self._ws_task: Optional[asyncio.Task] = None
        self._ws_connected = False
        self._running = False
        self._callbacks: List[Callable] = []
        self._auth_permanently_failed = False
        self._login_lock: asyncio.Lock = asyncio.Lock()
        self._last_event_at: float = 0.0
        self._reconnect_count: int = 0
        self._server_fingerprint: Optional[str] = None
        self._expected_identity = expected_identity
        self._console_identity: Optional[str] = None
        normalized_api_token = api_token.strip() if api_token is not None else ""
        self._api_token: Optional[str] = normalized_api_token or None

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

    @property
    def server_fingerprint(self) -> Optional[str]:
        """SHA-256 of the console TLS certificate observed at login."""
        return self._server_fingerprint

    @property
    def console_identity(self) -> Optional[str]:
        return self._console_identity

    @property
    def open_api_configured(self) -> bool:
        """Whether commands use the token-authenticated official Open API."""
        return self._api_token is not None

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

    def _get_api_session(self) -> aiohttp.ClientSession:
        """Return the isolated, cookieless Open API HTTP session."""
        if self._api_session is None or self._api_session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_ctx)
            self._api_session = aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.DummyCookieJar(),
            )
        return self._api_session

    def _base_url(self) -> str:
        return f"https://{self._host}"

    def _open_api_base_url(self) -> str:
        """Build the local Open API origin on its required HTTPS port.

        Settings historically stores a bare host, sometimes including the
        console UI port. Always replace that port with 12445. A token is never
        sent to an arbitrary path or operator-supplied second host.
        """
        raw_host = self._host.strip()
        parsed = urlsplit(
            raw_host if "://" in raw_host else f"//{raw_host}"
        )
        hostname = parsed.hostname
        if not hostname:
            raise AccessClientError("Invalid UniFi Access host")
        if ":" in hostname:  # IPv6 literals need brackets in a URL.
            hostname = f"[{hostname}]"
        return f"https://{hostname}:12445"

    async def login(self) -> None:
        """
        POST credentials to the UNVR console and capture the CSRF token.

        The CSRF token is returned in the X-Updated-CSRF-Token or
        X-CSRF-Token response header.

        Raises:
            AccessClientError: if login fails (non-2xx response).
        """
        async with self._login_lock:
            if self.connected and self._console_identity is not None:
                return
            url = self._base_url() + API_LOGIN
            payload = {"username": self._username, "password": self._password}
            session = self._get_session()
            session.cookie_jar.clear()

            try:
                async with session.post(url, json=payload, ssl=self._ssl_ctx, timeout=_HTTP_TIMEOUT) as resp:
                    connection = getattr(resp, "connection", None)
                    transport = getattr(connection, "transport", None)
                    ssl_object = (
                        transport.get_extra_info("ssl_object")
                        if transport is not None
                        else None
                    )
                    certificate = (
                        ssl_object.getpeercert(binary_form=True)
                        if ssl_object is not None
                        else None
                    )
                    if isinstance(certificate, (bytes, bytearray)) and certificate:
                        self._server_fingerprint = hashlib.sha256(
                            certificate
                        ).hexdigest()
                    if resp.status == 401:
                        self._auth_permanently_failed = True
                        self._csrf_token = None
                        self._auth_cookie = None
                        await resp.text()
                        logger.warning("UniFi login returned HTTP 401")
                        raise AccessClientError(
                            "UniFi rejected the credentials (HTTP 401). "
                            "Double-check the service-account username + password."
                        )
                    if resp.status not in (200, 201):
                        await resp.text()
                        logger.warning("UniFi login returned HTTP %d", resp.status)
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
                        raise AccessClientError("TOKEN cookie not found in login response")

                # Verify the authenticated namespace on every login, including
                # REST 401 reauth and WebSocket reconnect. Publishing cookies
                # from a different site would let reused upstream IDs inherit
                # local grants before the next periodic topology sync.
                try:
                    identity = await self._fetch_console_identity_authenticated(
                        session, token, auth_cookie
                    )
                except BaseException:
                    self._csrf_token = None
                    self._auth_cookie = None
                    raise
                if (
                    self._expected_identity is not None
                    and identity != self._expected_identity
                ):
                    self._csrf_token = None
                    self._auth_cookie = None
                    self._auth_permanently_failed = True
                    raise AccessClientError(
                        "UniFi Access site identity does not match this installation"
                    )
                self._expected_identity = identity
                self._console_identity = identity
                # Publish authenticated state only after credentials AND site
                # identity are verified. Concurrent requests continue to see
                # disconnected and wait on this login lock instead of reaching
                # an untrusted namespace during the identity GET.
                self._csrf_token = token
                self._auth_cookie = auth_cookie
                self._auth_permanently_failed = False
                logger.info("Logged in to UniFi Access at %s", self._host)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                # Clear any half-set auth state so the next call re-logs in
                # cleanly rather than sending a stale token or cookie.
                self._csrf_token = None
                self._auth_cookie = None
                raise AccessClientError(
                    f"Network error during login: {exc}"
                ) from exc

    @staticmethod
    def _derive_console_identities(
        info: object, bootstrap: object = None
    ) -> list[str]:
        """Return every stable hashed namespace candidate in preference order.

        UniFi firmware has added and renamed identity fields over time. A
        previously enrolled installation must therefore match its persisted
        identity against *all* identifiers currently exposed, rather than
        changing identity just because a newer preferred field appeared.
        """
        candidates: list[str] = []

        def append(prefix: str, value: object) -> None:
            if value in (None, ""):
                return
            identity = hashlib.sha256(f"{prefix}:{value}".encode()).hexdigest()
            if identity not in candidates:
                candidates.append(identity)

        data = info.get("data", info) if isinstance(info, dict) else {}
        data_items = data if isinstance(data, list) else [data]
        for key in (
            "console_id", "consoleId", "site_id", "siteId",
            "host_id", "hostId", "unique_id",
        ):
            for item in data_items:
                if isinstance(item, dict):
                    append("access-site", item.get(key))
        buildings = (
            bootstrap
            if isinstance(bootstrap, list)
            else bootstrap.get("data", [])
            if isinstance(bootstrap, dict)
            else []
        )
        building_ids = sorted(
            str(building.get("unique_id") or building.get("id"))
            for building in buildings
            if isinstance(building, dict)
            and (building.get("unique_id") or building.get("id"))
        )
        for building_id in building_ids:
            append("access-building", building_id)
        return candidates

    @staticmethod
    def _derive_console_identity(info: object, bootstrap: object = None) -> str | None:
        """Return the preferred identity for first-time enrollment."""
        candidates = AccessClient._derive_console_identities(info, bootstrap)
        return candidates[0] if candidates else None

    async def _fetch_console_identity_authenticated(
        self,
        session: aiohttp.ClientSession,
        csrf_token: str,
        auth_cookie: str,
    ) -> str:
        headers = {
            "X-CSRF-Token": csrf_token,
            "Cookie": f"TOKEN={auth_cookie}",
        }

        async def fetch_optional(path: str) -> tuple[object | None, bool]:
            """Fetch one identity source; bool says the source was usable."""
            try:
                async with session.get(
                    self._base_url() + path,
                    headers=headers,
                    ssl=self._ssl_ctx,
                    timeout=_HTTP_TIMEOUT,
                ) as response:
                    if response.status in (401, 403):
                        raise AccessClientError(
                            "Authentication failed while verifying Access identity"
                        )
                    if response.status >= 400:
                        logger.warning(
                            "Access identity source %s returned HTTP %d",
                            path,
                            response.status,
                        )
                        return None, False
                    try:
                        return await response.json(content_type=None), True
                    except (TypeError, ValueError):
                        logger.warning(
                            "Access identity source %s returned invalid JSON", path
                        )
                        return None, False
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.warning("Access identity source %s failed: %s", path, exc)
                return None, False

        info, _info_usable = await fetch_optional(API_ACCESS_INFO)
        candidates = self._derive_console_identities(info or {})
        if self._expected_identity in candidates:
            return self._expected_identity

        # An authenticated console/site UUID is the preferred first-time
        # enrollment identity. With an existing pin that did not match, still
        # fetch topology so a building-derived legacy pin survives firmware
        # adding a new higher-priority field.
        if self._expected_identity is None and candidates:
            return candidates[0]

        bootstrap, bootstrap_usable = await fetch_optional(API_BOOTSTRAP)
        candidates = self._derive_console_identities(info or {}, bootstrap or {})
        if self._expected_identity in candidates:
            return self._expected_identity
        if self._expected_identity is not None and not bootstrap_usable:
            raise AccessClientError(
                "Could not verify the persisted UniFi Access site identity"
            )
        if not candidates:
            raise AccessClientError(
                "UniFi Access did not expose a stable site identity"
            )
        # Returning a definitively observed candidate lets login distinguish a
        # real site mismatch and mark it permanent.
        return candidates[0]

    async def _reverify_authenticated_identity(self) -> None:
        """Revalidate a cached session before each WebSocket upgrade."""
        async with self._login_lock:
            if not self.connected or not self._auth_cookie:
                raise AccessClientError("Access session is not authenticated")
            try:
                identity = await self._fetch_console_identity_authenticated(
                    self._get_session(), self._csrf_token, self._auth_cookie
                )
            except BaseException:
                self._csrf_token = None
                self._auth_cookie = None
                raise
            if (
                self._expected_identity is not None
                and identity != self._expected_identity
            ):
                self._csrf_token = None
                self._auth_cookie = None
                self._auth_permanently_failed = True
                raise AccessClientError(
                    "UniFi Access site identity does not match this installation"
                )
            self._expected_identity = identity
            self._console_identity = identity

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

        timeout = kwargs.pop("timeout", _HTTP_TIMEOUT)
        for attempt in range(2):
            try:
                resp = await session.request(
                    method,
                    url,
                    headers=headers,
                    ssl=self._ssl_ctx,
                    timeout=timeout,
                    **kwargs,
                )
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                raise AccessClientError(f"Network error for {method} {path}: {exc}") from exc

            if resp.status == 401 and attempt == 0:
                logger.warning("Got 401 from %s — re-authenticating", path)
                # ClientResponse.release() is synchronous in aiohttp 3.x.
                # Awaiting it raised TypeError on every REST 401, preventing
                # the documented re-authentication retry from ever running.
                resp.release()
                self._csrf_token = None
                await self.login()
                headers["X-CSRF-Token"] = self._csrf_token
                if self._auth_cookie:
                    headers["Cookie"] = f"TOKEN={self._auth_cookie}"
                continue

            if resp.status >= 400:
                await resp.text()
                raise AccessClientError(
                    f"HTTP {resp.status} from {method} {path}",
                    status=resp.status,
                )

            return resp

        # Should never reach here
        raise AccessClientError(f"Unexpected state after retries for {method} {path}")

    @staticmethod
    async def _json_object_response(
        response: aiohttp.ClientResponse,
        *,
        operation: str,
    ) -> dict:
        """Decode a response without ever reflecting its body to the caller."""
        try:
            payload = await response.json(content_type=None)
        except (aiohttp.ClientError, TypeError, ValueError) as exc:
            raise AccessClientError(
                f"UniFi Access returned invalid JSON for {operation}"
            ) from exc
        if not isinstance(payload, dict):
            raise AccessClientError(
                f"UniFi Access returned an invalid envelope for {operation}"
            )
        return payload

    async def _open_api_request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
    ) -> object:
        """Call the official token API and return its validated ``data``.

        A configured token is an explicit control-plane choice. Authentication,
        transport, and schema errors propagate to the caller and must never
        fall back to the private username/password endpoint.
        """
        if self._api_token is None:
            raise AccessClientError("UniFi Access Open API token is not configured")

        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
        }
        kwargs: dict = {}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            kwargs["json"] = json_body

        url = self._open_api_base_url() + path
        try:
            response = await self._get_api_session().request(
                method,
                url,
                headers=headers,
                ssl=self._ssl_ctx,
                timeout=_HTTP_TIMEOUT,
                **kwargs,
            )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise AccessClientError(
                f"Network error for UniFi Access Open API {method} {path}"
            ) from exc

        async with response:
            if response.status < 200 or response.status >= 300:
                await response.text()
                raise AccessClientError(
                    f"HTTP {response.status} from UniFi Access Open API "
                    f"{method} {path}"
                )
            payload = await self._json_object_response(
                response,
                operation=f"Open API {method} {path}",
            )

        if payload.get("code") != "SUCCESS" or "data" not in payload:
            raise AccessClientError(
                f"UniFi Access Open API rejected or malformed {method} {path}"
            )
        return payload["data"]

    async def _legacy_json_request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
    ) -> dict:
        """Call a private session endpoint and require an object response."""
        kwargs = {"json": json_body} if json_body is not None else {}
        response = await self._request(method, path, **kwargs)
        async with response:
            return await self._json_object_response(
                response,
                operation=f"legacy API {method} {path}",
            )

    async def validate_open_api(self) -> bool:
        """Validate a configured Open API token without changing door state.

        Returns ``False`` when no token is configured. With a token, failures
        raise :class:`AccessClientError`; success returns ``True`` after a
        strict doors-list read and, when a door exists, a rule read. The GETs
        validate token authentication and ``view:space`` access. UniFi does
        not expose a non-mutating probe for ``edit:space``; the first command
        still validates that permission before any legacy path can run.
        """
        if self._api_token is None:
            return False
        data = await self._open_api_request("GET", API_OPEN_DOORS)
        if not isinstance(data, list):
            raise AccessClientError(
                "UniFi Access Open API returned an invalid doors list"
            )

        location_ids: list[str] = []
        for row in data:
            if not isinstance(row, dict):
                raise AccessClientError(
                    "UniFi Access Open API returned a non-object door row"
                )
            location_id = row.get("id")
            if not isinstance(location_id, str) or not location_id:
                raise AccessClientError(
                    "UniFi Access Open API returned a door without an ID"
                )
            location_ids.append(location_id)

        if location_ids:
            await self.get_lock_rule(
                location_ids[0],
                location_id=location_ids[0],
            )
        return True

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

    async def get_console_identity(self) -> str:
        """Return a stable hashed Access site/console namespace identity.

        Access firmware has used several field spellings across releases, so
        login verifies every available authenticated identity source before
        publishing the session. Raw upstream identifiers are never stored.
        """
        if self._console_identity is not None:
            return self._console_identity
        await self.login()
        if self._console_identity is None:  # defensive: login always verifies
            raise AccessClientError(
                "UniFi Access did not expose a stable site identity"
            )
        return self._console_identity

    async def verify_console_identity(self) -> str:
        """Perform an uncached authenticated site-identity verification."""
        if not self.connected:
            await self.login()
        else:
            await self._reverify_authenticated_identity()
        if self._console_identity is None:
            raise AccessClientError(
                "UniFi Access did not expose a stable site identity"
            )
        return self._console_identity

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
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict) and isinstance(data.get("data", []), list):
            raw_list = data.get("data", [])
        else:
            raise AccessClientError("UniFi Access returned an invalid user list")
        for user in raw_list:
            if not isinstance(user, dict):
                raise AccessClientError(
                    "UniFi Access returned a non-object user row"
                )
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

    @staticmethod
    def _normalized_lock_rule(
        value: object,
        *,
        ended_time: object = None,
    ) -> dict[str, object]:
        if not isinstance(value, str):
            raise AccessClientError("UniFi Access returned a lock rule without a type")
        rule_type = value.strip().lower()
        if rule_type not in _LOCK_RULE_TYPES:
            raise AccessClientError("UniFi Access returned an unknown lock rule type")
        if isinstance(ended_time, bool) or (
            ended_time is not None and not isinstance(ended_time, int)
        ):
            raise AccessClientError("UniFi Access returned an invalid rule end time")
        return {"type": rule_type, "ended_time": ended_time}

    @classmethod
    def _parse_official_lock_rule(cls, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            raise AccessClientError(
                "UniFi Access Open API returned an invalid lock rule"
            )
        return cls._normalized_lock_rule(
            data.get("type"),
            ended_time=data.get("ended_time"),
        )

    @classmethod
    def _parse_legacy_lock_rule(cls, payload: dict) -> dict[str, object]:
        """Parse known private-API envelopes without accepting arbitrary JSON."""
        if "code" in payload and payload.get("code") != "SUCCESS":
            raise AccessClientError("UniFi Access legacy lock-rule request failed")
        if "meta" in payload:
            meta = payload.get("meta")
            if not isinstance(meta, dict) or meta.get("rc") not in {"ok", "success"}:
                raise AccessClientError("UniFi Access legacy lock-rule request failed")

        candidates: list[object] = [payload]
        if "data" in payload:
            candidates.append(payload["data"])
        if "result" in payload:
            candidates.append(payload["result"])

        for candidate in candidates:
            if isinstance(candidate, str) and candidate in _LOCK_RULE_TYPES:
                return cls._normalized_lock_rule(candidate)
            if not isinstance(candidate, dict):
                continue
            nested = candidate.get("lock_rule")
            if isinstance(nested, dict):
                try:
                    return cls._normalized_lock_rule(
                        nested.get("type") or nested.get("lock_rule"),
                        ended_time=nested.get(
                            "ended_time", nested.get("end_time")
                        ),
                    )
                except AccessClientError:
                    pass
            value = candidate.get("type") or candidate.get("lock_rule")
            if value is not None and not isinstance(value, dict):
                return cls._normalized_lock_rule(
                    value,
                    ended_time=candidate.get(
                        "ended_time", candidate.get("end_time")
                    ),
                )

        raise AccessClientError(
            "UniFi Access returned an invalid legacy lock-rule envelope"
        )

    @staticmethod
    def _validate_legacy_rule_write(payload: dict, requested_type: str) -> None:
        """Accept only explicit success shapes observed across Access releases."""
        if "code" in payload:
            if payload.get("code") == "SUCCESS":
                return
            raise AccessClientError("UniFi Access rejected the legacy lock rule")

        if "meta" in payload:
            meta = payload.get("meta")
            if isinstance(meta, dict) and meta.get("rc") in {"ok", "success"}:
                return
            raise AccessClientError("UniFi Access rejected the legacy lock rule")

        if payload.get("success") is True or payload.get("data") == "success":
            return

        # A few private API versions echo the new rule instead of returning a
        # success sentinel. Reuse the strict rule parser and require an exact
        # match rather than treating any object body as success.
        try:
            echoed = AccessClient._parse_legacy_lock_rule(payload)
        except AccessClientError as exc:
            raise AccessClientError(
                "UniFi Access returned an invalid legacy rule-write envelope"
            ) from exc
        if echoed["type"] != requested_type:
            raise AccessClientError("UniFi Access echoed a different lock rule")

    @staticmethod
    def _legacy_state_from_rule(rule: dict[str, object]) -> str:
        rule_type = rule.get("type")
        if rule_type in _UNLOCKED_RULE_TYPES:
            return "unlocked"
        if rule_type in _LOCKED_RULE_TYPES:
            return "locked"
        # `reset` means "return to native behavior"; native behavior may be
        # locked or inside an active unlock schedule. Guessing here would turn
        # an unverified state into a false safety confirmation.
        raise AccessClientError(
            "Legacy Access API did not expose the door state after reset"
        )

    async def get_lock_rule(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, object]:
        """Fetch a normalized rule as ``type`` plus optional ``ended_time``."""
        if self.open_api_configured:
            if not location_id:
                raise AccessClientError(
                    "Official UniFi Access lock control requires a location_id"
                )
            path = API_OPEN_DOOR_LOCK_RULE.format(location_id=location_id)
            data = await self._open_api_request("GET", path)
            return self._parse_official_lock_rule(data)

        if not device_id:
            raise AccessClientError(
                "Legacy UniFi Access lock control requires a device_id"
            )
        path = API_DEVICE_LOCK_RULE.format(device_id=device_id)
        try:
            payload = await self._legacy_json_request("GET", path)
        except AccessClientError as exc:
            if getattr(exc, "status", None) == 404:
                raise AccessLegacyEndpointGoneError(
                    _LEGACY_ENDPOINT_GONE_MESSAGE
                ) from exc
            raise
        return self._parse_legacy_lock_rule(payload)

    async def get_door_state(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> str:
        """Return exactly ``locked`` or ``unlocked`` from bounded API data."""
        if self.open_api_configured:
            if not location_id:
                raise AccessClientError(
                    "Official UniFi Access door state requires a location_id"
                )
            path = API_OPEN_DOOR.format(location_id=location_id)
            data = await self._open_api_request("GET", path)
            if not isinstance(data, dict) or data.get("id") != location_id:
                raise AccessClientError(
                    "UniFi Access Open API returned the wrong door state"
                )
            relay_state = data.get("door_lock_relay_status")
            if relay_state == "lock":
                return "locked"
            if relay_state == "unlock":
                return "unlocked"
            raise AccessClientError(
                "UniFi Access Open API returned an invalid door relay state"
            )

        rule = await self.get_lock_rule(device_id, location_id=location_id)
        return self._legacy_state_from_rule(rule)

    async def _confirm_rule_command(
        self,
        device_id: str,
        location_id: str | None,
        *,
        requested_type: str,
        accepted_types: frozenset[str] | None,
        rejected_types: frozenset[str] = frozenset(),
        expected_state: str | None,
        must_change_from: dict[str, object] | None = None,
    ) -> dict[str, str]:
        last_error: AccessClientError | None = None
        last_rule: str | None = None
        last_state: str | None = None

        for attempt in range(_LOCK_CONFIRM_ATTEMPTS):
            try:
                rule = await self.get_lock_rule(
                    device_id,
                    location_id=location_id,
                )
                last_rule = str(rule["type"])
                rule_matches = (
                    last_rule in accepted_types
                    if accepted_types is not None
                    else last_rule not in rejected_types
                )
                if must_change_from is not None and rule == must_change_from:
                    rule_matches = False
                if rule_matches:
                    if self.open_api_configured:
                        last_state = await self.get_door_state(
                            device_id,
                            location_id=location_id,
                        )
                    else:
                        last_state = self._legacy_state_from_rule(rule)
                    if expected_state is None or last_state == expected_state:
                        return {"type": last_rule, "state": last_state}
            except AccessClientError as exc:
                last_error = exc

            if attempt + 1 < _LOCK_CONFIRM_ATTEMPTS:
                await asyncio.sleep(_LOCK_CONFIRM_DELAY)

        detail = ""
        if last_rule is not None or last_state is not None:
            detail = f" (observed rule={last_rule}, state={last_state})"
        error = AccessClientError(
            f"UniFi Access {requested_type} command was not confirmed{detail}"
        )
        if last_error is not None:
            raise error from last_error
        raise error

    async def _write_rule_and_confirm(
        self,
        device_id: str,
        location_id: str | None,
        *,
        rule_type: str,
        accepted_types: frozenset[str] | None,
        rejected_types: frozenset[str] = frozenset(),
        expected_state: str | None,
        must_change_from: dict[str, object] | None = None,
    ) -> dict[str, str]:
        if rule_type not in _LOCK_RULE_TYPES:
            raise AccessClientError("Unsupported UniFi Access lock rule")

        if self.open_api_configured:
            if not location_id:
                raise AccessClientError(
                    "Official UniFi Access lock control requires a location_id"
                )
            path = API_OPEN_DOOR_LOCK_RULE.format(location_id=location_id)
            data = await self._open_api_request(
                "PUT",
                path,
                json_body={"type": rule_type},
            )
            if data != "success":
                raise AccessClientError(
                    "UniFi Access Open API returned an invalid rule-write result"
                )
        else:
            if not device_id:
                raise AccessClientError(
                    "Legacy UniFi Access lock control requires a device_id"
                )
            path = API_DEVICE_LOCK_RULE.format(device_id=device_id)
            try:
                payload = await self._legacy_json_request(
                    "PUT",
                    path,
                    json_body={"lock_rule": rule_type},
                )
            except AccessClientError as exc:
                if getattr(exc, "status", None) == 404:
                    raise AccessLegacyEndpointGoneError(
                        _LEGACY_ENDPOINT_GONE_MESSAGE
                    ) from exc
                raise
            self._validate_legacy_rule_write(payload, rule_type)

        return await self._confirm_rule_command(
            device_id,
            location_id,
            requested_type=rule_type,
            accepted_types=accepted_types,
            rejected_types=rejected_types,
            expected_state=expected_state,
            must_change_from=must_change_from,
        )

    async def hold_unlocked(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Apply and confirm a persistent ``keep_unlock`` override."""
        result = await self._write_rule_and_confirm(
            device_id,
            location_id,
            rule_type="keep_unlock",
            accepted_types=frozenset({"keep_unlock"}),
            expected_state="unlocked",
        )
        logger.info("Persistent unlock confirmed for device %s", device_id)
        return result

    async def hold_locked(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Apply and confirm a persistent ``keep_lock`` override."""
        result = await self._write_rule_and_confirm(
            device_id,
            location_id,
            rule_type="keep_lock",
            accepted_types=frozenset({"keep_lock"}),
            expected_state="locked",
        )
        logger.info("Persistent lock confirmed for device %s", device_id)
        return result

    async def force_lock(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Lock now, terminating an active schedule or temporary unlock."""
        result = await self._write_rule_and_confirm(
            device_id,
            location_id,
            rule_type="lock_now",
            # The official GET schema treats lock_now as an input operation;
            # firmware commonly reports the resulting override as lock_early
            # or keep_lock. Private firmware may echo lock_now.
            accepted_types=_LOCKED_RULE_TYPES,
            expected_state="locked",
        )
        logger.info("Immediate lock confirmed for device %s", device_id)
        return result

    async def release_persistent_lock(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Replace ``keep_lock`` with a schedule-safe immediate lock.

        Hub-sync lifecycle code may clear its durable ownership only when
        readback proves that the previous persistent rule changed. A stale
        ``keep_lock`` response is still physically safe, but accepting it would
        strand future schedules with no recovery record.
        """
        previous = await self.get_lock_rule(
            device_id,
            location_id=location_id,
        )
        must_change_from = previous if previous.get("type") == "keep_lock" else None
        result = await self._write_rule_and_confirm(
            device_id,
            location_id,
            rule_type="lock_now",
            accepted_types=_LOCKED_RULE_TYPES,
            expected_state="locked",
            must_change_from=must_change_from,
        )
        logger.info(
            "Persistent lock override released and immediate lock confirmed for %s",
            device_id,
        )
        return result

    async def restore_native_rule(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Clear this app's temporary override and restore Access behavior."""
        previous = await self.get_lock_rule(
            device_id,
            location_id=location_id,
        )
        # reset is idempotent when Access already reports native/schedule
        # behavior. For any temporary/early-lock rule, require a post-write
        # transition so a stale GET cannot be mislabeled as Follow Schedule.
        must_change_from = (
            None
            if previous.get("type") in {"schedule", "reset"}
            else previous
        )
        result = await self._write_rule_and_confirm(
            device_id,
            location_id,
            rule_type="reset",
            accepted_types=None,
            rejected_types=frozenset({"keep_lock", "keep_unlock", "custom"}),
            expected_state=None,
            must_change_from=must_change_from,
        )
        logger.info("Native lock rule restored for device %s", device_id)
        return result

    async def unlock_persistent(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Compatibility wrapper for :meth:`hold_unlocked`."""
        return await self.hold_unlocked(device_id, location_id=location_id)

    async def lock(
        self,
        device_id: str,
        *,
        location_id: str | None = None,
    ) -> dict[str, str]:
        """Compatibility wrapper for immediate locking, never rule reset."""
        return await self.force_lock(device_id, location_id=location_id)

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
        if callback not in self._callbacks:
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
                logger.warning(
                    "Access WebSocket returned HTTP %d — retrying in %.0fs",
                    exc.status,
                    delay,
                )
            except Exception as exc:
                # Some aiohttp exception strings embed the complete request
                # URL, whose query contains the Access CSRF credential.
                logger.error(
                    "Access WebSocket %s — retrying in %.0fs",
                    type(exc).__name__,
                    delay,
                )
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
        else:
            # Normal WebSocket closure leaves the REST session authenticated.
            # Revalidate it so every upgrade remains site-bound, not only
            # reconnects that happened to receive a 401 first.
            await self.verify_console_identity()

        # Build wss:// URL with CSRF token as a query parameter (UniFi requirement)
        ws_url = (
            f"wss://{self._host}{API_WEBSOCKET}"
            f"?x-csrf-token={self._csrf_token}"
        )
        headers = {"X-CSRF-Token": self._csrf_token}
        if self._auth_cookie:
            headers["Cookie"] = f"TOKEN={self._auth_cookie}"

        session = self._get_session()

        # The actual URL carries the CSRF token in its query string. Never log
        # that session credential; host + path are sufficient diagnostics.
        logger.info(
            "Connecting to Access WebSocket at %s%s", self._host, API_WEBSOCKET
        )
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
        # Seed activity age on every (re)connect for API diagnostics. Socket
        # liveness itself is handled by aiohttp heartbeat + this loop.
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
        if self._api_session is not None and not self._api_session.closed:
            await self._api_session.close()
            self._api_session = None
        self._csrf_token = None
        logger.info("AccessClient closed")
