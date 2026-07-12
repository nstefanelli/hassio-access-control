from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover - skipped in environments without FastAPI/httpx
    TestClient = None


ROOT = Path(__file__).resolve().parents[1]


def _load_package() -> None:
    if "access_control" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        "access_control",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["access_control"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)


def _reload_access_control_modules():
    _load_package()
    module_names = [
        "access_control.database",
        "access_control.config",
        "access_control.web_auth",
        "access_control.api_auth",
        "access_control.access_client",
        "access_control.protect_client",
        "access_control.ha_client",
        "access_control.auth_engine",
        "access_control.api_routes",
        "access_control.web_routes",
        "access_control.main",
    ]
    loaded = {}
    for name in module_names:
        if name in sys.modules:
            loaded[name] = importlib.reload(sys.modules[name])
        else:
            loaded[name] = importlib.import_module(name)
    return loaded


@unittest.skipIf(TestClient is None, "FastAPI/httpx not installed in this environment")
class IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self._old_data_dir = os.environ.get("DATA_DIR")
        os.environ["DATA_DIR"] = self.tempdir.name
        self.modules = _reload_access_control_modules()

    def tearDown(self) -> None:
        if self._old_data_dir is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = self._old_data_dir
        self.tempdir.cleanup()

    def _seed_configured_db(self) -> None:
        database = self.modules["access_control.database"]
        config = self.modules["access_control.config"]

        async def _seed() -> None:
            db = database.Database()
            await db.connect()
            secret_key = "integration-secret"
            salt = b"0123456789abcdef"
            enc_key = config.derive_key(secret_key, salt)
            await db.set_config("admin_username", "admin")
            await db.set_config("admin_password_hash", config.hash_password("password"))
            await db.set_config("secret_key", secret_key)
            await db.set_config("encryption_salt", salt.hex())
            await db.set_config("unvr_host", "unvr.local")
            await db.set_config("unvr_username", config.encrypt_value("user", enc_key))
            await db.set_config("unvr_password", config.encrypt_value("pass", enc_key))
            await db.set_config("ha_url", "http://ha.local")
            await db.set_config("ha_token", config.encrypt_value("token", enc_key))
            await db.close()

        asyncio.run(_seed())

    def test_setup_guard_redirects_when_unconfigured(self) -> None:
        app_module = self.modules["access_control.main"]

        with TestClient(app_module.app) as client:
            response = client.get("/", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/setup")
        # Security and cache headers are finalized by the outer ingress
        # boundary even when setup_guard returns before routing.
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

    def test_body_cap_covers_unauthenticated_login(self) -> None:
        app_module = self.modules["access_control.main"]
        oversized = b"x" * (app_module._MAX_FORM_BODY + 1)

        with TestClient(app_module.app) as client:
            response = client.post(
                "/login",
                content=oversized,
                headers={"content-type": "application/octet-stream"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_body_cap_covers_chunked_setup_submission(self) -> None:
        app_module = self.modules["access_control.main"]

        def chunks():
            yield b"x" * (app_module._MAX_FORM_BODY // 2)
            yield b"y" * (app_module._MAX_FORM_BODY // 2 + 2)

        with TestClient(app_module.app) as client:
            response = client.post(
                "/setup",
                content=chunks(),
                headers={
                    "content-type": "application/octet-stream",
                    "transfer-encoding": "chunked",
                },
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_unhandled_exception_is_sanitized_with_security_headers(self) -> None:
        app_module = self.modules["access_control.main"]

        @app_module.app.get("/__regression_unhandled_exception")
        async def regression_failure():
            raise RuntimeError("sensitive upstream failure detail")

        with TestClient(
            app_module.app, raise_server_exceptions=False
        ) as client:
            # This is an intentionally unconfigured lifespan; bypass only the
            # setup redirect so the synthetic failing route is reachable.
            app_module.app.state.configured = True
            response = client.get("/__regression_unhandled_exception")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.text, "Internal Server Error")
        self.assertNotIn("sensitive upstream", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertIn(
            "frame-ancestors 'none'",
            response.headers["content-security-policy"],
        )

    def test_login_and_csrf_middleware_end_to_end(self) -> None:
        self._seed_configured_db()
        app_module = self.modules["access_control.main"]

        with patch("access_control.access_client.AccessClient.login", new=AsyncMock(return_value=None)), \
             patch("access_control.access_client.AccessClient.get_console_identity", new=AsyncMock(return_value="site-identity")), \
             patch("access_control.access_client.AccessClient.verify_console_identity", new=AsyncMock(return_value="site-identity")), \
             patch("access_control.access_client.AccessClient.fetch_users", new=AsyncMock(return_value=[])), \
             patch("access_control.access_client.AccessClient.get_bootstrap", new=AsyncMock(return_value={"data": []})), \
             patch("access_control.access_client.AccessClient.start_websocket", new=AsyncMock(return_value=None)), \
             patch("access_control.protect_client.ProtectClient.login", new=AsyncMock(return_value=None)), \
             patch("access_control.protect_client.ProtectClient.start_websocket", new=AsyncMock(return_value=None)), \
             patch("access_control.ha_client.HAClient.test_connection", new=AsyncMock(return_value=False)):
            # base_url MUST be https: the session cookie is Secure, so over a
            # plain-http test transport httpx would drop it and the follow-up
            # POST would arrive unauthenticated (303 login-redirect) instead of
            # exercising the CSRF middleware (403). This is what previously made
            # the end-to-end CSRF assertion unreachable.
            with TestClient(app_module.app, base_url="https://testserver") as client:
                login_page = client.get("/login")
                self.assertEqual(login_page.status_code, 200)

                login_response = client.post(
                    "/login",
                    data={"username": "admin", "password": "password"},
                    follow_redirects=False,
                )
                self.assertEqual(login_response.status_code, 303)
                self.assertEqual(login_response.headers["location"], "/")

                # Authenticated (cookie now round-trips) but no CSRF token —
                # the CSRF middleware must reject with 403.
                csrf_fail = client.post("/sync-users", data={}, follow_redirects=False)
                self.assertEqual(csrf_fail.status_code, 403)

                # The dashboard polls every few seconds. That is not user
                # activity and must not slide the session expiry forever.
                background = client.get(
                    "/", headers={"X-Background-Poll": "true"}
                )
                self.assertEqual(background.status_code, 200)
                self.assertNotIn("set-cookie", background.headers)
                self.assertEqual(background.headers["cache-control"], "no-store")


if __name__ == "__main__":
    unittest.main()
