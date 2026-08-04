"""Regression tests for the 2026-08 web review fixes.

Covers:
- WEB-1: _render mints CSRF tokens for the same identity require_login /
  the CSRF middleware validate against (ingress SSO wins over a stale
  session cookie), and never refreshes the stale cookie under ingress.
- WEB-2: the session cookie only carries Secure when the browser-facing
  hop is HTTPS (direct plain-HTTP deployments must not get a cookie the
  browser silently discards).
- WEB-8: the per-visitor operation lock is retired after a successful
  delete so app.state.visitor_operation_locks stays bounded.
- FE-2: lock-action failures redirected to /locks?error=... surface as a
  visible error banner.
- FE-4: the rate-limited login page renders as the bare login page, not
  inside the authenticated app shell.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from access_control import web_auth, web_routes


def _request(
    *,
    headers=None,
    cookies=None,
    scope=None,
    ingress_user=None,
    ingress_active=False,
    scheme="http",
    query_params=None,
    **app_state,
):
    state = SimpleNamespace(
        ingress_user=ingress_user, ingress_active=ingress_active
    )
    defaults = {
        "db": None,
        "access_client": None,
        "ha_client": None,
        "protect_client": None,
        "auth_engine": None,
        "relock_manager": None,
        "lock_states": {},
        "enc_key": None,
    }
    defaults.update(app_state)
    req = SimpleNamespace(
        headers=headers or {},
        cookies=cookies or {},
        scope=scope if scope is not None else {},
        state=state,
        url=SimpleNamespace(scheme=scheme),
        client=SimpleNamespace(host="127.0.0.1"),
        app=SimpleNamespace(state=SimpleNamespace(**defaults)),
    )
    if query_params is not None:
        req.query_params = query_params
    return req


class CsrfIdentityConsistencyTests(unittest.IsolatedAsyncioTestCase):
    """WEB-1: a client holding BOTH an ingress SSO identity and a session
    cookie must get CSRF tokens minted for the identity the validators
    (require_login / the CSRF middleware) resolve — ingress first."""

    def setUp(self) -> None:
        web_auth.SECRET_KEY = "test-secret"

    async def _render_context(self, request):
        captured = {}
        response = HTMLResponse("ok")

        def fake_template_response(req, template, context):
            captured.update(context)
            return response

        with patch.object(
            web_routes.templates, "TemplateResponse", fake_template_response
        ):
            rendered = await web_routes._render(
                "home.html", request, {"request": request}
            )
        return captured, rendered

    async def test_token_validates_for_require_login_identity(self) -> None:
        cookie = web_auth.create_session_cookie("cookie-admin")
        request = _request(
            cookies={"session": cookie},
            ingress_user={"id": "uid-1", "name": "Nick"},
            ingress_active=True,
        )

        context, rendered = await self._render_context(request)

        validator_identity = web_auth.require_login(request)
        self.assertEqual(validator_identity, "ha:Nick")
        self.assertTrue(
            web_auth.validate_csrf_token(
                context["csrf_token"], validator_identity
            ),
            "CSRF token minted by _render must validate for the identity "
            "require_login returns",
        )

    async def test_stale_cookie_is_not_refreshed_under_ingress(self) -> None:
        cookie = web_auth.create_session_cookie("cookie-admin")
        request = _request(
            cookies={"session": cookie},
            ingress_user={"id": "uid-1", "name": "Nick"},
            ingress_active=True,
        )

        _, rendered = await self._render_context(request)

        self.assertNotIn(
            "set-cookie",
            rendered.headers,
            "the stale session cookie must not be re-signed under ingress "
            "SSO — that made the CSRF lockout self-sustaining",
        )

    async def test_cookie_only_client_keeps_token_and_refresh(self) -> None:
        cookie = web_auth.create_session_cookie("cookie-admin")
        request = _request(cookies={"session": cookie})

        context, rendered = await self._render_context(request)

        self.assertTrue(
            web_auth.validate_csrf_token(
                context["csrf_token"], web_auth.require_login(request)
            )
        )
        self.assertIn("set-cookie", rendered.headers)


class SessionCookieSecureTests(unittest.TestCase):
    """WEB-2: Secure must track the browser-facing scheme; a Secure cookie
    set over plain HTTP is silently discarded → infinite login loop."""

    def setUp(self) -> None:
        web_auth.SECRET_KEY = "test-secret"

    @staticmethod
    def _set_cookie(request) -> str:
        response = Response()
        web_auth.set_session_cookie(response, request, "admin")
        return response.headers["set-cookie"]

    def test_plain_http_direct_port_omits_secure(self) -> None:
        header = self._set_cookie(_request(scheme="http"))
        self.assertNotIn("secure", header.lower())
        self.assertIn("httponly", header.lower())

    def test_https_direct_port_keeps_secure(self) -> None:
        header = self._set_cookie(_request(scheme="https"))
        self.assertIn("secure", header.lower())

    def test_forwarded_https_proto_keeps_secure(self) -> None:
        header = self._set_cookie(
            _request(scheme="http", headers={"x-forwarded-proto": "https"})
        )
        self.assertIn("secure", header.lower())

    def test_ingress_keeps_secure_despite_plain_http_hop(self) -> None:
        header = self._set_cookie(_request(scheme="http", ingress_active=True))
        self.assertIn("secure", header.lower())


class VisitorLockCleanupTests(unittest.IsolatedAsyncioTestCase):
    """WEB-8: visitor_operation_locks must not grow one Lock per visitor
    forever — a successful delete retires the entry."""

    @staticmethod
    def _db(visitor):
        return SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            get_visitor=AsyncMock(return_value=visitor),
            delete_visitor=AsyncMock(),
            log_admin_action=AsyncMock(),
        )

    _VISITOR = {"id": 5, "name": "Guest", "unvr_visitor_id": "v-5"}

    async def test_successful_delete_retires_operation_lock(self) -> None:
        access = SimpleNamespace(connected=True, delete_visitor=AsyncMock())
        request = _request(db=self._db(self._VISITOR), access_client=access)

        response = await web_routes.delete_visitor_route(
            5, request, user="admin"
        )

        self.assertEqual(response.status_code, 303)
        self.assertNotIn("error=", response.headers["location"])
        self.assertEqual(request.app.state.visitor_operation_locks, {})

    async def test_failed_delete_keeps_operation_lock(self) -> None:
        access = SimpleNamespace(
            connected=True,
            delete_visitor=AsyncMock(side_effect=Exception("boom")),
        )
        request = _request(db=self._db(self._VISITOR), access_client=access)

        response = await web_routes.delete_visitor_route(
            5, request, user="admin"
        )

        self.assertIn("error=", response.headers["location"])
        self.assertIn(5, request.app.state.visitor_operation_locks)


class LocksErrorBannerTests(unittest.IsolatedAsyncioTestCase):
    """FE-2: /locks?error=... must surface as a visible error banner."""

    async def test_locks_list_reads_error_query_param(self) -> None:
        db = SimpleNamespace(
            get_all_locks=AsyncMock(return_value=[]),
            get_entry_devices_for_locks=AsyncMock(return_value={}),
        )
        request = _request(
            db=db,
            query_params={"error": "Lock action failed", "notice": None},
        )
        captured = {}

        async def fake_render(template, req, context):
            captured.update(context)
            return HTMLResponse("ok")

        with patch.object(web_routes, "_render", fake_render):
            await web_routes.locks_list(request, user="admin")

        self.assertEqual(captured["command_error"], "Lock action failed")

    def test_template_renders_error_banner(self) -> None:
        template = web_routes.templates.env.get_template("locks.html")
        html = template.render(
            request=SimpleNamespace(scope={}),
            user="admin",
            page="locks",
            ingress_active=False,
            ingress_path="",
            csrf_token="csrf",
            lockdown=False,
            locks=[],
            ha_locks=[],
            access_locations=[],
            protect_doorbells=[],
            protect_cameras=[],
            command_notice=None,
            command_error="Lock action denied: lockdown active",
        )
        self.assertIn("Lock action denied: lockdown active", html)
        self.assertIn('role="alert"', html)

    def test_template_omits_banner_without_error(self) -> None:
        template = web_routes.templates.env.get_template("locks.html")
        html = template.render(
            request=SimpleNamespace(scope={}),
            user="admin",
            page="locks",
            ingress_active=False,
            ingress_path="",
            csrf_token="csrf",
            lockdown=False,
            locks=[],
            ha_locks=[],
            access_locations=[],
            protect_doorbells=[],
            protect_cameras=[],
            command_notice=None,
            command_error=None,
        )
        self.assertNotIn('role="alert"', html)


class RateLimitedLoginPageTests(unittest.TestCase):
    """FE-4: the 429 login render must stay on the bare login page, not the
    authenticated app shell (sidebar + sign-out)."""

    def test_429_login_render_has_no_app_shell(self) -> None:
        web_auth.SECRET_KEY = "test-secret"
        app = FastAPI()
        app.include_router(web_routes.router)
        app.state.db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=False),
        )

        with TestClient(app) as client:
            response = client.post(
                "/login",
                data={"username": "admin", "password": "pw"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 429)
        self.assertIn("Too many failed attempts", response.text)
        # The shell markup (not the always-present CSS rules) must be absent.
        self.assertNotIn('<div id="app-shell">', response.text)
        self.assertNotIn('<aside id="sidebar">', response.text)
        self.assertNotIn("Sign out", response.text)


if __name__ == "__main__":
    unittest.main()
