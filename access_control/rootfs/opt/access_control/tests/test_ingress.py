"""
Tests for the HA Ingress middleware (ingress.py).

Covers:
- Valid Supervisor ingress headers + admin user → ingress_user populated,
  root_path set on the scope.
- Valid headers + non-admin → 403 HTML response.
- Missing X-Ingress-Path → SSO headers ignored, falls through with empty state.
- Malformed X-Ingress-Path (header-injection attempt from another addon) →
  SSO headers ignored.
- X-Ingress-Path present but no X-Remote-User-* headers → root_path set,
  no SSO login (legacy session-cookie path can still kick in downstream).
- Cookie Path scoping helper (web_auth._cookie_path) returns the ingress
  prefix when active, "/" otherwise.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def _load_package() -> None:
    """Load the access_control package into sys.modules if not present."""
    if "access_control" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        "access_control",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    pkg = importlib.util.module_from_spec(spec)
    sys.modules["access_control"] = pkg
    spec.loader.exec_module(pkg)


_load_package()
from access_control.ingress import (  # noqa: E402
    INGRESS_PATH_RE,
    ingress_middleware,
)


def _fake_request(headers: dict[str, str]) -> SimpleNamespace:
    """
    Build a minimal Request-like object with the attributes the middleware
    actually touches: .headers, .scope (mutable dict), .state (mutable namespace).
    Starlette's real Request supports much more, but the middleware here
    sticks to this narrow surface.
    """
    return SimpleNamespace(
        headers=headers,
        scope={"type": "http"},
        state=SimpleNamespace(),
    )


async def _passthrough(request):
    """A fake `call_next` that just echoes the request scope+state for assertions."""
    return SimpleNamespace(scope=request.scope, state=request.state, status_code=200)


class TestIngressPathRegex(unittest.TestCase):
    """The regex is the defense against header injection — it must be strict."""

    def test_accepts_real_supervisor_format(self):
        # Real Supervisor prefixes look like /api/hassio_ingress/<base64url-token>
        valid = [
            "/api/hassio_ingress/abcDEF123_-xyz",
            "/api/hassio_ingress/A",
            "/api/hassio_ingress/01234567890abcdef-_",
        ]
        for path in valid:
            self.assertIsNotNone(INGRESS_PATH_RE.match(path), f"should accept {path!r}")

    def test_rejects_malformed(self):
        invalid = [
            "",
            "/",
            "/api/hassio_ingress",                  # missing token
            "/api/hassio_ingress/",                 # empty token
            "/api/hassio_ingress/tok/extra",        # extra path segment
            "/api/hassio_ingress/tok!",             # invalid char
            "/api/hassio_ingress/tok ",             # trailing space
            "/api/hassio_ingress/tok\n",            # newline injection
            "api/hassio_ingress/tok",               # missing leading slash
            "/api/foo/hassio_ingress/tok",          # wrong prefix
            "/api/hassio_ingress/tok/../escape",    # path traversal attempt
        ]
        for path in invalid:
            self.assertIsNone(INGRESS_PATH_RE.match(path), f"should reject {path!r}")


class TestIngressMiddleware(unittest.IsolatedAsyncioTestCase):

    async def test_admin_via_supervisor_sets_ingress_user_and_root_path(self):
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/realtoken123",
            "X-Remote-User-Id": "abc-def",
            "X-Remote-User-Name": "Nick",
            "X-Remote-User-Is-Admin": "true",
        })

        resp = await ingress_middleware(req, _passthrough)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(req.scope["root_path"], "/api/hassio_ingress/realtoken123")
        self.assertTrue(req.state.ingress_active)
        self.assertEqual(req.state.ingress_user, {"id": "abc-def", "name": "Nick"})

    async def test_admin_value_one_accepted(self):
        # Supervisor serializes is_admin as "1"/"0" in current versions.
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/realtoken123",
            "X-Remote-User-Id": "abc-def",
            "X-Remote-User-Name": "Nick",
            "X-Remote-User-Is-Admin": "1",
        })
        resp = await ingress_middleware(req, _passthrough)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(req.state.ingress_user, {"id": "abc-def", "name": "Nick"})

    async def test_admin_value_zero_rejected(self):
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/realtoken123",
            "X-Remote-User-Id": "abc-def",
            "X-Remote-User-Name": "Guest",
            "X-Remote-User-Is-Admin": "0",
        })
        resp = await ingress_middleware(req, _passthrough)
        self.assertEqual(resp.status_code, 403)

    async def test_x_hass_header_scheme_accepted(self):
        # Older Core ingress uses X-Hass-* instead of X-Remote-User-*.
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/realtoken123",
            "X-Hass-User-Id": "abc-def",
            "X-Hass-Is-Admin": "1",
        })
        resp = await ingress_middleware(req, _passthrough)
        self.assertEqual(resp.status_code, 200)
        # No name header sent — middleware should fall back to id for the
        # display name so downstream auth has something non-empty.
        self.assertEqual(req.state.ingress_user, {"id": "abc-def", "name": "abc-def"})

    async def test_non_admin_via_supervisor_gets_403(self):
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/realtoken123",
            "X-Remote-User-Id": "abc-def",
            "X-Remote-User-Name": "Guest",
            "X-Remote-User-Is-Admin": "false",
        })

        resp = await ingress_middleware(req, _passthrough)

        # 403 short-circuits before call_next; resp is our HTMLResponse
        self.assertEqual(resp.status_code, 403)
        # Even though we 403, root_path is still set (we got far enough to
        # recognize the request as ingress; we just refused to authorize it)
        self.assertEqual(req.scope["root_path"], "/api/hassio_ingress/realtoken123")
        self.assertIsNone(req.state.ingress_user)

    async def test_missing_ingress_header_ignores_sso_headers(self):
        # No X-Ingress-Path: SSO headers must NOT be trusted (could be
        # forged by another addon on the Docker bridge).
        req = _fake_request({
            "X-Remote-User-Id": "attacker",
            "X-Remote-User-Name": "fake",
            "X-Remote-User-Is-Admin": "true",
        })

        resp = await ingress_middleware(req, _passthrough)

        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("root_path", req.scope)
        self.assertFalse(req.state.ingress_active)
        self.assertIsNone(req.state.ingress_user)

    async def test_forged_ingress_path_format_ignored(self):
        # Header injection attempt: a value that *looks* close but doesn't
        # match the strict regex. Must be ignored.
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/tok/../etc/passwd",
            "X-Remote-User-Id": "attacker",
            "X-Remote-User-Name": "fake",
            "X-Remote-User-Is-Admin": "true",
        })

        resp = await ingress_middleware(req, _passthrough)

        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("root_path", req.scope)
        self.assertFalse(req.state.ingress_active)
        self.assertIsNone(req.state.ingress_user)

    async def test_valid_path_no_sso_headers_sets_root_only(self):
        # Edge case: Supervisor ingress can route /health/live (auth-exempt)
        # without sending X-Remote-User-* headers. The middleware should
        # still set root_path but not populate ingress_user.
        req = _fake_request({
            "X-Ingress-Path": "/api/hassio_ingress/realtoken123",
        })

        resp = await ingress_middleware(req, _passthrough)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(req.scope["root_path"], "/api/hassio_ingress/realtoken123")
        self.assertTrue(req.state.ingress_active)
        self.assertIsNone(req.state.ingress_user)


class TestSecurityHeaders(unittest.TestCase):
    """The frame-blocking headers must flip based on ingress_active.

    Direct mode: X-Frame-Options: DENY + frame-ancestors 'none' (addon
    must never be iframed). Ingress mode: SAMEORIGIN + frame-ancestors
    'self' so HA can render the addon inside its own iframe.
    """

    def setUp(self):
        from access_control.ingress import security_headers_for
        self._fn = security_headers_for

    def test_direct_mode_blocks_framing(self):
        h = self._fn(ingress_active=False)
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])

    def test_ingress_mode_allows_same_origin_framing(self):
        h = self._fn(ingress_active=True)
        self.assertEqual(h["X-Frame-Options"], "SAMEORIGIN")
        self.assertIn("frame-ancestors 'self'", h["Content-Security-Policy"])

    def test_common_headers_are_set_in_both_modes(self):
        for mode in (False, True):
            h = self._fn(ingress_active=mode)
            self.assertEqual(h["X-Content-Type-Options"], "nosniff")
            self.assertIn("max-age=31536000", h["Strict-Transport-Security"])
            self.assertIn("'unsafe-inline'", h["Content-Security-Policy"])


class TestCookiePath(unittest.TestCase):
    """The cookie Path scope must follow root_path so session cookies don't
    leak across addons sharing the HA host."""

    def setUp(self):
        from access_control.web_auth import _cookie_path
        self._cookie_path = _cookie_path

    def test_ingress_path_used_as_cookie_path(self):
        req = SimpleNamespace(scope={"root_path": "/api/hassio_ingress/tok"})
        self.assertEqual(self._cookie_path(req), "/api/hassio_ingress/tok")

    def test_no_root_path_falls_back_to_slash(self):
        req = SimpleNamespace(scope={})
        self.assertEqual(self._cookie_path(req), "/")

    def test_empty_root_path_falls_back_to_slash(self):
        req = SimpleNamespace(scope={"root_path": ""})
        self.assertEqual(self._cookie_path(req), "/")


if __name__ == "__main__":
    unittest.main()
