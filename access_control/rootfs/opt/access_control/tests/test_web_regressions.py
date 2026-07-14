"""Web-boundary regressions found by the end-to-end review."""
from __future__ import annotations

import unittest
from datetime import timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch
from zoneinfo import ZoneInfo

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from access_control import web_auth, web_routes


def _request(
    *, zone=timezone.utc, headers=None, db=None, access=None, ha=None,
    auth_engine=None, relock_manager=None, physical_command_lock=None,
):
    if auth_engine is None:
        auth_engine = SimpleNamespace(tz=zone, lockdown=False)
    return SimpleNamespace(
        headers=headers or {},
        scope={},
        state=SimpleNamespace(ingress_user=None, ingress_active=False),
        client=SimpleNamespace(host="127.0.0.1"),
        app=SimpleNamespace(
            state=SimpleNamespace(
                auth_engine=auth_engine,
                db=db,
                access_client=access,
                ha_client=ha,
                enc_key=None,
                lock_states={},
                relock_manager=relock_manager,
                physical_command_lock=physical_command_lock,
            )
        ),
    )


class SiteTimezoneTests(unittest.TestCase):
    def test_site_timezone_comes_from_auth_engine(self) -> None:
        berlin = ZoneInfo("Europe/Berlin")
        self.assertIs(web_routes._site_timezone(_request(zone=berlin)), berlin)

    def test_dst_gap_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not exist"):
            web_routes._parse_site_datetime(
                "2026-03-08", "02:30", ZoneInfo("America/New_York")
            )

    def test_dst_fold_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            web_routes._parse_site_datetime(
                "2026-11-01", "01:30", ZoneInfo("America/New_York")
            )

    def test_valid_local_time_retains_configured_zone(self) -> None:
        zone = ZoneInfo("America/Los_Angeles")
        parsed = web_routes._parse_site_datetime("2026-07-12", "14:30", zone)
        self.assertEqual(parsed.tzinfo, zone)
        self.assertEqual((parsed.hour, parsed.minute), (14, 30))


class VisitorExtensionTests(unittest.IsolatedAsyncioTestCase):
    async def test_extension_cannot_end_before_future_visitor_start(self) -> None:
        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            get_visitor=AsyncMock(return_value={
                "id": 7,
                "name": "Future Guest",
                "unvr_visitor_id": "visitor-7",
                "start_time": "2999-01-01T10:00:00+00:00",
                "end_time": "2999-01-02T10:00:00+00:00",
                "status": 1,
            }),
            update_active_visitor_end_time=AsyncMock(return_value=True),
            log_admin_action=AsyncMock(),
        )
        access = SimpleNamespace(update_visitor=AsyncMock())
        response = await web_routes.extend_visitor(
            7,
            _request(db=db, access=access),
            user="admin",
            end_date="2998-01-01",
            end_time="10:00",
        )

        self.assertEqual(response.status_code, 303)
        self.assertIn("after+the+visitor+start", response.headers["location"])
        access.update_visitor.assert_not_awaited()
        db.update_active_visitor_end_time.assert_not_awaited()


class ManualLockActionSafetyTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _db_for(lock: dict) -> SimpleNamespace:
        return SimpleNamespace(
            get_lock=AsyncMock(return_value=lock),
            log_access=AsyncMock(),
        )

    async def test_lockdown_rejects_forged_manual_unlock(self) -> None:
        lock = {
            "id": 4,
            "type": "ha_external",
            "entity_id": "lock.back",
            "name": "Back Door",
            "buzz_enabled": 1,
        }
        db = self._db_for(lock)
        ha = SimpleNamespace(unlock=AsyncMock(return_value=True))
        request = _request(
            db=db,
            ha=ha,
            auth_engine=SimpleNamespace(tz=timezone.utc, lockdown=True),
        )

        response = await web_routes._lock_action(4, "unlock", "admin", request)

        self.assertEqual(response.status_code, 303)
        self.assertIn("Lockdown+mode+active", response.headers["location"])
        ha.unlock.assert_not_awaited()
        db.log_access.assert_awaited_once_with(
            method="manual_unlock",
            result="denied",
            lock_id=4,
            lock_name="Back Door",
            user_name="admin",
            reason="Lockdown mode active",
        )

    async def test_lockdown_rejects_forged_manual_buzz(self) -> None:
        lock = {
            "id": 5,
            "type": "ha_external",
            "entity_id": "lock.front",
            "name": "Front Door",
            "buzz_enabled": 1,
        }
        db = self._db_for(lock)
        ha = SimpleNamespace(unlock=AsyncMock(return_value=True))
        request = _request(
            db=db,
            ha=ha,
            auth_engine=SimpleNamespace(tz=timezone.utc, lockdown=True),
        )

        response = await web_routes._lock_action(5, "buzz", "admin", request)

        self.assertEqual(response.status_code, 303)
        self.assertIn("Lockdown+mode+active", response.headers["location"])
        ha.unlock.assert_not_awaited()
        db.log_access.assert_awaited_once_with(
            method="manual_buzz",
            result="denied",
            lock_id=5,
            lock_name="Front Door",
            user_name="admin",
            reason="Lockdown mode active",
        )

    async def test_forged_buzz_is_rejected_when_disabled_for_lock(self) -> None:
        lock = {
            "id": 6,
            "type": "ha_external",
            "entity_id": "lock.side",
            "name": "Side Door",
            "buzz_enabled": 0,
        }
        db = self._db_for(lock)
        ha = SimpleNamespace(unlock=AsyncMock(return_value=True))
        request = _request(db=db, ha=ha)

        response = await web_routes._lock_action(6, "buzz", "admin", request)

        self.assertEqual(response.status_code, 303)
        self.assertIn("Buzz+is+disabled", response.headers["location"])
        ha.unlock.assert_not_awaited()
        db.log_access.assert_awaited_once_with(
            method="manual_buzz",
            result="denied",
            lock_id=6,
            lock_name="Side Door",
            user_name="admin",
            reason="Buzz is disabled for this lock",
        )

    async def test_accepted_lock_is_not_success_until_ha_confirms_state(self) -> None:
        lock = {
            "id": 7,
            "type": "ha_external",
            "entity_id": "lock.patio",
            "name": "Patio Door",
            "buzz_enabled": 1,
        }
        db = self._db_for(lock)
        db.get_all_alarm_panels = AsyncMock(return_value=[])
        paused = {"entity_id": "lock.patio", "deadline": 1234.0}
        relock = SimpleNamespace(
            pause=AsyncMock(return_value=paused),
            resume=AsyncMock(),
            cancel=AsyncMock(),
        )
        ha = SimpleNamespace(
            lock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
        )
        request = _request(db=db, ha=ha, relock_manager=relock)

        with patch(
            "access_control.lock_actions.asyncio.sleep", new=AsyncMock()
        ):
            response = await web_routes._lock_action(7, "lock", "admin", request)

        self.assertEqual(response.status_code, 303)
        ha.get_entity_state.assert_has_awaits(
            [call("lock.patio")] * 3
        )
        relock.resume.assert_awaited_once_with(paused)
        relock.cancel.assert_not_awaited()
        self.assertNotIn("lock.patio", request.app.state.lock_states)
        db.log_access.assert_awaited_once_with(
            method="manual_lock",
            result="error",
            lock_id=7,
            lock_name="Patio Door",
            user_name="admin",
            reason="HA accepted lock command but entity was not confirmed locked",
        )


class HomeTemplateSafetyTests(unittest.TestCase):
    def test_lockdown_hides_enabled_buzz_control(self) -> None:
        template = web_routes.templates.env.get_template("home.html")
        context = {
            "user": "admin",
            "page": "home",
            "ingress_active": False,
            "ingress_path": "",
            "csrf_token": "csrf",
            "locks": [{
                "id": 7,
                "name": "Garage",
                "door_name": "Garage entry",
                "buzz_enabled": 1,
            }],
            "alarm_panels": [],
            "log_entries": [],
            "ws_last_event": {},
            "unvr_connected": True,
            "protect_connected": True,
            "ha_connected": True,
            "ws_connected": True,
        }

        unlocked_html = template.render(**context, lockdown=False)
        lockdown_html = template.render(**context, lockdown=True)

        self.assertIn('action="locks/7/buzz"', unlocked_html)
        self.assertNotIn('action="locks/7/buzz"', lockdown_html)
        self.assertIn("Lockdown Active", lockdown_html)


class LocksTemplateRelockBadgeTests(unittest.TestCase):
    """Change 3(c): the locks page shows a neutral "re-lock pending" chip and a
    danger "re-lock overdue" badge only on affected cards."""

    def _render(self, locks):
        template = web_routes.templates.env.get_template("locks.html")
        return template.render(
            request=SimpleNamespace(scope={}),
            user="admin",
            page="locks",
            ingress_active=False,
            ingress_path="",
            csrf_token="csrf",
            lockdown=False,
            locks=locks,
            ha_locks=[],
            access_locations=[],
            protect_doorbells=[],
            protect_cameras=[],
            unvr_connected=True,
            protect_connected=True,
            ha_connected=True,
            ws_connected=True,
        )

    @staticmethod
    def _lock(**over):
        base = {
            "id": 1, "name": "Door", "type": "ha_external",
            "entity_id": "lock.x", "state": "unlocked",
            "buzz_enabled": 0, "relock_duration": 30, "hidden": 0,
            "entry_devices": [],
        }
        base.update(over)
        return base

    def test_badges_render_only_on_affected_cards(self) -> None:
        overdue = self._lock(
            id=1, name="Overdue", entity_id="lock.a",
            relock_pending=True, relock_overdue=True,
        )
        pending = self._lock(
            id=2, name="Pending", entity_id="lock.b",
            relock_pending=True, relock_overdue=False,
        )
        clean = self._lock(id=3, name="Clean", entity_id="lock.c")

        html = self._render([overdue, pending, clean])

        self.assertIn('<span class="badge-denied">re-lock overdue</span>', html)
        self.assertIn('<span class="chip">re-lock pending</span>', html)
        # One card each; the clean lock shows neither.
        self.assertEqual(html.count("re-lock overdue"), 1)
        self.assertEqual(html.count("re-lock pending"), 1)

    def test_no_badge_when_no_pending_relock(self) -> None:
        html = self._render([self._lock()])
        self.assertNotIn("re-lock pending", html)
        self.assertNotIn("re-lock overdue", html)


class AssetCacheBustingTests(unittest.TestCase):
    def test_static_asset_links_carry_content_hash(self) -> None:
        # Without a version query, browsers may satisfy static/app.css from
        # cache after an add-on update and render new templates against a
        # stale (or cached-error) stylesheet.
        html = web_routes.templates.env.get_template("home.html").render(
            user="admin",
            page="home",
            ingress_active=False,
            ingress_path="",
            csrf_token="csrf",
            lockdown=False,
            locks=[],
            alarm_panels=[],
            log_entries=[],
            ws_last_event={},
            unvr_connected=True,
            protect_connected=True,
            ha_connected=True,
            ws_connected=True,
        )
        css_v = web_routes.ASSET_VERSIONS["app.css"]
        js_v = web_routes.ASSET_VERSIONS["app.js"]
        self.assertRegex(css_v, r"^[0-9a-f]{12}$")
        self.assertRegex(js_v, r"^[0-9a-f]{12}$")
        self.assertIn(f'href="static/app.css?v={css_v}"', html)
        self.assertIn(f'src="static/app.js?v={js_v}"', html)


class RenderAndValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_background_poll_does_not_refresh_session_cookie(self) -> None:
        request = _request(headers={"X-Background-Poll": "true"})
        response = HTMLResponse("ok")
        with patch.object(
            web_routes, "get_session_user", return_value="admin"
        ), patch.object(
            web_routes, "generate_csrf_token", return_value="csrf"
        ), patch.object(
            web_routes.templates, "TemplateResponse", return_value=response
        ), patch.object(
            web_routes, "refresh_session_cookie"
        ) as refresh:
            rendered = await web_routes._render(
                "home.html", request, {"request": request}
            )

        self.assertIs(rendered, response)
        refresh.assert_not_called()
        self.assertNotIn("set-cookie", rendered.headers)

    async def test_unknown_api_key_scope_is_rejected_before_persistence(self) -> None:
        db = SimpleNamespace(add_api_key=AsyncMock())
        request = _request(db=db)
        error_response = HTMLResponse("invalid", status_code=422)
        with patch.object(
            web_routes,
            "_enforce_action_rate_limit",
            new=AsyncMock(return_value=None),
        ), patch.object(
            web_routes,
            "_settings_with_result",
            new=AsyncMock(return_value=error_response),
        ) as render_error, patch.object(
            web_routes, "generate_api_key"
        ) as generate:
            response = await web_routes.create_api_key(
                request,
                name="Integration",
                scope="superuser",
                user="admin",
            )

        self.assertIs(response, error_response)
        render_error.assert_awaited_once()
        generate.assert_not_called()
        db.add_api_key.assert_not_awaited()


class LogoutHardeningTests(unittest.TestCase):
    """GET /logout used to clear the session cookie with no CSRF check, so a
    third-party page could force-logout a signed-in admin with a bare
    ``<img src="/logout">``. Logout is now POST, guarded by require_csrf
    like every other state-changing route, and the GET route is removed
    outright (405) rather than kept as a silent no-op. Hardening review
    2026-07-12.
    """

    @staticmethod
    def _client() -> TestClient:
        web_auth.SECRET_KEY = "test-secret"
        app = FastAPI()
        app.include_router(web_routes.router)
        # require_csrf itself Depends(require_login); overriding require_login
        # simulates an authenticated "admin" session without needing a real
        # signed cookie, while leaving the real require_csrf CSRF check in
        # place so these tests exercise the actual dependency the route uses.
        app.dependency_overrides[web_routes.require_login] = lambda: "admin"
        return TestClient(app)

    def test_post_logout_with_valid_csrf_clears_session(self) -> None:
        client = self._client()  # sets web_auth.SECRET_KEY as a side effect
        token = web_routes.generate_csrf_token("admin")
        with client:
            response = client.post(
                "/logout",
                data={"_csrf_token": token},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")
        set_cookie = response.headers.get("set-cookie", "")
        self.assertIn("session=", set_cookie)
        self.assertIn("Max-Age=0", set_cookie)

    def test_post_logout_without_csrf_is_rejected(self) -> None:
        with self._client() as client:
            response = client.post("/logout", data={}, follow_redirects=False)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("set-cookie", response.headers)

    def test_get_logout_no_longer_clears_session_cookie(self) -> None:
        with self._client() as client:
            response = client.get("/logout", follow_redirects=False)

        self.assertEqual(response.status_code, 405)
        self.assertNotIn("set-cookie", response.headers)


if __name__ == "__main__":
    unittest.main()
