"""Tests for Supervisor and direct-host restart transports."""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from access_control import service_restart, web_routes


class _Response:
    def __init__(self, status: int, text: str = "") -> None:
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def text(self) -> str:
        return self._text


class _Session:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def post(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class ServiceRestartTests(unittest.IsolatedAsyncioTestCase):
    async def test_supervisor_restart_uses_bearer_token(self) -> None:
        session = _Session(_Response(200))
        env = {
            "SUPERVISOR_TOKEN": "supervisor-secret",
            "SUPERVISOR_RESTART_URL": "http://supervisor/addons/self/restart",
        }
        with patch.dict("os.environ", env, clear=True), patch.object(
            service_restart.aiohttp, "ClientSession", return_value=session
        ):
            await service_restart.request_service_restart()

        self.assertEqual(len(session.calls), 1)
        url, kwargs = session.calls[0]
        self.assertEqual(url, env["SUPERVISOR_RESTART_URL"])
        self.assertEqual(
            kwargs["headers"],
            {"Authorization": "Bearer supervisor-secret"},
        )

    async def test_supervisor_failure_is_not_reported_as_success(self) -> None:
        session = _Session(_Response(503, "restarting unavailable"))
        with patch.dict(
            "os.environ", {"SUPERVISOR_TOKEN": "token"}, clear=True
        ), patch.object(
            service_restart.aiohttp, "ClientSession", return_value=session
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
                await service_restart.request_service_restart()

    async def test_direct_host_fallback_uses_argv_without_shell(self) -> None:
        process = SimpleNamespace(wait=AsyncMock(return_value=0))
        create = AsyncMock(return_value=process)
        with patch.dict(
            "os.environ", {"RESTART_COMMAND": "/usr/bin/env true"}, clear=True
        ), patch.object(asyncio, "create_subprocess_exec", create):
            await service_restart.request_service_restart()

        create.assert_awaited_once_with(
            "/usr/bin/env",
            "true",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        process.wait.assert_awaited_once_with()

    async def test_restart_without_transport_fails_loudly(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Restart is unavailable"):
                await service_restart.request_service_restart()

    async def test_web_restart_tracks_failure_and_exposes_operator_message(self) -> None:
        tasks: list[asyncio.Task] = []
        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            log_admin_action=AsyncMock(),
        )
        state = SimpleNamespace(
            db=db,
            restart_request_error=None,
            track_background_task=tasks.append,
        )
        request = SimpleNamespace(
            app=SimpleNamespace(state=state),
            scope={},
            client=SimpleNamespace(host="127.0.0.1"),
        )

        with patch.dict(
            "os.environ", {"SUPERVISOR_TOKEN": "token"}, clear=True
        ), patch.object(
            web_routes,
            "request_service_restart",
            new=AsyncMock(side_effect=RuntimeError("supervisor unavailable")),
        ):
            response = await web_routes.restart_service(request, user="admin")
            self.assertEqual(response.status_code, 303)
            self.assertEqual(len(tasks), 1)
            await asyncio.gather(*tasks)

        db.log_admin_action.assert_awaited_once_with(
            "admin", "service_restart"
        )
        self.assertIn("restart request failed", state.restart_request_error)


if __name__ == "__main__":
    unittest.main()
