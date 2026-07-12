"""Portable service-restart request used by UI and scheduler."""
from __future__ import annotations

import asyncio
import logging
import os
import shlex

import aiohttp

_LOGGER = logging.getLogger(__name__)
_SUPERVISOR_RESTART_URL = "http://supervisor/addons/self/restart"


async def request_service_restart(*, delay: float = 0.0) -> None:
    """Ask Supervisor to restart this add-on, with a direct-host fallback.

    Home Assistant add-ons cannot restart themselves with systemd. When a
    Supervisor token is present we use the documented add-on restart endpoint.
    ``RESTART_COMMAND`` remains an explicit opt-in fallback for local/VM
    deployments; there is intentionally no pretend-success command.
    """
    if delay > 0:
        await asyncio.sleep(delay)

    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
    if supervisor_token:
        url = os.environ.get("SUPERVISOR_RESTART_URL", _SUPERVISOR_RESTART_URL)
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                headers={"Authorization": f"Bearer {supervisor_token}"},
            ) as response:
                if 200 <= response.status < 300:
                    _LOGGER.warning("Supervisor accepted add-on restart request")
                    return
                await response.text()
                _LOGGER.error(
                    "Supervisor restart request failed with HTTP %d",
                    response.status,
                )
                raise RuntimeError(
                    f"Supervisor restart request failed: HTTP {response.status}"
                )

    restart_command = os.environ.get("RESTART_COMMAND")
    if not restart_command:
        raise RuntimeError(
            "Restart is unavailable: no SUPERVISOR_TOKEN or RESTART_COMMAND"
        )
    parts = shlex.split(restart_command)
    if not parts:
        raise RuntimeError("RESTART_COMMAND is empty")
    process = await asyncio.create_subprocess_exec(
        *parts,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return_code = await process.wait()
    if return_code != 0:
        raise RuntimeError(f"RESTART_COMMAND exited with status {return_code}")
