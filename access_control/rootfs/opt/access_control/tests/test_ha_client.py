"""Unit tests for HAClient credential resolution (env-first token).

Regression for 2026-07-05: the Supervisor token is rotated periodically and
re-exported as ACCESS_CONTROL_HA_TOKEN. HAClient captured it at construction,
so after a rotation every lock/unlock 401'd until an add-on restart. _headers()
must resolve the token env-first on every call.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path

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


_load_package()
HAClient = importlib.import_module("access_control.ha_client").HAClient

_ENV = "ACCESS_CONTROL_HA_TOKEN"


class TestHAClientTokenResolution(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.pop(_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(_ENV, None)
        if self._saved is not None:
            os.environ[_ENV] = self._saved

    def test_uses_db_token_when_env_unset(self) -> None:
        """Non-Supervisor deployment: fall back to the construction token."""
        client = HAClient("http://supervisor/core", "db-token")
        self.assertEqual(client._headers()["Authorization"], "Bearer db-token")

    def test_env_token_shadows_construction_token(self) -> None:
        client = HAClient("http://supervisor/core", "stale-db-token")
        os.environ[_ENV] = "fresh-supervisor-token"
        self.assertEqual(
            client._headers()["Authorization"], "Bearer fresh-supervisor-token"
        )

    def test_rotation_picked_up_without_reconstruction(self) -> None:
        """The whole point: a rotated env token wins on the very next call."""
        client = HAClient("http://supervisor/core", "ignored")
        os.environ[_ENV] = "token-v1"
        self.assertEqual(client._headers()["Authorization"], "Bearer token-v1")
        os.environ[_ENV] = "token-v2"  # Supervisor rotated it mid-run
        self.assertEqual(client._headers()["Authorization"], "Bearer token-v2")


if __name__ == "__main__":
    unittest.main()
