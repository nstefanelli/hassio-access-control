"""Secret-key source selection and mismatch regressions."""
from __future__ import annotations

import hashlib
import importlib.util
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

from access_control.config import (
    SECRET_KEY_SOURCE_DATABASE,
    SECRET_KEY_SOURCE_ENVIRONMENT,
    resolve_secret_key,
    secret_key_fingerprint,
)


class ResolveSecretKeyTests(unittest.TestCase):
    def test_legacy_database_without_source_marker_uses_stored_key(self) -> None:
        resolved = resolve_secret_key(
            stored_key="database-key",
            source=None,
            stored_fingerprint=None,
            environment_key="later-environment-key",
        )
        self.assertEqual(resolved, ("database-key", SECRET_KEY_SOURCE_DATABASE))

    def test_environment_mode_accepts_matching_key(self) -> None:
        key = "external-backup-key"
        fingerprint = secret_key_fingerprint(key)
        resolved = resolve_secret_key(
            stored_key=None,
            source=SECRET_KEY_SOURCE_ENVIRONMENT,
            stored_fingerprint=fingerprint,
            environment_key=key,
        )
        self.assertEqual(resolved, (key, SECRET_KEY_SOURCE_ENVIRONMENT))
        self.assertTrue(fingerprint.startswith("pbkdf2_sha256$480000$"))
        self.assertNotEqual(fingerprint, hashlib.sha256(key.encode()).hexdigest())

    def test_environment_mode_accepts_legacy_fingerprint_for_migration(
        self,
    ) -> None:
        key = "legacy-external-key"
        resolved = resolve_secret_key(
            stored_key=None,
            source=SECRET_KEY_SOURCE_ENVIRONMENT,
            stored_fingerprint=hashlib.sha256(key.encode()).hexdigest(),
            environment_key=key,
        )
        self.assertEqual(resolved, (key, SECRET_KEY_SOURCE_ENVIRONMENT))

    def test_environment_mode_rejects_missing_key(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "required"):
            resolve_secret_key(
                stored_key=None,
                source=SECRET_KEY_SOURCE_ENVIRONMENT,
                stored_fingerprint=secret_key_fingerprint("expected"),
                environment_key=None,
            )

    def test_environment_mode_rejects_mismatched_key(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            resolve_secret_key(
                stored_key=None,
                source=SECRET_KEY_SOURCE_ENVIRONMENT,
                stored_fingerprint=secret_key_fingerprint("expected"),
                environment_key="wrong",
            )

    def test_unknown_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Unsupported"):
            resolve_secret_key(
                stored_key="key",
                source="surprise",
                stored_fingerprint=None,
                environment_key=None,
            )


if __name__ == "__main__":
    unittest.main()
