"""Secret-key source selection and mismatch regressions."""
from __future__ import annotations

import unittest

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
        resolved = resolve_secret_key(
            stored_key=None,
            source=SECRET_KEY_SOURCE_ENVIRONMENT,
            stored_fingerprint=secret_key_fingerprint(key),
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
