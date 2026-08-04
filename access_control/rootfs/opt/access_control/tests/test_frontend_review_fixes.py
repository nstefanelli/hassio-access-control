"""Regressions for the frontend review findings (FE-1, FE-3, FE-6, FE-7, FE-8).

FE-1 gets a real server-side render: HTML-attribute entity decoding runs
BEFORE the JS engine compiles inline handlers, so a Jinja-escaped value
interpolated into an onsubmit string is still live JS. The safe pattern is a
static handler reading data-* attributes via this.dataset.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import jinja2

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

XSS_NAME = "'+alert(document.cookie)+'"


def _render_group_detail(group_name: str) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("group_detail.html")
    return template.render(
        page="groups",
        user="admin",
        ingress_active=False,
        ingress_path="",
        csrf_token="test-token",
        asset_v={"app.css": "v", "app.js": "v"},
        error=None,
        group={
            "id": 1,
            "name": group_name,
            "description": "",
            "all_locks": 1,
            "can_disarm": 0,
            "blocked_when_armed_away": 0,
            "blocked_when_armed_home": 0,
            "schedule_enabled": 0,
            "schedule_days": "",
            "schedule_start": "",
            "schedule_end": "",
        },
        members=[{"id": 5, "name": "Apostrophe O'Member", "email": ""}],
        available_users=[],
        all_locks=[],
        group_lock_ids=set(),
    )


class RemoveMemberConfirmXssTests(unittest.TestCase):
    """FE-1: group name must never be interpolated into inline JS."""

    def test_confirm_uses_static_dataset_pattern(self) -> None:
        rendered = _render_group_detail(XSS_NAME)

        # The handler must be a fixed string that only reads data-* values.
        self.assertIn(
            "onsubmit=\"return confirm('Remove ' + this.dataset.name"
            " + ' from ' + this.dataset.groupName + '?')\"",
            rendered,
        )
        # The group name travels via an escaped attribute, not via JS source.
        self.assertIn(
            'data-group-name="&#39;+alert(document.cookie)+&#39;"', rendered
        )
        # No raw payload anywhere: autoescape/|e kept every quote entity-encoded.
        self.assertNotIn(XSS_NAME, rendered)

    def test_confirm_handler_is_identical_for_any_group_name(self) -> None:
        # The old template baked the group name into the handler, so two
        # groups produced two different inline scripts. The fixed handler is
        # byte-identical regardless of the name.
        def handler(rendered: str) -> str:
            start = rendered.index("remove-member")
            start = rendered.index("onsubmit=", start)
            return rendered[start : rendered.index(")\"", start) + 2]

        self.assertEqual(
            handler(_render_group_detail("Family")),
            handler(_render_group_detail(XSS_NAME)),
        )


class DoubleSubmitGuardTests(unittest.TestCase):
    """FE-3: the guard must target event.submitter and defer the disable."""

    def setUp(self) -> None:
        source = (STATIC_DIR / "app.js").read_text()
        start = source.index('document.addEventListener("submit"')
        self.guard = source[start : source.index("});", start) + 3]

    def test_guard_prefers_event_submitter(self) -> None:
        self.assertIn("event.submitter", self.guard)
        # querySelector remains only as the fallback for submits not
        # triggered by a button (e.g. Enter in a single-field form).
        self.assertLess(
            self.guard.index("event.submitter"),
            self.guard.index("querySelector"),
        )

    def test_disable_is_deferred_so_submitter_value_posts(self) -> None:
        # A synchronous disable during the submit event can drop the clicked
        # button's name/value (e.g. the settings "clear" flag) from the POST.
        self.assertIn("setTimeout", self.guard)
        self.assertLess(
            self.guard.index("setTimeout"),
            self.guard.index("button.disabled = true"),
        )


class BackgroundRefreshSwapTests(unittest.TestCase):
    """FE-6: skip no-op swaps and swaps that would steal focus."""

    def setUp(self) -> None:
        self.source = (STATIC_DIR / "app.js").read_text()
        start = self.source.index("async function refresh()")
        self.refresh = self.source[start : self.source.index("\n  }", start)]

    def test_swap_skipped_when_markup_unchanged_or_focused(self) -> None:
        self.assertIn("document.activeElement", self.refresh)
        self.assertIn("markupWithoutCsrf(currentTarget)", self.refresh)
        self.assertIn("nextTarget.outerHTML", self.refresh)

    def test_comparison_ignores_client_injected_csrf_inputs(self) -> None:
        # injectCsrf() adds hidden _csrf_token inputs the fetched document
        # never has; comparing without stripping them would defeat the skip.
        start = self.source.index("function markupWithoutCsrf")
        helper = self.source[start : self.source.index("\n  }", start)]
        self.assertIn('input[name="_csrf_token"]', helper)
        self.assertIn("cloneNode(true)", helper)

    def test_csrf_meta_rotates_before_any_skip_decision(self) -> None:
        self.assertLess(
            self.refresh.index("updateCsrfToken(nextDocument)"),
            self.refresh.index("markupWithoutCsrf"),
        )
        # The re-injection into a swapped subtree still happens.
        self.assertIn("injectCsrf(nextTarget)", self.refresh)


class RestartBannerSlowPathTests(unittest.TestCase):
    """FE-7: the reload poller must never give up permanently."""

    def setUp(self) -> None:
        source = (TEMPLATES_DIR / "settings.html").read_text()
        start = source.index("function tryReload()")
        self.script = source[start : source.index("})();", start)]

    def test_poller_falls_back_to_slow_interval_instead_of_stopping(self) -> None:
        # No hard attempt cap guarding the retry: after the fast attempts the
        # poller keeps going at a slower cadence.
        self.assertNotIn("attempts < 30", self.script)
        self.assertIn("FAST_ATTEMPTS", self.script)
        self.assertIn("5000", self.script)

    def test_banner_reports_slow_restart_with_manual_hint(self) -> None:
        self.assertIn("restart-banner", self.script)
        self.assertIn("longer than usual", self.script)
        self.assertIn("manually", self.script)


class DeadToggleKeyRemovalTests(unittest.TestCase):
    """FE-8: the unreferenced key-reveal helper stays deleted."""

    def test_no_template_or_script_references_toggle_key(self) -> None:
        for path in [*TEMPLATES_DIR.glob("*.html"), STATIC_DIR / "app.js"]:
            source = path.read_text()
            for needle in ("toggleKey", "data-full-key", "dataset.fullKey"):
                self.assertNotIn(needle, source, f"{needle} found in {path.name}")


if __name__ == "__main__":
    unittest.main()
