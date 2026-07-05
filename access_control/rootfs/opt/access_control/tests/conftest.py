"""Pytest bootstrap — prefer the REAL dependencies over the in-test stubs.

Several unit-test modules inject MagicMock stand-ins for fastapi / aiohttp /
aiosqlite / cryptography / itsdangerous into ``sys.modules`` so pure-logic
tests can run on a bare Python with no dependencies installed. Those guards
key on "module not already imported" (`name not in sys.modules`). At full-suite
collection that means whichever stub-injecting module is imported first would
shadow the REAL packages process-wide — silently running the entire suite
against fakes and forcing the end-to-end ``TestClient`` tests to skip.

Importing the real packages here — conftest is loaded before any test module —
makes those guards no-op whenever the dependency is actually installed (the
documented ``--with-requirements`` invocation). When a dependency is genuinely
absent, ``find_spec`` returns ``None`` and the per-module stub fallback still
applies, so the bare-Python path keeps working.
"""
import importlib
import importlib.util

_REAL_DEPS = (
    "fastapi",
    "fastapi.testclient",
    "starlette",
    "aiohttp",
    "aiosqlite",
    "cryptography",
    "itsdangerous",
    "httpx",
)

for _name in _REAL_DEPS:
    try:
        if importlib.util.find_spec(_name) is not None:
            importlib.import_module(_name)
    except Exception:
        # A partially-installed dep shouldn't break collection; the per-module
        # stub fallback will handle it.
        pass
