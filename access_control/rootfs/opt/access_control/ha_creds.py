"""HA-credentials resolution helper.

Extracted from main.py so the env-vs-DB precedence logic is testable
without dragging FastAPI (and the rest of main.py's import surface)
into the test process. The helper has no framework dependencies — it
takes plain strings and a `decrypt` callable, returns plain strings.

See `_resolve_ha_creds` docstring for the precedence rules.
"""
from __future__ import annotations

import logging
from typing import Callable

_log = logging.getLogger(__name__)


def resolve_ha_creds(
    env_url: str | None,
    env_token: str | None,
    db_url: str | None,
    db_token_enc: str | None,
    *,
    decrypt: Callable[[str], str],
    log: logging.Logger = _log,
) -> tuple[str, str, str]:
    """Resolve HA URL + token from env vars (preferred) or DB (fallback).

    Returns ``(url, token, source_label)``. Raises :class:`RuntimeError`
    if neither source yields a complete pair.

    Env vars and DB are two *complete* sources; mixing them (env URL +
    DB token, or vice versa) produces a silent zombie config — the
    Supervisor proxy URL only accepts SUPERVISOR_TOKEN, so a stale env
    URL paired with a DB long-lived token 401s every HA call.

    Either both env vars are set (Supervisor-proxy path, default for
    addon deployments) or neither is (direct-port path, DB is the
    source of truth). A *partial* env injection is a misconfig — we
    log it at ERROR and fall back to DB so the operator can at least
    see the addon boot, then trigger ``decrypt`` for the DB token only.

    ``decrypt`` is a callable that decrypts the DB-stored token (e.g.
    ``functools.partial(decrypt_value, key=enc_key)``). Passed in so
    tests can stub it without setting up real Fernet keys.
    """
    if env_url and env_token:
        return env_url, env_token, "env"
    if env_url or env_token:
        log.error(
            "Partial HA env-var injection: ACCESS_CONTROL_HA_URL set=%s "
            "ACCESS_CONTROL_HA_TOKEN set=%s. Both must be set or neither. "
            "Refusing to cross-source env+DB; falling back to DB-stored "
            "creds. Fix run.sh / Supervisor env injection.",
            bool(env_url),
            bool(env_token),
        )
        token = decrypt(db_token_enc) if db_token_enc else None
        if db_url and token:
            return db_url, token, "db (env partial — see error above)"
        raise RuntimeError(
            "HA credentials are incomplete after env-partial fallback: "
            f"DB ha_url={bool(db_url)}, ha_token={bool(token)}. "
            "Re-run setup or fix the Supervisor env injection."
        )
    if db_url and db_token_enc:
        return db_url, decrypt(db_token_enc), "db"
    raise RuntimeError(
        "HA credentials are incomplete: neither env vars "
        "(ACCESS_CONTROL_HA_URL/_TOKEN) nor DB-stored "
        "ha_url/ha_token were available."
    )
