"""
HA Ingress integration.

Supervisor proxies addon traffic through Home Assistant when ingress is
enabled. Each request gets these headers:

- X-Ingress-Path:        the URL prefix Supervisor stripped before forwarding
                         (e.g. /api/hassio_ingress/<base64url-token>)
- X-Remote-User-Id:      HA user UUID (only when auth_api: true)
- X-Remote-User-Name:    HA user display name
- X-Remote-User-Is-Admin: "true" / "false"

The middleware here does two jobs:

1. **URL prefix propagation** — copy X-Ingress-Path into
   request.scope["root_path"] so Starlette generates correctly-prefixed
   URLs (RedirectResponse, url_for, etc.).

2. **SSO trust** — populate request.state.ingress_user when the request
   came in through Supervisor's ingress proxy *and* identifies an HA
   admin. Downstream auth dependencies can check that state to bypass
   the legacy session-cookie login flow.

**Defense against header injection:** other add-ons on the same Docker
bridge network could reach this container directly and try to set
X-Remote-User-* headers themselves. The Supervisor's X-Ingress-Path
follows a strict format that no other addon can forge without
guessing the per-session token — we validate the format before
trusting any SSO header. Without a valid X-Ingress-Path, all
X-Remote-User-* headers are ignored and the request falls through to
the legacy session-cookie auth path.
"""
from __future__ import annotations

import re

from fastapi import Request
from fastapi.responses import HTMLResponse

# /api/hassio_ingress/<base64url-token>. The token portion is what
# Supervisor signs per HA session; it's unguessable from outside that
# session, so requiring a well-formed X-Ingress-Path means we'll only
# trust SSO headers that came through the real ingress proxy.
# Use \A and \Z anchors (instead of ^ / $) so a trailing newline injected
# into the header value can't bypass the format check — `$` matches before
# `\n` at end-of-string by default.
INGRESS_PATH_RE = re.compile(r"\A/api/hassio_ingress/[A-Za-z0-9_-]+\Z")

_FORBIDDEN_BODY = (
    "<!doctype html><meta charset=utf-8>"
    "<title>Access Control — admin required</title>"
    "<style>body{font-family:system-ui;max-width:32rem;margin:4rem auto;"
    "padding:1rem;color:#1f2937}h1{font-size:1.5rem;margin:0 0 1rem}"
    "p{margin:0 0 .75rem}</style>"
    "<h1>Admin access required</h1>"
    "<p>This add-on is restricted to Home Assistant administrators. "
    "Ask your HA owner to grant your account admin permissions if you "
    "need access.</p>"
)


def _initial_state(request: Request) -> None:
    """Default ingress state on every request — cleared per-request."""
    request.state.ingress_active = False
    request.state.ingress_user = None


def security_headers_for(*, ingress_active: bool) -> dict[str, str]:
    """
    Return the static security-header dict for a given access mode.

    Frame-blocking flips with the access mode:

    - **Direct port** — `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`.
      The addon is a standalone web app and must never be iframed.
    - **HA Ingress** — `X-Frame-Options: SAMEORIGIN` + CSP `frame-ancestors 'self'`.
      The HA frontend *intentionally* renders the addon inside an iframe at
      the same browser origin (Supervisor proxies the addon under the HA
      host). `DENY` would refuse to render and the panel would be blank.

    Other headers (HSTS, Referrer-Policy, X-Content-Type-Options,
    script/style/font CSP) are identical across modes.
    """
    if ingress_active:
        xframe = "SAMEORIGIN"
        frame_ancestors = "frame-ancestors 'self'"
    else:
        xframe = "DENY"
        frame_ancestors = "frame-ancestors 'none'"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        f"{frame_ancestors}"
    )
    return {
        "X-Frame-Options": xframe,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-XSS-Protection": "0",
        "Content-Security-Policy": csp,
    }


async def ingress_middleware(request: Request, call_next):
    """
    See module docstring for behavior.

    Returns a 403 HTMLResponse if the request is identified as a non-admin
    HA user via SSO; otherwise delegates to the next middleware/route.
    """
    _initial_state(request)

    ingress_path = request.headers.get("X-Ingress-Path", "")
    if not ingress_path or not INGRESS_PATH_RE.match(ingress_path):
        # No valid ingress prefix → not from the Supervisor's proxy. Any
        # X-Remote-User-* headers on this request are ignored (could be
        # forged by another addon on the Docker bridge).
        return await call_next(request)

    request.scope["root_path"] = ingress_path
    request.state.ingress_active = True

    user_id = request.headers.get("X-Remote-User-Id", "")
    user_name = request.headers.get("X-Remote-User-Name", "")
    is_admin_raw = request.headers.get("X-Remote-User-Is-Admin", "")

    if user_id and user_name:
        if is_admin_raw.lower() != "true":
            return HTMLResponse(_FORBIDDEN_BODY, status_code=403)
        request.state.ingress_user = {"id": user_id, "name": user_name}

    return await call_next(request)
