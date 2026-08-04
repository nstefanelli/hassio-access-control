"""Dashboard session authentication using itsdangerous signed cookies."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

# Set at application startup
SECRET_KEY: str | None = None

SESSION_MAX_AGE = 14400  # 4 hours inactivity timeout


def get_serializer() -> URLSafeTimedSerializer:
    """Return a URLSafeTimedSerializer configured with the module-level SECRET_KEY."""
    return URLSafeTimedSerializer(SECRET_KEY)


def create_session_cookie(username: str) -> str:
    """Create a signed session cookie value for the given username."""
    s = get_serializer()
    return s.dumps({"user": username})


def get_session_user(request: Request) -> str | None:
    """
    Read the 'session' cookie from the request and return the username, or None.

    Returns None if the cookie is missing, expired, or tampered with.
    """
    cookies = getattr(request, "cookies", None)
    token = cookies.get("session") if cookies else None
    if not token:
        return None
    try:
        s = get_serializer()
        data = s.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("user")
    except BadSignature:
        return None
    except Exception:
        return None


def _cookie_path(request: Request) -> str:
    """
    Cookie Path scope.

    When accessed via HA Ingress, the URL prefix is per-session (e.g.
    /api/hassio_ingress/<token>/) and the browser sees the HA host's
    domain. Setting Path=/ on the cookie would leak it to every other
    page on the HA host — including other add-ons. We scope it to the
    ingress prefix so the cookie is only sent on requests to this addon.

    Outside of ingress (direct-port deployments, local docker tests),
    fall back to Path=/ which is the standard default.
    """
    return request.scope.get("root_path") or "/"


def resolve_effective_user(request: Request) -> str | None:
    """
    Resolve the authenticated identity, or None if unauthenticated.

    Order of precedence (shared by require_login, the CSRF middleware in
    main.py, and web_routes._render — anything that mints or validates a
    CSRF token MUST resolve identity in this exact order, otherwise a
    client presenting both an ingress SSO identity and a stale session
    cookie gets tokens generated for one identity but validated against
    the other, and every POST 403s):

    1. HA Ingress SSO — if ingress_middleware identified an HA admin via
       the X-Remote-User-* headers, trust that and skip cookie auth
       entirely. Use the HA display name as the in-app username so
       admin_log entries are attributable; callers can reach ingress_user
       via request.state if they need the HA user id.
    2. Signed session cookie — the legacy path for direct-port deployments.
    """
    ingress_user = getattr(request.state, "ingress_user", None)
    if ingress_user:
        return f"ha:{ingress_user['name']}"
    return get_session_user(request)


def require_login(request: Request) -> str:
    """
    Return the logged-in username, or raise an HTTPException (303 redirect to /login).

    Identity precedence lives in resolve_effective_user (ingress SSO first,
    then the signed session cookie).

    For HTMX requests with no auth, return HX-Redirect header so the browser
    performs a full navigation instead of injecting the login page into the DOM.
    """
    user = resolve_effective_user(request)
    if not user:
        root = request.scope.get("root_path", "")
        if request.headers.get("HX-Request") == "true":
            raise HTTPException(
                status_code=200,
                detail="Login required",
                headers={"HX-Redirect": f"{root}/login"},
            )
        raise HTTPException(
            status_code=303,
            detail="Login required",
            headers={"Location": f"{root}/login"},
        )
    return user


# --- CSRF Protection ---

def generate_csrf_token(session_user: str) -> str:
    """Generate a signed CSRF token tied to the session user."""
    s = get_serializer()
    return s.dumps({"csrf": session_user})


def validate_csrf_token(token: str, session_user: str) -> bool:
    """Validate a CSRF token. Returns True if valid, False otherwise."""
    s = get_serializer()
    try:
        data = s.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("csrf") == session_user
    except Exception:
        return False


async def require_csrf(request: Request, user: str = Depends(require_login)) -> str:
    """
    Validate CSRF token from form data; raise 403 if missing or invalid.

    Note: CSRF protection still applies under HA Ingress SSO. The X-Remote-
    User-* headers establish identity, but a cross-site form submission
    (e.g. from a malicious page in another tab on the same browser) could
    still ride on the user's HA session cookies. CSRF tokens defend against
    that independently.
    """
    form_data = await request.form()
    token = form_data.get("_csrf_token", "")
    if not token or not validate_csrf_token(str(token), user):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return user


def _cookie_secure(request: Request) -> bool:
    """
    Whether the session cookie should carry the Secure attribute.

    Browsers silently discard Secure cookies set over plain HTTP, so
    hardcoding secure=True turned the documented direct-port http://
    deployment into an infinite login loop. Derive it instead:

    - Ingress: the browser-facing hop is the HA frontend (HTTPS in any
      sane deployment) even though the Supervisor proxies to us over
      plain HTTP internally — keep Secure.
    - Otherwise trust X-Forwarded-Proto (reverse-proxy TLS termination),
      falling back to the request scheme itself.
    """
    if getattr(request.state, "ingress_active", False):
        return True
    headers = getattr(request, "headers", None) or {}
    forwarded_proto = headers.get("x-forwarded-proto") or headers.get(
        "X-Forwarded-Proto"
    )
    if forwarded_proto:
        return forwarded_proto.split(",")[0].strip().lower() == "https"
    return getattr(getattr(request, "url", None), "scheme", "") == "https"


def set_session_cookie(response, request: Request, username: str) -> None:
    """
    Set the signed session cookie, scoped to the ingress prefix when active.
    Shared by the /login POST handler and the per-render session refresh.
    """
    cookie_value = create_session_cookie(username)
    response.set_cookie(
        "session",
        cookie_value,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        max_age=SESSION_MAX_AGE,
        path=_cookie_path(request),
    )


def refresh_session_cookie(response, request: Request, username: str) -> None:
    """Re-sign and re-set the session cookie for sliding window timeout."""
    set_session_cookie(response, request, username)


def clear_session_cookie(response, request: Request) -> None:
    """Delete the session cookie at the correct path scope."""
    response.delete_cookie("session", path=_cookie_path(request))
