"""Dashboard session authentication using itsdangerous signed cookies."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
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
    token = request.cookies.get("session")
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


def require_login(request: Request) -> str:
    """
    Return the logged-in username, or raise an HTTPException (303 redirect to /login).

    For HTMX requests, returns HX-Redirect header so the browser performs a full
    navigation instead of injecting the login page into the DOM.
    """
    user = get_session_user(request)
    if not user:
        if request.headers.get("HX-Request") == "true":
            raise HTTPException(
                status_code=200,
                detail="Login required",
                headers={"HX-Redirect": "/login"},
            )
        raise HTTPException(
            status_code=303,
            detail="Login required",
            headers={"Location": "/login"},
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
    """Validate CSRF token from form data; raise 403 if missing or invalid."""
    form_data = await request.form()
    token = form_data.get("_csrf_token", "")
    if not token or not validate_csrf_token(str(token), user):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    return user


def refresh_session_cookie(response, username: str) -> None:
    """Re-sign and re-set the session cookie for sliding window timeout."""
    cookie_value = create_session_cookie(username)
    response.set_cookie(
        "session",
        cookie_value,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
    )
