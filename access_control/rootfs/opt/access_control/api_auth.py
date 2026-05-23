"""API key authentication middleware."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import hash_api_key
from .database import Database
security = HTTPBearer()
_API_RATE_LIMIT = {"max_attempts": 10, "window": 300, "lockout": 60}


async def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """Verify API key and return {"key": str, "scope": str}."""
    client_ip = request.client.host if request.client else "unknown"
    db: Database = request.app.state.db
    if await db.is_rate_limited("api", client_ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts")

    key = credentials.credentials
    key_hash = hash_api_key(key)
    valid = await db.verify_api_key(key_hash)
    if not valid:
        await db.record_rate_limit_failure("api", client_ip, **_API_RATE_LIMIT)
        raise HTTPException(status_code=401, detail="Invalid API key")

    await db.clear_rate_limit("api", client_ip)
    return {"key": key, "scope": valid.get("scope") or "full"}
