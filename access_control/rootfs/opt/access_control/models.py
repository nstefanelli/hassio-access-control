from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class LockType(str, Enum):
    ACCESS_NATIVE = "access_native"
    HA_EXTERNAL = "ha_external"


class AccessResult(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
    ERROR = "error"


class AccessMethod(str, Enum):
    NFC = "nfc"
    FACE = "face"
    MANUAL = "manual"
    API = "api"


class UserStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DELETED_UPSTREAM = "deleted_upstream"


class User(BaseModel):
    id: Optional[int] = None
    ulp_id: str
    name: str
    email: Optional[str] = None
    status: UserStatus = UserStatus.ACTIVE
    synced_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class Lock(BaseModel):
    id: Optional[int] = None
    type: LockType
    device_id: Optional[str] = None
    location_id: Optional[str] = None
    entity_id: Optional[str] = None
    name: str
    door_name: Optional[str] = None

    class Config:
        from_attributes = True


class AccessRule(BaseModel):
    id: Optional[int] = None
    user_id: int
    lock_id: int
    enabled: bool = True
    schedule_enabled: bool = False
    schedule_days: Optional[str] = None  # comma-separated day numbers, e.g. "0,1,2,3,4"
    schedule_start: Optional[str] = None  # HH:MM format
    schedule_end: Optional[str] = None    # HH:MM format
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AccessLogEntry(BaseModel):
    id: Optional[int] = None
    timestamp: Optional[datetime] = None
    user_id: Optional[int] = None
    user_name: Optional[str] = None
    lock_id: Optional[int] = None
    lock_name: Optional[str] = None
    method: AccessMethod
    result: AccessResult
    reason: Optional[str] = None

    class Config:
        from_attributes = True


class HealthStatus(BaseModel):
    unvr_connected: bool
    ha_connected: bool
    websocket_connected: bool
    user_count: int
    lock_count: int
    uptime_seconds: float


class SetupData(BaseModel):
    admin_username: str
    admin_password: str
    unvr_host: str
    unvr_username: str
    unvr_password: str
    ha_url: str
    ha_token: str
