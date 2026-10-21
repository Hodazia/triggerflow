import hashlib
import secrets
from datetime import datetime, timezone

from typing import Annotated
from fastapi import Depends, HTTPException, Header
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models.model import APIKey, Tenant


api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def hash_api_key(raw_key: str) -> str:
    '''
    Produce a fixed-length SHA-256 hash for database lookup.
    '''
    return hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()


def generate_api_key() -> str:
    '''
    Generate a cryptographically random API key.
    The full secret is returned to the caller once.
    '''
    return "tf_" + secrets.token_urlsafe(32)


def get_key_prefix(raw_key: str):
    '''
    stores only a short, non-secret identifier
    '''
    return raw_key[:16]


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Invalid or expired API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


async def get_current_api_key(
    raw_key: Annotated[
        str | None,
        Header(alias="X-API-Key"),
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    if not raw_key:
        raise unauthorized()

    key_hash = hash_api_key(raw_key)

    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    api_key = result.scalar_one_or_none()

    if api_key is None or api_key.revoked_at is not None:
        raise unauthorized()

    now = datetime.now(timezone.utc)

    if api_key.expires_at is not None:
        expires_at = api_key.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= now:
            raise unauthorized()

    return api_key


async def require_key_management(
    current_key: APIKey = Depends(get_current_api_key),
) -> APIKey:
    if "keys:manage" not in (current_key.scopes or []):
        raise HTTPException(
            status_code=403,
            detail="This API key does not have keys:manage permission",
        )

    return current_key


async def require_endpoint_management(
    current_key: APIKey = Depends(get_current_api_key),
) -> APIKey:
    if "endpoints:manage" not in (current_key.scopes or []):
        raise HTTPException(
            status_code=403,
            detail="This API key does not have endpoints:manage permission",
        )

    return current_key


BOOTSTRAP_SCOPES = ["keys:manage", "endpoints:manage"]


async def seed_bootstrap_key(db: AsyncSession, raw_key: str):
    key_hash = hash_api_key(raw_key)

    tenant = await db.get(Tenant, "demo")
    if tenant is None:
        db.add(Tenant(id="demo", name="Demo"))
        await db.flush()

    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    existing = result.scalar_one_or_none()

    if existing:
        current_scopes = list(existing.scopes or [])
        missing = [
            scope for scope in BOOTSTRAP_SCOPES if scope not in current_scopes
        ]
        if missing:
            existing.scopes = current_scopes + missing
            await db.commit()
        return

    db.add(
        APIKey(
            tenant_id="demo",
            name="Bootstrap key",
            key_prefix=get_key_prefix(raw_key),
            key_hash=key_hash,
            scopes=list(BOOTSTRAP_SCOPES),
        )
    )
    await db.commit()
