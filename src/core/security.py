import hashlib
import secrets
from datetime import datetime, timezone

from typing import Annotated
from fastapi import Depends, HTTPException, Header
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from core.database import get_db
from models.model import APIKey


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


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Invalid or expired API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def get_current_api_key(
    raw_key: Annotated[
        str | None,
        Header(alias="X-API-Key"),
    ] = None,
    db: Session = Depends(get_db),
) -> APIKey:
    if not raw_key:
        raise unauthorized()

    key_hash = hash_api_key(raw_key)

    api_key = db.scalar(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )

    if api_key is None or api_key.revoked_at is not None:
        raise unauthorized()

    now = datetime.now(timezone.utc)

    if api_key.expires_at is not None:
        # Some database drivers return naive datetimes for
        # timezone-aware columns, so normalize before comparison.
        expires_at = api_key.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= now:
            raise unauthorized()

    return api_key

def require_key_management(
    current_key: APIKey = Depends(get_current_api_key),
) -> APIKey:
    if "keys:manage" not in current_key.scopes:
        raise HTTPException(
            status_code=403,
            detail="This API key does not have keys:manage permission",
        )

    return current_key



async def seed_bootstrap_key(db: AsyncSession, raw_key: str):
    key_hash = hash_api_key(raw_key)

    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    existing = result.scalar_one_or_none()

    if existing:
        return

    db.add(
        APIKey(
            owner_id="demo",
            name="Bootstrap key",
            key_prefix=raw_key[:12],
            key_hash=key_hash,
        )
    )
    await db.commit()


def get_key_prefix(raw_key:str):
    '''
    stores only a short, non-secret identifier
    '''
    return raw_key[:16]

'''
When a request arrives with X-API-Key, TriggerFlow hashes the supplied key and looks up the matching hash in the database. 
It never needs to retrieve the original secret.

GET /v1/api-keys
X-API-Key: tf_live_example_secret


The backend:
1. Reads the X-API-Key header.
2. Hashes the supplied secret.
3. Looks up the matching record in PostgreSQL.
4. Rejects the request if the key doesn't exist, has expired, or has been revoked.
5. Checks that the key has keys:manage.
6. Makes the authenticated key's tenant_id available to the route.
The distinction between 401 and 403 is useful:
- 401 Unauthorized: credentials are missing or invalid.
- 403 Forbidden: credentials are valid but lack the required permission.

'''