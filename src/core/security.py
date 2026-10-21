import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.model import APIKey


api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()


def generate_api_key() -> str:
    return "tf_" + secrets.token_urlsafe(32)


async def get_current_key(
    raw_key: str | None = Depends(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    if not raw_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key",
        )

    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == hash_api_key(raw_key),
            APIKey.revoked_at.is_(None),
        )
    )

    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked API key",
        )

    return api_key


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
