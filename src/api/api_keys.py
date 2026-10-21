
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.model import APIKey
from schemas.APISchema import APIKeyCreate,APIKeyCreated,APIKeyRead
from core.security import generate_api_key, get_current_key, hash_api_key

router = APIRouter(prefix="/v1/api-keys", tags=["API Keys"])


@router.post("", response_model=APIKeyCreated, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    current: APIKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
):
    raw_key = generate_api_key()

    key = APIKey(
        owner_id=current.owner_id,
        name=body.name,
        key_prefix=raw_key[:12],
        key_hash=hash_api_key(raw_key),
    )

    db.add(key)
    await db.commit()
    await db.refresh(key)

    # The raw secret is returned only once.
    return APIKeyCreated(
        id=key.id,
        name=key.name,
        key=raw_key,
    )


@router.get("", response_model=list[APIKeyRead])
async def list_api_keys(
    current: APIKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(APIKey)
        .where(APIKey.owner_id == current.owner_id)
        .order_by(APIKey.id.desc())
    )

    return result.scalars().all()


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: int,
    current: APIKey = Depends(get_current_key),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.owner_id == current.owner_id,
        )
    )
    key = result.scalar_one_or_none()

    if not key:
        raise HTTPException(
            status_code=404,
            detail="API key not found",
        )

    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        await db.commit()

'''
The three endpoints are:
- POST /v1/api-keys — create another API key for the same owner.
- GET /v1/api-keys — list keys without revealing their secrets.
- DELETE /v1/api-keys/{key_id} — revoke a key.

'''
