
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException,Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated
from core.security import get_key_prefix, require_key_management
from core.database import get_db
from models.model import APIKey
from schemas.APISchema import APIKeyCreate,APIKeyCreated,APIKeyRead
from core.security import generate_api_key, get_current_key, hash_api_key

router = APIRouter(prefix="/v1/api-keys", tags=["API Keys"])


@router.post("", response_model=APIKeyCreated, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    current_key: Annotated[
        APIKey, Depends(require_key_management)
    ],
    db: AsyncSession = Depends(get_db),
):
    raw_key = generate_api_key()
    now = datetime.now(timezone.utc)

    expires_at = None
    if body.expires_in_days is not None:
        expires_at = now + timedelta(days=body.expires_in_days)

    api_key = APIKey(
        tenant_id=current_key.tenant_id,
        name=body.name,
        key_prefix=get_key_prefix(raw_key),
        key_hash=hash_api_key(raw_key),
        scopes=body.scopes,
        created_at=now,
        expires_at=expires_at,
    )

    db.add(api_key)
   
    try:
        db.commit()
        db.refresh(api_key)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to create API key",
        )

    # The raw secret is returned only in this response.
    return APIKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
    )


@router.get("", response_model=list[APIKeyRead])
async def list_api_keys(
     current_key: Annotated[
        APIKey, Depends(require_key_management)
    ],
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[APIKey]:
    statement = (
        select(APIKey)
        .where(APIKey.tenant_id == current_key.tenant_id)
        .order_by(APIKey.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(statement).all())



@router.delete(
    "/{key_id}",
    status_code=204,
)
def revoke_api_key(
    key_id: str,
    current_key: Annotated[
        APIKey, Depends(require_key_management)
    ],
    db: Session = Depends(get_db),
) -> Response:
    api_key = db.scalar(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.tenant_id == current_key.tenant_id,
        )
    )

    if api_key is None:
        # Same response whether the ID doesn't exist or belongs
        # to another tenant.
        raise HTTPException(
            status_code=404,
            detail="API key not found",
        )

    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(timezone.utc)
        db.commit()

    return Response(status_code=204)

'''
The three endpoints are:
- POST /v1/api-keys — create another API key for the same owner.
- GET /v1/api-keys — list keys without revealing their secrets.
- DELETE /v1/api-keys/{key_id} — revoke a key.

'''
