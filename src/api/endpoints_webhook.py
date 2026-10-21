from fastapi import APIRouter, Depends, HTTPException, Query, Response
from typing import Annotated
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import datetime, timezone
from src.core.webhook_url_security import validate_webhook_url
from src.models.model import WebhookEndpoint
from src.core.security import require_endpoint_management
from src.models.model import APIKey
from src.schemas.WebhookSchema import EndpointCreate, EndpointRead, EndpointUpdate
from src.core.database import get_db


router = APIRouter(
    prefix="/v1/endpoints",
    tags=["Webhook Endpoints"],
)


async def get_owned_endpoint(
    endpoint_id: str,
    tenant_id: str,
    db: AsyncSession,
) -> WebhookEndpoint:
    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == endpoint_id.strip(),
            WebhookEndpoint.tenant_id == tenant_id,
            WebhookEndpoint.deleted_at.is_(None),
        )
    )
    endpoint = result.scalar_one_or_none()

    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Endpoint not found",
        )

    return endpoint


@router.post(
    "",
    response_model=EndpointRead,
    status_code=201,
)
async def create_endpoint(
    body: EndpointCreate,
    current_key: Annotated[
        APIKey, Depends(require_endpoint_management)
    ],
    db: AsyncSession = Depends(get_db),
) -> WebhookEndpoint:
    try:
        validate_webhook_url(str(body.url))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    now = datetime.now(timezone.utc)
    endpoint = WebhookEndpoint(
        tenant_id=current_key.tenant_id,
        name=body.name,
        url=str(body.url),
        subscribed_events=body.subscribed_events,
        is_active=True,
        created_at=now,
        updated_at=now,
    )

    db.add(endpoint)

    try:
        await db.commit()
        await db.refresh(endpoint)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to create endpoint",
        )

    return endpoint


@router.get(
    "",
    response_model=list[EndpointRead],
)
async def list_endpoints(
    current_key: Annotated[
        APIKey, Depends(require_endpoint_management)
    ],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[WebhookEndpoint]:
    statement = (
        select(WebhookEndpoint)
        .where(
            WebhookEndpoint.tenant_id == current_key.tenant_id,
            WebhookEndpoint.deleted_at.is_(None),
        )
        .order_by(WebhookEndpoint.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    result = await db.execute(statement)
    return list(result.scalars().all())


@router.get(
    "/{endpoint_id}",
    response_model=EndpointRead,
)
async def get_endpoint(
    endpoint_id: str,
    current_key: Annotated[
        APIKey, Depends(require_endpoint_management)
    ],
    db: AsyncSession = Depends(get_db),
) -> WebhookEndpoint:
    return await get_owned_endpoint(
        endpoint_id,
        current_key.tenant_id,
        db,
    )


@router.patch(
    "/{endpoint_id}",
    response_model=EndpointRead,
)
async def update_endpoint(
    endpoint_id: str,
    body: EndpointUpdate,
    current_key: Annotated[
        APIKey, Depends(require_endpoint_management)
    ],
    db: AsyncSession = Depends(get_db),
) -> WebhookEndpoint:
    endpoint = await get_owned_endpoint(
        endpoint_id,
        current_key.tenant_id,
        db,
    )

    changes = body.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(
            status_code=422,
            detail="Provide at least one field to update",
        )

    for field, value in changes.items():
        if value is None:
            raise HTTPException(
                status_code=422,
                detail=f"{field} cannot be null",
            )

    if "url" in changes:
        try:
            validate_webhook_url(str(changes["url"]))
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

        changes["url"] = str(changes["url"])

    for field, value in changes.items():
        setattr(endpoint, field, value)

    endpoint.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(endpoint)

    return endpoint


@router.delete(
    "/{endpoint_id}",
    status_code=204,
)
async def delete_endpoint(
    endpoint_id: str,
    current_key: Annotated[
        APIKey, Depends(require_endpoint_management)
    ],
    db: AsyncSession = Depends(get_db),
) -> Response:
    endpoint = await get_owned_endpoint(
        endpoint_id,
        current_key.tenant_id,
        db,
    )

    now = datetime.now(timezone.utc)

    endpoint.is_active = False
    endpoint.deleted_at = now
    endpoint.updated_at = now

    await db.commit()

    return Response(status_code=204)
