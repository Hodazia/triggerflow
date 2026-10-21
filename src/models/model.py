from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Index
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36) , primary_key=True, default = lambda: str(uuid.uuid4()))

    #used for customer isolation
    tenant_id: Mapped[str] = mapped_column(String(100),
     ForeignKey("tenants.id", ondelete="CASCADE") , 
     nullable=False,index=True)

     # e.g. production backend
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # let the customer identify a key in the dashboard without its full name
    key_prefix: Mapped[str] = mapped_column(String(24), nullable=False)

    #Store only the hash of the complete API Key
    key_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )

    # Example: ["events:write", "keys:manage"]
    scopes: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False,
        default=utc_now
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "key_hash",
            name="uq_api_keys_key_hash",
        ),
        Index(
            "ix_api_keys_tenant_created",
            "tenant_id",
            "created_at",
        ),
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(100), index=True
    )
    task_type: Mapped[str] = mapped_column(String(100), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(
        String(20), default="queued", index=True
    )
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
