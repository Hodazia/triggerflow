
from datetime import datetime
from pydantic import BaseModel, Field , field_validator, ConfigDict


ALLOWED_SCOPES = {
    "keys:manage",
    "events:write",
    "events:read",
    "endpoints:manage",
    "usage:read",
}

class APIKeyCreate(BaseModel):
    name:str = Field(min_length=1, max_length=100, examples=["production-backend"])
    scopes: list[str] = Field(
        min_length=1,
        examples=[["events:write", "events:read"]],
    )

    expires_in_days: int | None = Field(
        default=None,
        ge=1,
        le=365,
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Name cannot be blank")

        return value

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, scopes: list[str]) -> list[str]:
        if len(scopes) != len(set(scopes)):
            raise ValueError("Duplicate scopes are not allowed")

        invalid = set(scopes) - ALLOWED_SCOPES

        if invalid:
            raise ValueError(
                f"Unsupported scopes: {', '.join(sorted(invalid))}"
            )

        return scopes

class APIKeyCreated(BaseModel):
    id: int
    name: str
    key: str
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None


class APIKeyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None

'''
user will give a name to the api , and we will return the api key,

but why do we need an API key anyways,
and how are different api keys will be useful


Notice the two separate response schemas:
- APIKeyCreated contains key, because the full secret must be shown once.
- APIKeyRead deliberately has no key or key_hash.
This separation prevents an accidental secret leak when listing keys or returning an existing database record.

The scope list is also validated server-side. A client cannot invent a permission such as admin:all.

'''