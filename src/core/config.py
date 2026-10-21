from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = Field(
        validation_alias=AliasChoices("DATABASE_URL", "DB_URL", "database_url"),
    )
    bootstrap_api_key: str = Field(
        validation_alias=AliasChoices(
            "BOOTSTRAP_API_KEY",
            "bootstrap_api_key",
        ),
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @field_validator("database_url")
    @classmethod
    def normalize_async_url(cls, value: str) -> str:
        value = value.strip()

        if value.startswith("postgresql+psycopg"):
            value = "postgresql+asyncpg" + value[len("postgresql+psycopg") :]
        elif value.startswith("postgresql://"):
            value = "postgresql+asyncpg://" + value[len("postgresql://") :]

        parsed = urlparse(value)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        sslmode = query.pop("sslmode", None)
        if sslmode in {"require", "verify-ca", "verify-full"}:
            query.setdefault("ssl", "require")

        query.pop("channel_binding", None)

        return urlunparse(parsed._replace(query=urlencode(query)))


settings = Settings()
