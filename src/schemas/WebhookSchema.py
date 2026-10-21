
from datetime import datetime
from pydantic import AnyHttpUrl, BaseModel, Field , field_validator, ConfigDict

class EndpointCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)

    url:AnyHttpUrl

    subscribed_events: list[str] = Field(min_length=1, max_length=50)
    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Endpoint name cannot be blank")

        return value

    @field_validator("subscribed_events")
    @classmethod
    def validate_events(cls, events: list[str]) -> list[str]:
        if len(events) != len(set(events)):
            raise ValueError("Duplicate event subscriptions are not allowed")

        for event in events:
            if not event or len(event) > 100:
                raise ValueError("Invalid event type")

            # Example: order.paid, user.logged_in
            parts = event.split(".")

            if not all(
                part and part.replace("_", "").isalnum()
                for part in parts
            ):
                raise ValueError(f"Invalid event type: {event}")

        return events


class EndpointUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    url: AnyHttpUrl | None = None
    subscribed_events: list[str] | None = Field(
        default=None,
        min_length=1,
        max_length=50,
    )
    is_active: bool | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return value

        value = value.strip()

        if not value:
            raise ValueError("Endpoint name cannot be blank")

        return value

    @field_validator("subscribed_events")
    @classmethod
    def validate_events(
        cls,
        events: list[str] | None,
    ) -> list[str] | None:
        if events is None:
            return None

        if len(events) != len(set(events)):
            raise ValueError("Duplicate event subscriptions are not allowed")

        for event in events:
            parts = event.split(".")
            if (
                len(event) > 100
                or not all(
                    part and part.replace("_", "").isalnum()
                    for part in parts
                )
            ):
                raise ValueError(f"Invalid event type: {event}")

        return events


class EndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    url: str
    subscribed_events: list[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None