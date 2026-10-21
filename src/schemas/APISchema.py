
from datetime import datetime
from pydantic import BaseModel, Field


class APIKeyCreate(BaseModel):
    name:str = Field(min_length=1, max_length=100)

class APIKeyCreated(BaseModel):
    id: int
    name: str
    key: str


class APIKeyRead(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: datetime
    revoked_at: datetime | None

'''
user will give a name to the api , and we will return the api key,

but why do we need an API key anyways,
and how are different api keys will be useful

'''


