from enum import Enum

from pydantic import BaseModel
from typing import Optional, Union


class GoogleToken(BaseModel):
    credential: str
    clientId: Optional[str]
    select_by: Optional[str]


class TokenData(BaseModel):
    username: Union[str, None] = None


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class ServiceProvider(str, Enum):
    internal = "internal"
    google = "google"


class BaseUser(BaseModel):
    email: str
    password: Optional[str] = None


class UserReset(BaseModel):
    password: str
    passwordcheck: str