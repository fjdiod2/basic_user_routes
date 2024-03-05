from datetime import timedelta, datetime
from typing import Union

from fastapi import HTTPException
from jose import jwt

from basic_user_routes.schemas import TokenData
from basic_user_routes.config import BaseRouterConfig


def create_access_token(priv_key: str, algo: str, data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, priv_key, algorithm=algo)
    return encoded_jwt


def decode_token(token: str, config: BaseRouterConfig, is_reset=False):
    credentials_exception = HTTPException(
        status_code=400,
        detail="Could not validate credentials",
    )
    payload = jwt.decode(token, config.pub_key, algorithms=[config.algorithm])
    username: str = payload.get("sub")
    msg_type: str = payload.get("type")
    if username is None or (msg_type != "reset" and is_reset):
        raise credentials_exception
    token_data = TokenData(username=username)
    return token_data