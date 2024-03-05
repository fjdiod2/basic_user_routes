from dataclasses import dataclass
from typing import Callable

from sqlalchemy.orm import sessionmaker

from basic_user_routes.crud import BaseCrud


@dataclass
class BaseRouterConfig:
    priv_key: str
    pub_key: str
    crud: BaseCrud
    api_base_url: str
    google_client_id: str
    login_redirect: str
    send_link_email: Callable[[str, str, str, str], None]
    get_db: Callable[[], sessionmaker]
    prefix: str = "/internal"
    algorithm: str = "RS256"
    expire_limit: int = 180