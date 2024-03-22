from abc import ABC
from typing import Optional

from basic_user_routes.schemas import UserBase, BaseUser


class BaseCrud(ABC):
    def authenticate_user(self, db, email: str, password: str) -> Optional[UserBase]:
        pass

    def authenticate_user_google(self, db, user_email: str) -> Optional[UserBase]:
        pass

    def create_user(self, db, user: BaseUser, service_provider: str):
        pass

    def get_user_by_email(self, db, email: str) -> Optional[UserBase]:
        pass

    def get_password_hash(self, password: str) -> str:
        pass