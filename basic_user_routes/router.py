from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from google.auth.transport import requests as requests_transport
from google.oauth2 import id_token
from jose import ExpiredSignatureError, JWTError
from sqlalchemy.orm import Session

from basic_user_routes.config import BaseRouterConfig
from basic_user_routes.models import UserBase
from basic_user_routes.schemas import GoogleToken, UserBase, UserCreate, BaseUser, UserReset
from basic_user_routes.utils import create_access_token, decode_token


def decode_google_token(token: str, google_client_id: str):
    return id_token.verify_oauth2_token(token, requests_transport.Request(), google_client_id)


def get_basic_user_router(config: BaseRouterConfig):
    router = APIRouter(prefix=config.prefix, include_in_schema=False)

    @router.post("/sign_in")
    def sign_in(user: BaseUser, db: Session = Depends(config.get_db)):
        try:
            user = config.crud.authenticate_user(db, user.email, user.password)
        except ValueError:
            raise HTTPException(status_code=400, detail="Already registered through Google")
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        access_token_expires = timedelta(minutes=config.expire_limit)
        access_token = create_access_token(
            priv_key=config.priv_key, algo=config.algorithm, data={"sub": user.email},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    @router.post("/sign_up")
    def sign_up(background_tasks: BackgroundTasks, user: UserCreate, db: Session = Depends(config.get_db)):
        db_user = config.crud.get_user_by_email(db, email=user.email)
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        config.crud.create_user(db=db, user=user, service_provider="email")
        confirmation_token_expires = timedelta(minutes=config.expire_limit)
        data = {"sub": user.email}
        token = create_access_token(priv_key=config.priv_key, algo=config.algorithm,
                                    data=data, expires_delta=confirmation_token_expires)
        link = config.api_base_url + f"{config.prefix}/activate/{token}"
        background_tasks.add_task(config.send_link_email, user.email,
                                  link, "Click the link to activate your account",
                                  "Activate")
        return {"status": "ok", "message": "Check email for confirmation message"}

    @router.get("/activate/{token}")
    def activate(token: str, db: Session = Depends(config.get_db)):
        try:
            token_data = decode_token(token, config)
        except JWTError:
            raise HTTPException(status_code=400, detail="Token validation error")
        except ExpiredSignatureError:
            raise HTTPException(status_code=400, detail="Token has expired")
        user = config.crud.get_user_by_email(db, email=token_data.username)
        if user is None:
            raise HTTPException(status_code=400, detail="No user for the token")
        if user.is_active:
            return {"status": "ok", "message": "Email already confirmed"}
        user.is_active = True
        db.commit()
        return RedirectResponse(config.login_redirect)

    @router.post("/sign_in_google")
    def sign_in_google(background_tasks: BackgroundTasks, request: Request, token: GoogleToken,
                       db: Session = Depends(config.get_db)):
        decoded = decode_google_token(token.credential, config.google_client_id)
        if not decoded["email_verified"]:
            raise HTTPException(status_code=400, detail="Email not verified")
        try:
            user_db = config.crud.authenticate_user_google(db, decoded["email"])
        except ValueError:
            raise HTTPException(status_code=400, detail="Already registered with email")
        if not user_db:
            config.crud.create_user(db=db, user=BaseUser(email=decoded["email"]), service_provider="google")
        access_token_expires = timedelta(minutes=config.expire_limit)
        access_token = create_access_token(
            priv_key=config.priv_key, algo=config.algorithm,
            data={"sub": decoded["email"]}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    @router.get("/reset_password")
    def get_reset_link(background_tasks: BackgroundTasks, email: str, db: Session = Depends(config.get_db)):
        db_user = config.crud.get_user_by_email(db, email=email)
        if db_user is None:
            raise HTTPException(status_code=400, detail="User does not exists")
        if not db_user.is_active:
            raise HTTPException(status_code=400, detail="User not activated")
        if db_user.service_provider_name == "google":
            raise HTTPException(status_code=400, detail="Registered through google")
        reset_token_expires = timedelta(minutes=30)
        data = {"sub": email, "type": "reset"}
        token = create_access_token(config.priv_key, config.algorithm, data, reset_token_expires)
        link = f"{config.api_base_url}/{config.prefix}/reset_password?t={token}"
        background_tasks.add_task(config.send_link_email, email, link, "Click the link to reset your password",
                                  "Reset password")
        return {"status": "ok", "message": "Check email for reset link"}

    @router.post("/reset_password/{token}")
    def reset_password(token: str, user_data: UserReset, db: Session = Depends(config.get_db)):
        try:
            token_data = decode_token(token, config, is_reset=True)
        except JWTError:
            raise HTTPException(status_code=400, detail="Token validation error")
        except ExpiredSignatureError:
            raise HTTPException(status_code=400, detail="Token has expired")
        user = config.crud.get_user_by_email(db, email=token_data.username)
        if user is None:
            raise HTTPException(status_code=400, detail="No user for the token")
        user.hashed_password = config.crud.get_password_hash(user_data.password)
        db.commit()
        return {"status": "ok", "message": "Password changed"}

    @router.get("/resend_activation")
    def resend_activation(background_tasks: BackgroundTasks, user: UserBase,
                          db: Session = Depends(config.get_db)):
        db_user = config.crud.get_user_by_email(db, email=user.email)
        if db_user is None:
            raise HTTPException(status_code=400, detail="Email not found")
        if db_user.is_active:
            raise HTTPException(status_code=400, detail="Email already activated")
        confirmation_token_expires = timedelta(minutes=60*3)
        data = {"sub": user.email}
        token = create_access_token(config.priv_key, config.algorithm, data, confirmation_token_expires)
        link = f"{config.api_base_url}/{config.prefix}/activate/{token}"
        background_tasks.add_task(config.send_link_email, user.email, link, "Click the link to activate your account",
                                  "Activate")
        return {"status": "ok", "message": "Check your email for confirmation message"}

    return router
