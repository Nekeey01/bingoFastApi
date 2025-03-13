import os
from datetime import datetime, timedelta
from urllib.parse import urlencode

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from starlette.responses import RedirectResponse

from database.database import get_db
from database.models import User, UserCreate, UserAuth, Token

load_dotenv()

FRONTEND_URL = "http://localhost:5173/"

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

# OAuth settings
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID') or None
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET') or None
GOOGLE_REDIRECT_URI = "http://127.0.0.1:8000/gLoginCallback"

YANDEX_CLIENT_ID = os.environ.get('YANDEX_CLIENT_ID') or None
YANDEX_CLIENT_SECRET = os.environ.get('YANDEX_CLIENT_SECRET') or None
YANDEX_REDIRECT_URI = "http://127.0.0.1:8000/yaLoginCallback"
if GOOGLE_CLIENT_ID is None or GOOGLE_CLIENT_SECRET is None:
    raise BaseException('Missing env variables')

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"payload - {payload}")

        return payload.get("sub")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(User).where(User.email == email))
    return result.scalars().first()


async def get_user_by_google_id(db: AsyncSession, google_id: str):
    result = await db.execute(select(User).where(User.google_id == google_id))
    return result.scalars().first()


async def authenticate_user(db: AsyncSession, email: str, password: str):
    user = await get_user_by_email(db, email)
    if not user or not pwd_context.verify(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@auth_router.get("/gLogin")
async def google_login(request: Request):
    redirect_uri = request.url_for('google_login_callback')

    return {
        "auth_url": f"https://accounts.google.com/o/oauth2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=email%20profile"
    }


@auth_router.get("/gLoginCallback")
async def google_login_callback(code: str, db: AsyncSession = Depends(get_db)):
    token_request_uri = "https://oauth2.googleapis.com/token"
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_request_uri, data=data)
        response.raise_for_status()

        token_response = response.json()
    id_token_value = token_response.get('id_token')
    if not id_token_value:
        raise HTTPException(status_code=400, detail="Missing id_token in response.")

    try:
        id_info = id_token.verify_oauth2_token(id_token_value, google_requests.Request(), GOOGLE_CLIENT_ID)
        print(f"id_info - {id_info}")

        email = id_info["email"]
        google_id = id_info["sub"]
        picture_link = id_info["picture"]

        user = await get_user_by_email(db, email)
        if user:
            if not user.google_id:
                user.google_id = google_id
                user.google_avatar_path = picture_link
                if not user.avatar_path:
                    user.avatar_path = picture_link
                await db.commit()
                # await db.refresh(user)
        else:
            user = User(email=email, google_id=google_id, google_avatar_path=picture_link, avatar_path=picture_link)
            db.add(user)
            await db.commit()
            await db.refresh(user)

        token_expire_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        access_token = create_access_token(data={"sub": user.email},
                                           expires_delta=token_expire_delta)

        headers = {"access_token": access_token, "token_type": "bearer"}

        redirect_url = f"{FRONTEND_URL}auth/callback?{urlencode(headers)}"

        return RedirectResponse(url=redirect_url)

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Google token")


@auth_router.get("/yaLogin")
async def yandex_login(request: Request):
    redirect_uri = request.url_for('yandex_login_callback')

    return {
        "auth_url": f"https://oauth.yandex.ru/authorize?response_type=code&client_id={YANDEX_CLIENT_ID}&redirect_uri={YANDEX_REDIRECT_URI}"
    }


# TODO: Добавить обработку аватара и юзернейма. Аватар меняется только при отсутсвии\наличии дефолтного.
# Сделать возможность выбирать, какой аватар вставлять (свой, яндекс, гугл)

@auth_router.get("/yaLoginCallback")
async def yandex_login_callback(code: str, db: AsyncSession = Depends(get_db)):
    token_request_uri = "https://oauth.yandex.ru/token"
    user_info_url = "https://login.yandex.ru/info"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': YANDEX_CLIENT_ID,
        'client_secret': YANDEX_CLIENT_SECRET,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_request_uri, data=data)
        response.raise_for_status()
        token_response = response.json()

        access_token = token_response.get('access_token')
        if not access_token:
            raise HTTPException(status_code=400, detail="Missing access_token in response.")

        user_info_response = await client.get(
            user_info_url,
            headers={"Authorization": f"OAuth {access_token}"}
        )
        user_info = user_info_response.json()

        email = user_info["default_email"]
        yandex_id = user_info["id"]
        picture_link = f"https://avatars.yandex.net/get-yapic/{user_info['default_avatar_id']}/islands-middle"

    try:

        user = await get_user_by_email(db, email)
        if user:
            if not user.yandex_id:
                user.yandex_id = yandex_id
                user.yandex_avatar_path = picture_link
                if not user.avatar_path:
                    user.avatar_path = picture_link
                await db.commit()
                # await db.refresh(user)
        else:
            user = User(email=email, yandex_id=yandex_id, yandex_avatar_path=picture_link, avatar_path=picture_link)
            db.add(user)
            await db.commit()
            await db.refresh(user)

        token_expire_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        access_token = create_access_token(data={"sub": user.email},
                                           expires_delta=token_expire_delta)

        headers = {"access_token": access_token, "token_type": "bearer"}

        redirect_url = f"{FRONTEND_URL}auth/callback?{urlencode(headers)}"

        return RedirectResponse(url=redirect_url)

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Yandex token")


@auth_router.post("/register")
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    existing_user = await get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already taken")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "User registered", "status": 200}


@auth_router.post("/login", response_model=Token)
async def login(user: UserAuth, db: AsyncSession = Depends(get_db)):
    print(f"username - {user.email}"
          f"password - {user.password}")
    db_user = await authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_expire_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    token = create_access_token(data={"sub": db_user.email},
                                expires_delta=token_expire_delta)
    return {"access_token": token, "token_type": "bearer"}
