from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from auth import get_current_user, get_user_by_email
from database.database import get_db
from database.models import ProviderRequest

profile_router = APIRouter()


@profile_router.get("/getCurrentAvatar")
async def get_current_avatar(email: str = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, email)
    avatar_path = user.avatar_path
    return {"avatar_url": avatar_path}


#
# @profile_router.post("/setCurrentAvatar")
# async def set_current_avatar(url: str, email: str = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
#     paпппыы

@profile_router.post("/setCurrentAvatarByOAuth")
async def set_current_avatar_by_OAuth(provider: ProviderRequest, email: str = Depends(get_current_user),
                                      db: AsyncSession = Depends(get_db)):
    print(f"provider - {provider}")
    print(f"token - {email}")
    avatar_url = "lox"
    user = await get_user_by_email(db, email)
    if provider.provider == "Google":
        user.avatar_path = user.google_avatar_path
        avatar_url = user.google_avatar_path
    elif provider.provider == "Yandex":
        user.avatar_path = user.yandex_avatar_path
        avatar_url = user.yandex_avatar_path

    await db.commit()
    await db.refresh(user)

    return {"avatar_url": avatar_url}
