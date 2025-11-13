from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr

from .models import UserRole


# ---------- Shared base ----------

class UserBase(BaseModel):
    name: str
    username: str
    email: EmailStr
    role: UserRole


# ---------- Input schemas ----------

class UserCreate(UserBase):
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    

class UserRoleUpdate(BaseModel):
    role: UserRole


# ---------- Output schemas ----------

class UserRead(BaseModel):
    id: int
    name: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True  # for SQLAlchemy models


# ---------- Token schemas ----------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: int
    role: UserRole
