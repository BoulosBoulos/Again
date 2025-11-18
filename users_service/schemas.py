from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, ConfigDict

from .models import UserRole


# ---------- Input schemas ----------
class UserCreate(BaseModel):
    """
    Schema for user registration input.
    Public registration does NOT accept role; it is assigned internally.
    """
    name: str
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    """
    Schema for user login credentials.

    Attributes
    ----------
    username : str
        Username used for authentication.
    password : str
        Plaintext password supplied by the client.
    """
    username: str
    password: str


class UserUpdate(BaseModel):
    """
    Schema for updating the authenticated user's profile.

    Only name and email are editable; both are optional.
    """
    name: Optional[str] = None
    email: Optional[EmailStr] = None


class UserRoleUpdate(BaseModel):
    """
    Schema used by admins to change a user's role.
    """
    role: UserRole


class PasswordReset(BaseModel):
    """
    Schema for admin-initiated password resets.

    Attributes
    ----------
    new_password : str
        The new plaintext password to be set for the user.
    """
    new_password: str


# ---------- Output schemas ----------

class UserRead(BaseModel):
    """
    Schema returned when reading user information.

    Exposes safe, non-sensitive fields and hides the password hash.
    """
    id: int
    name: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# ---------- Token schemas ----------

class Token(BaseModel):
    """
    Schema for JWT access token responses.

    Attributes
    ----------
    access_token : str
        Encoded JWT.
    token_type : str
        Token type, usually 'bearer'.
    """
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """
    Internal schema for decoded token payload.

    Attributes
    ----------
    user_id : int
        ID of the authenticated user.
    role : UserRole
        Role embedded in the token.
    """
    user_id: int
    role: UserRole
