from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models
from .database import get_db

# --- JWT / security settings (SHARED WITH OTHER SERVICES) ---
SECRET_KEY = "super-secret-smart-meeting-room-key"  # same in rooms_service/auth.py
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- Password hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/login")



def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    Parameters
    ----------
    plain_password : str
        Raw password provided by the user.
    hashed_password : str
        Previously stored bcrypt hash.

    Returns
    -------
    bool
        True if the password matches, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Parameters
    ----------
    password : str
        The raw password to hash.

    Returns
    -------
    str
        Bcrypt hash suitable for storage.
    """
    return pwd_context.hash(password)


# ---------- DB helpers ----------

def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    """
    Retrieve a user by username.

    Parameters
    ----------
    db : Session
        Database session.
    username : str
        Username to look up.

    Returns
    -------
    Optional[User]
        Matching user instance, or None if not found.
    """
    return db.query(models.User).filter(models.User.username == username).first()


def authenticate_user(
    db: Session, username: str, password: str
) -> Optional[models.User]:
    """
    Authenticate a user given username and password.

    Parameters
    ----------
    db : Session
        Database session.
    username : str
        Username provided by the client.
    password : str
        Plaintext password provided by the client.

    Returns
    -------
    Optional[User]
        The authenticated user if credentials are valid, otherwise None.
    """
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


# ---------- JWT helpers ----------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT access token.

    Parameters
    ----------
    data : dict
        Claims to embed in the token (e.g. 'sub', 'role', 'user_id').
    expires_delta : Optional[timedelta]
        Optional custom expiration interval.

    Returns
    -------
    str
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Resolve the current user from a JWT bearer token.

    Steps
    -----
    - Decode the JWT using the shared SECRET_KEY.
    - Extract the username and optional role.
    - Load the user from the database.
    - Optionally verify that the token role matches the database role.

    Parameters
    ----------
    token : str
        Bearer token from the Authorization header.
    db : Session
        Database session.

    Returns
    -------
    User
        The authenticated user.

    Raises
    ------
    HTTPException
        If the token is invalid, expired, or the user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_role: Optional[str] = payload.get("role")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception

    # Optional consistency check between token role and DB role
    if token_role is not None:
        try:
            token_role_enum = models.UserRole(token_role)
        except ValueError:
            # Token has an invalid role
            raise credentials_exception
        if token_role_enum != user.role:
            raise credentials_exception

    return user


# ---------- RBAC helper ----------

def require_roles(allowed_roles: List[models.UserRole]):
    """
    Build a dependency that enforces role-based access control.

    Parameters
    ----------
    allowed_roles : List[UserRole]
        Roles that are allowed to access the protected endpoint.

    Returns
    -------
    Callable
        A FastAPI dependency that verifies the current user's role
        and raises HTTP 403 if not permitted.
    """

    async def dependency(current_user: models.User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for this role",
            )
        return current_user

    return dependency
