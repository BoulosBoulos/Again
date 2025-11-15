from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import models, schemas
from .auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    get_current_user,
    get_password_hash,
    require_roles,
)
from .database import Base, engine, get_db
from .models import UserRole
import re, os, httpx
from jose import jwt
from .auth import SECRET_KEY, ALGORITHM

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Users Service", version="1.0.0")

BOOKINGS_SERVICE_URL = os.getenv(
    "BOOKINGS_SERVICE_URL",
    "http://bookings_service:8002",  # Docker internal hostname:port
)

SERVICE_ACCOUNT_USERNAME = "users_service"
SERVICE_ACCOUNT_USER_ID = 0        # "fake" ID for the service account
SERVICE_ACCOUNT_ROLE = "auditor"   # allowed to call GET /bookings

def make_service_account_token() -> str:
    payload = {
        "sub": SERVICE_ACCOUNT_USERNAME,
        "role": SERVICE_ACCOUNT_ROLE,
        "user_id": SERVICE_ACCOUNT_USER_ID,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


@app.get("/")
def root():
    return {"service": "users", "status": "running"}


# ---------- Password Strength ----------

def validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long",
        )
    if not re.search(r"[A-Za-z]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one letter",
        )
    if not re.search(r"\d", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit",
        )
    
# ---------- Registration ----------

@app.post(
    "/users/register",
    response_model=schemas.UserRead,
    status_code=status.HTTP_201_CREATED,
)
def register_user(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check unique username/email
    existing = (
        db.query(models.User)
        .filter(
            (models.User.username == user_in.username)
            | (models.User.email == user_in.email)
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists",
        )

    # --- Bootstrap admin + secure default roles ---
    user_count = db.query(models.User).count()
    if user_count == 0:
        # first ever account → admin
        assigned_role = UserRole.ADMIN
    else:
        # all public registrations → regular
        assigned_role = UserRole.REGULAR

    # enforce password strength
    validate_password_strength(user_in.password)
    hashed_pw = get_password_hash(user_in.password)
    user = models.User(
        name=user_in.name,
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_pw,
        role=assigned_role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# ---------- Login (token) ----------

@app.post("/users/login", response_model=schemas.Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Store role as string in the token (user.role.value)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role.value,
            "user_id": user.id, 
        },
        expires_delta=access_token_expires,
    )

    return {"access_token": access_token, "token_type": "bearer"}


# ---------- Current user profile (Regular user) ----------

@app.get("/users/me", response_model=schemas.UserRead)
def get_my_profile(current_user: models.User = Depends(get_current_user)):
    return current_user


@app.put("/users/me", response_model=schemas.UserRead)
def update_my_profile(
    update_data: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # block read-only / service accounts
    if current_user.role in (UserRole.AUDITOR, UserRole.SERVICE_ACCOUNT):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read-only users cannot modify profiles",
        )

    if update_data.name is not None:
        current_user.name = update_data.name

    if update_data.email is not None and update_data.email != current_user.email:
        # check if email is already used by another user
        email_owner = (
            db.query(models.User)
            .filter(models.User.email == update_data.email)
            .first()
        )
        if email_owner and email_owner.id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use",
            )
        current_user.email = update_data.email

    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user


@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_my_account(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # ❗ block read-only / service accounts
    if current_user.role in (UserRole.AUDITOR, UserRole.SERVICE_ACCOUNT):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read-only users cannot delete accounts",
        )

    db.delete(current_user)
    db.commit()
    return

# ---------- helpers ----------

admin_only = require_roles([UserRole.ADMIN])
admin_or_auditor = require_roles([UserRole.ADMIN, UserRole.AUDITOR])


# ---------- Admin: list users, get by username, delete ----------

@app.get("/users", response_model=List[schemas.UserRead])
def list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_or_auditor),
):
    users = db.query(models.User).all()
    return users


@app.get("/users/{username}", response_model=schemas.UserRead)
def get_user_by_username_admin(
    username: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_or_auditor),
):
    user = (
        db.query(models.User)
        .filter(models.User.username == username)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user


@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_admin(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_only),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    db.delete(user)
    db.commit()
    return


@app.put("/users/{user_id}/role", response_model=schemas.UserRead)
def change_user_role(
    user_id: int,
    role_update: schemas.UserRoleUpdate,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_only),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    user.role = role_update.role
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/users/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_user_password(
    user_id: int,
    body: schemas.PasswordReset,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_only),
):
    """
    Admin: reset a user's password.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    validate_password_strength(body.new_password)
    user.hashed_password = get_password_hash(body.new_password)
    db.add(user)
    db.commit()
    return


# ---------- Booking history (stub for now) ----------

@app.get("/users/{user_id}/booking-history")
def get_user_booking_history(
    user_id: int,
    current_user: models.User = Depends(get_current_user),
):
    """
    View booking history for a user.

    - Regular user: can only see their own history.
    - Admin/Auditor: can see any user's history.

    This endpoint delegates to the Bookings service.
    """
    # RBAC: only self OR admin/auditor
    if current_user.role not in (UserRole.ADMIN, UserRole.AUDITOR) and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to view other users' booking history",
        )

    token = make_service_account_token()
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = httpx.get(
            f"{BOOKINGS_SERVICE_URL}/bookings",
            params={"user_id": user_id},
            headers=headers,
            timeout=5.0,
        )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to contact bookings service",
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Bookings service returned an error",
        )

    bookings = response.json()
    return {
        "user_id": user_id,
        "bookings": bookings,
    }
