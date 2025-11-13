from datetime import timedelta
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

# Create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Users Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "users", "status": "running"}


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

    hashed_pw = get_password_hash(user_in.password)
    user = models.User(
        name=user_in.name,
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_pw,
        role=user_in.role,
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
    if update_data.name is not None:
        current_user.name = update_data.name
    if update_data.email is not None:
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
    db.delete(current_user)
    db.commit()
    return


# ---------- Admin-only helpers ----------

admin_only = require_roles([UserRole.ADMIN])


# ---------- Admin: list users, get by username, delete ----------

@app.get("/users", response_model=List[schemas.UserRead])
def list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_only),
):
    users = db.query(models.User).all()
    return users


@app.get("/users/{username}", response_model=schemas.UserRead)
def get_user_by_username_admin(
    username: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_only),
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


# ---------- Booking history (stub for now) ----------

@app.get("/users/{user_id}/booking-history")
def get_user_booking_history(
    user_id: int,
    current_user: models.User = Depends(get_current_user),
):
    """
    View booking history for a user.

    - Regular user: can only see their own history.
    - Admin: can see any user's history.
    """
    if current_user.role != UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to view other users' booking history",
        )

    # TODO: integrate with Bookings service.
    return {
        "user_id": user_id,
        "bookings": [],
        "note": "Booking history integration with Bookings service not implemented yet.",
    }
