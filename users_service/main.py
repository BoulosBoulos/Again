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
SERVICE_ACCOUNT_ROLE = "service_account"   # least-privilege

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

    """
    Validate password complexity rules.

    A valid password must:
    - Be at least 8 characters long
    - Contain at least one letter
    - Contain at least one digit

    Parameters
    ----------
    password : str
        The raw password submitted by the user.

    Raises
    ------
    HTTPException
        If the password does not meet the strength requirements.
    """
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
    """
    Register a new user.

    Behavior:
    - First account created becomes ADMIN.
    - All subsequent public registrations become REGULAR users.
    - Username and email must be unique.
    - Password strength is validated before hashing.

    Parameters
    ----------
    user_in : UserCreate
        Incoming registration data.
    db : Session
        Database session.

    Returns
    -------
    UserRead
        The newly created user.

    Raises
    ------
    HTTPException
        If username/email already exist or password is weak.
    """
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
    """
    Authenticate a user and return a JWT access token.

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm
        Login credentials (username + password).
    db : Session
        Database session.

    Returns
    -------
    Token
        Access token with role and user_id embedded.

    Raises
    ------
    HTTPException
        If authentication fails.
    """

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
    """
    Retrieve the authenticated user's own profile.

    Parameters
    ----------
    current_user : User
        Extracted from JWT token.

    Returns
    -------
    UserRead
        The profile of the authenticated user.
    """
    return current_user


@app.put("/users/me", response_model=schemas.UserRead)
def update_my_profile(
    update_data: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Update the authenticated user's profile.

    Editable fields:
    - name
    - email (must be unique)

    Restrictions:
    - AUDITOR and SERVICE_ACCOUNT roles cannot update profiles.

    Parameters
    ----------
    update_data : UserUpdate
        Fields to update.
    db : Session
        Database session.
    current_user : User
        The authenticated user.

    Returns
    -------
    UserRead
        Updated user profile.

    Raises
    ------
    HTTPException
        If email already exists or role is read-only.
    """
    # block read-only / service accounts
    if current_user.role in (UserRole.AUDITOR, UserRole.SERVICE_ACCOUNT, UserRole.MODERATOR):
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
    """
    Delete the authenticated user's own account.

    Restrictions
    -----------
    - AUDITOR and SERVICE_ACCOUNT roles cannot delete accounts.

    Parameters
    ----------
    db : Session
        Database session.
    current_user : User
        The user executing the delete operation.

    Returns
    -------
    None

    Raises
    ------
    HTTPException
        If user role is read-only.
    """
    # ❗ block read-only / service accounts
    if current_user.role in (UserRole.AUDITOR, UserRole.SERVICE_ACCOUNT, UserRole.MODERATOR):
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
    """
    Admin/Auditor: Retrieve all users.

    Parameters
    ----------
    db : Session
        Database session.

    Returns
    -------
    List[UserRead]
        All registered users.

    Raises
    ------
    HTTPException
        If caller does not have ADMIN or AUDITOR role.
    """
    users = db.query(models.User).all()
    return users


@app.get("/users/{username}", response_model=schemas.UserRead)
def get_user_by_username_admin(
    username: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_or_auditor),
):
    """
    Admin/Auditor: Retrieve a specific user by username.

    Parameters
    ----------
    username : str
        Username to search for.
    db : Session
        Database session.

    Returns
    -------
    UserRead
        Matching user.

    Raises
    ------
    HTTPException
        If user does not exist.
    """
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
    """
    Admin only: Delete any user by ID.

    Parameters
    ----------
    user_id : int
        ID of the user to delete.
    db : Session
        Database session.

    Returns
    -------
    None

    Raises
    ------
    HTTPException
        If user is not found.
    """
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
    """
    Admin only: Update a user's role.

    Parameters
    ----------
    user_id : int
        User to modify.
    role_update : UserRoleUpdate
        New role to assign.
    db : Session
        Database session.

    Returns
    -------
    UserRead
        Updated user with new role.

    Raises
    ------
    HTTPException
        If user does not exist.
    """
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
    Admin: Reset another user's password.

    Validates password strength before hashing.

    Parameters
    ----------
    user_id : int
        ID of the user whose password is being reset.
    body : PasswordReset
        Contains the new password.
    db : Session
        Database session.

    Returns
    -------
    None

    Raises
    ------
    HTTPException
        If user does not exist or password is weak.
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
    Retrieve a user's full booking history via the Bookings service.

    Access Rules
    ------------
    - Admin & Auditor: may view any user's history.
    - Regular user: may view only their own history.

    Implementation Notes
    --------------------
    - Generates a service-account JWT.
    - Calls Bookings service: GET /bookings?user_id=<id>

    Parameters
    ----------
    user_id : int
        User whose history is requested.
    current_user : User
        Requesting user.

    Returns
    -------
    dict
        { "user_id": int, "bookings": list }

    Raises
    ------
    HTTPException
        If unauthorized or Bookings service errors.
    """
    # RBAC: only self OR admin/auditor
    if current_user.role in (UserRole.ADMIN, UserRole.AUDITOR, UserRole.FACILITY_MANAGER):
        pass  # can view any user
    elif current_user.role == UserRole.REGULAR and current_user.id == user_id:
        pass  # own history
    else:
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not allowed to view booking history for this user",
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

@app.put("/users/{user_id}", response_model=schemas.UserRead)
def admin_update_user(
    user_id: int,
    update_data: schemas.UserUpdate,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_only),
):
    """
    Admin only: Update another user's profile information.

    Editable fields:
    - name
    - email (must remain unique in the system)

    Parameters
    ----------
    user_id : int
        ID of the user to update.
    update_data : UserUpdate
        Fields to modify (name and/or email).
    db : Session
        Database session.

    Returns
    -------
    UserRead
        Updated user record.

    Raises
    ------
    HTTPException
        If user is not found or new email is already taken.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if update_data.name is not None:
        user.name = update_data.name

    if update_data.email is not None and update_data.email != user.email:
        email_owner = (
            db.query(models.User)
            .filter(models.User.email == update_data.email)
            .first()
        )
        if email_owner and email_owner.id != user.id:
            raise HTTPException(
                status_code=400,
                detail="Email already in use",
            )
        user.email = update_data.email

    db.add(user)
    db.commit()
    db.refresh(user)
    return user

