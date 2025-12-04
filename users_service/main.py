from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import Depends, FastAPI, HTTPException, status, Request, APIRouter
from fastapi.responses import JSONResponse

from .circuit_breaker import bookings_circuit_breaker
from .rate_limiter import ip_rate_limiter

from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from common.cache import get_cached_json, set_cached_json, delete_prefix


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
SERVICE_NAME = "users"
router_v1 = APIRouter(prefix="/api/v1")

BOOKINGS_SERVICE_URL = os.getenv(
    "BOOKINGS_SERVICE_URL",
    "http://bookings_service:8002",  # Docker internal hostname:port
)

SERVICE_ACCOUNT_USERNAME = "users_service"
SERVICE_ACCOUNT_USER_ID = 0        # "fake" ID for the service account
SERVICE_ACCOUNT_ROLE = "service_account"   # least-privilege

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "service": SERVICE_NAME,
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": exc.detail,
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Optional: log exc here later
    return JSONResponse(
        status_code=500,
        content={
            "service": SERVICE_NAME,
            "path": request.url.path,
            "method": request.method,
            "status_code": 500,
            "detail": "Internal server error",
        },
    )

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

@router_v1.post(
    "/users/register",
    response_model=schemas.UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(ip_rate_limiter)],
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

@router_v1.post("/users/login", response_model=schemas.Token, dependencies=[Depends(ip_rate_limiter)])
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

@router_v1.get("/users/me", response_model=schemas.UserRead)
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


@router_v1.put("/users/me", response_model=schemas.UserRead)
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


@router_v1.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_my_account(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Delete the authenticated user's own account.

    Restrictions
    -----------
    - AUDITOR, MODERATOR and SERVICE_ACCOUNT roles cannot delete accounts.
    - The last active ADMIN cannot delete their own account.

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
        - 403: If user role is read-only (AUDITOR, MODERATOR, SERVICE_ACCOUNT).
        - 400: If attempting to delete the last active admin user.
    """
    
    # ❗ block read-only / service accounts
    if current_user.role in (
        UserRole.AUDITOR,
        UserRole.SERVICE_ACCOUNT,
        UserRole.MODERATOR,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read-only users cannot delete accounts",
        )

    # ❗ do not allow deleting the last admin
    if current_user.role == UserRole.ADMIN:
        other_admins_count = (
            db.query(models.User)
            .filter(
                models.User.role == UserRole.ADMIN,
                models.User.id != current_user.id,
                # if you have is_active, keep this; otherwise remove this line:
                # models.User.is_active.is_(True),
            )
            .count()
        )
        if other_admins_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last active admin user."
                       "Create another admin first.",
            )

    db.delete(current_user)
    db.commit()
    return
# ---------- helpers ----------

admin_only = require_roles([UserRole.ADMIN])
admin_or_auditor = require_roles([UserRole.ADMIN, UserRole.AUDITOR])


# ---------- Admin: list users, get by username, delete ----------

@router_v1.get("/users", response_model=List[schemas.UserRead])
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


@router_v1.get("/users/{username}", response_model=schemas.UserRead)
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

    cache_key = f"user:username:{username}"
    cached = get_cached_json(cache_key)
    if cached is not None:
        return cached
    user = (
        db.query(models.User)
        .filter(models.User.username == username)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    
    data = schemas.UserRead.model_validate(user).model_dump()
    set_cached_json(cache_key, data, ttl_seconds=300)
    return user


@router_v1.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
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
    # After successfully updating or deleting user
    delete_prefix(f"user:{user_id}")

    return


@router_v1.put("/users/{user_id}/role", response_model=schemas.UserRead)
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

@router_v1.post("/users/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
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

@router_v1.get("/users/{user_id}/booking-history")
def get_user_booking_history(
    user_id: int,
    current_user: models.User = Depends(get_current_user),
):
    ...
    # RBAC checks (as you already have)
    if current_user.role in (UserRole.ADMIN, UserRole.AUDITOR, UserRole.FACILITY_MANAGER):
        pass
    elif current_user.role == UserRole.REGULAR and current_user.id == user_id:
        pass
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to view booking history for this user",
        )

    # ---- CIRCUIT BREAKER CHECK ----
    if not bookings_circuit_breaker.allow_request():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bookings service temporarily unavailable (circuit open)",
        )

    token = make_service_account_token()
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = httpx.get(
            f"{BOOKINGS_SERVICE_URL}/api/v1/bookings",
            params={"user_id": user_id},
            headers=headers,
            timeout=5.0,
        )
    except httpx.RequestError:
        # record failure and raise
        bookings_circuit_breaker.record_failure()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to contact bookings service",
        )

    if response.status_code != 200:
        bookings_circuit_breaker.record_failure()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Bookings service returned an error",
        )

    # success
    bookings_circuit_breaker.record_success()
    bookings = response.json()
    return {
        "user_id": user_id,
        "bookings": bookings,
    }



@router_v1.put("/users/{user_id}", response_model=schemas.UserRead)
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

app.include_router(router_v1)

