from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Enum

from .database import Base


class UserRole(str, PyEnum):
    """
    Enumeration of all supported user roles in the system.

    Roles
    -----
    admin
        Full administrative privileges across all services.
    regular
        Standard end user with access to their own data and bookings.
    facility_manager
        Power user for rooms and bookings (inventory/space management).
    moderator
        Lightweight review administrator with moderation rights.
    auditor
        Read-only user for compliance and auditing.
    service_account
        Non-human account used for inter-service communication.
    """
    ADMIN = "admin"
    REGULAR = "regular"
    FACILITY_MANAGER = "facility_manager"
    MODERATOR = "moderator"
    AUDITOR = "auditor"
    SERVICE_ACCOUNT = "service_account"


class User(Base):
    """
    SQLAlchemy model for application users.

    This model stores authentication and authorization information
    such as username, hashed password, and role.

    Attributes
    ----------
    id : int
        Primary key.
    name : str
        Full display name of the user.
    username : str
        Unique username used for login.
    email : str
        Unique email address of the user.
    hashed_password : str
        Bcrypt-hashed password.
    role : UserRole
        Role controlling access privileges.
    is_active : bool
        Flag indicating whether the user is active.
    created_at : datetime
        Timestamp of user creation.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.REGULAR)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
