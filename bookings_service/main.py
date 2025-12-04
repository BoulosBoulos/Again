from datetime import datetime
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status, Request, APIRouter
from fastapi.responses import JSONResponse

from sqlalchemy.orm import Session
from .rate_limiter import booking_rate_limiter

from common.cache import delete_prefix


from . import models, schemas
from .auth import get_current_user_claims, require_roles
from .database import Base, engine, get_db

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Bookings Service", version="1.0.0")
router_v1 = APIRouter(prefix="/api/v1")

SERVICE_NAME = "bookings"


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


@app.get("/")
def root():
    """
    Health-check endpoint for the Bookings service.

    Returns
    -------
    dict
        A small JSON payload indicating that the service is running.
    """
    return {"service": "bookings", "status": "running"}


admin_facility_or_auditor = require_roles(
    "admin",
    "facility_manager",
    "auditor",
    "service_account",  # internal read-only access
)

availability_roles = require_roles(
    "admin",
    "regular",
    "facility_manager",
    "auditor",
    "service_account",  # used by Rooms/Users services for inter-service checks
)


def ensure_time_valid(start_time: datetime, end_time: datetime):
    """
    Validate that a booking time range is well-formed.

    Parameters
    ----------
    start_time : datetime
        Start of the requested booking.
    end_time : datetime
        End of the requested booking.

    Raises
    ------
    HTTPException
        If end_time is not strictly after start_time.
    """
    if end_time <= start_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end_time must be after start_time",
        )


def has_conflict(
    db: Session,
    room_id: int,
    start_time: datetime,
    end_time: datetime,
    ignore_booking_id: Optional[int] = None,
) -> bool:
    """
    Check if there is any overlapping booking on the same room.

    Overlaps are detected for all bookings in the given room where:
    - status != CANCELLED
    - existing.end_time > start_time
    - existing.start_time < end_time

    Parameters
    ----------
    db : Session
        Database session.
    room_id : int
        Room identifier.
    start_time : datetime
        Proposed start time.
    end_time : datetime
        Proposed end time.
    ignore_booking_id : Optional[int]
        If provided, ignore this booking (useful when updating).

    Returns
    -------
    bool
        True if there is at least one conflicting booking, False otherwise.
    """
    q = (
        db.query(models.Booking)
        .filter(models.Booking.room_id == room_id)
        .filter(models.Booking.status != models.BookingStatus.CANCELLED)
        .filter(models.Booking.end_time > start_time)
        .filter(models.Booking.start_time < end_time)
    )

    if ignore_booking_id is not None:
        q = q.filter(models.Booking.id != ignore_booking_id)

    return db.query(q.exists()).scalar()


# ---------- Check room availability ----------


@router_v1.get("/bookings/availability")
def check_availability(
    room_id: int,
    start_time: datetime,
    end_time: datetime,
    db: Session = Depends(get_db),
    _: Dict = Depends(availability_roles),
):
    """
    Check if a room is available during a given time range.

    Access
    ------
    - Allowed roles: admin, regular, facility_manager, auditor, service_account.
    - Moderator is not allowed to call this endpoint.

    Parameters
    ----------
    room_id : int
        Room to check.
    start_time : datetime
        Start of the desired interval (ISO 8601).
    end_time : datetime
        End of the desired interval (ISO 8601).
    db : Session
        Database session.

    Returns
    -------
    dict
        JSON object with:
        - 'room_id' : int
        - 'available' : bool

    Raises
    ------
    HTTPException
        If the time range is invalid.
    """
    ensure_time_valid(start_time, end_time)
    busy = has_conflict(db, room_id, start_time, end_time)
    return {
        "room_id": room_id,
        "available": not busy,
    }


# ---------- Create booking (regular / power users) ----------


@router_v1.post(
    "/bookings",
    response_model=schemas.BookingRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(booking_rate_limiter)],
)
def create_booking(
    booking_in: schemas.BookingCreate,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    """
    Create a new booking for the authenticated user.

    Access
    ------
    - Allowed for: regular, admin, facility_manager.
    - Denied for roles: auditor, moderator, service_account.

    Behavior
    --------
    - Validates that the time range is correct.
    - Rejects bookings that overlap with existing non-cancelled bookings.
    - Uses the user_id from the JWT claims as the booking owner.

    Parameters
    ----------
    booking_in : BookingCreate
        Room and time information for the new booking.
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims (user_id, role, etc.).

    Returns
    -------
    BookingRead
        The newly created booking.

    Raises
    ------
    HTTPException
        If the user role is not allowed, the time range is invalid,
        or the room is already booked.
    """
    # ❗ Roles that cannot create bookings: auditor, moderator, service accounts
    if claims["role"] in ("auditor", "moderator", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot create bookings",
        )

    ensure_time_valid(booking_in.start_time, booking_in.end_time)

    if has_conflict(
        db,
        booking_in.room_id,
        booking_in.start_time,
        booking_in.end_time,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Room is already booked for this time range",
        )

    booking = models.Booking(
        user_id=claims["user_id"],
        room_id=booking_in.room_id,
        start_time=booking_in.start_time,
        end_time=booking_in.end_time,
        status=models.BookingStatus.CONFIRMED,
    )
    db.add(booking)
    db.commit()
    db.refresh(booking)
    delete_prefix("rooms:availability:")
    return booking


# ---------- My bookings (current user) ----------


@router_v1.get("/bookings/me", response_model=List[schemas.BookingRead])
def list_my_bookings(
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    """
    List bookings that belong to the authenticated user.

    Access
    ------
    - Allowed for: admin, facility_manager, regular.
    - Denied for: auditor, moderator, service_account.

    Parameters
    ----------
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims containing the current user's ID.

    Returns
    -------
    List[BookingRead]
        Bookings for the current user, ordered by start_time descending.
    """
    # Only admin, facility_manager, and regular users can have personal bookings
    if claims["role"] not in ("admin", "facility_manager", "regular"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot have personal bookings",
        )
    user_id = claims["user_id"]
    bookings = (
        db.query(models.Booking)
        .filter(models.Booking.user_id == user_id)
        .order_by(models.Booking.start_time.desc())
        .all()
    )
    return bookings


# ---------- Admin / facility / auditor / service: list all bookings ----------


@router_v1.get("/bookings", response_model=List[schemas.BookingRead])
def list_all_bookings(
    room_id: Optional[int] = Query(default=None, ge=1),
    user_id: Optional[int] = Query(default=None, ge=1),
    db: Session = Depends(get_db),
    _: Dict = Depends(admin_facility_or_auditor),
):
    """
    Admin/Facility/Auditor/Service Account: view all bookings with optional filters.

    Access
    ------
    - Allowed roles: admin, facility_manager, auditor, service_account.

    Parameters
    ----------
    room_id : Optional[int]
        If provided, filter bookings for a specific room.
    user_id : Optional[int]
        If provided, filter bookings for a specific user.
    db : Session
        Database session.

    Returns
    -------
    List[BookingRead]
        List of bookings matching the filters, ordered by start_time descending.
    """
    q = db.query(models.Booking)

    if room_id is not None:
        q = q.filter(models.Booking.room_id == room_id)

    if user_id is not None:
        q = q.filter(models.Booking.user_id == user_id)

    return q.order_by(models.Booking.start_time.desc()).all()


# ---------- Update booking (time/room/status) ----------


@router_v1.put("/bookings/{booking_id}", response_model=schemas.BookingRead, dependencies=[Depends(booking_rate_limiter)])
def update_booking(
    booking_id: int,
    update_data: schemas.BookingUpdate,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    """
    Update an existing booking's room, time, or status.

    Access
    ------
    - Owner of the booking.
    - Admin for any booking.
    - Auditor, moderator, and service_account cannot modify bookings.

    Behavior
    --------
    - Applies only the fields provided in BookingUpdate.
    - Re-validates the final time range.
    - Ensures no conflicts with other non-cancelled bookings.
    - Optionally updates the booking status.

    Parameters
    ----------
    booking_id : int
        ID of the booking to update.
    update_data : BookingUpdate
        Partial update data for the booking.
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims.

    Returns
    -------
    BookingRead
        The updated booking.

    Raises
    ------
    HTTPException
        If the booking is not found, the user is not allowed,
        the time range is invalid, or there is a conflict.
    """
    if claims["role"] in ("auditor", "moderator", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot modify bookings",
        )
    booking = db.query(models.Booking).filter(models.Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Booking not found",
        )

    is_admin = claims["role"] == "admin"
    is_owner = booking.user_id == claims["user_id"]

    # Admin can update any booking; others only their own
    if not (is_admin or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to update this booking",
        )

    # Determine new values (fallback to existing ones if not provided)
    new_room_id = (
        update_data.room_id if update_data.room_id is not None else booking.room_id
    )
    new_start_time = (
        update_data.start_time
        if update_data.start_time is not None
        else booking.start_time
    )
    new_end_time = (
        update_data.end_time if update_data.end_time is not None else booking.end_time
    )

    # Validate time
    ensure_time_valid(new_start_time, new_end_time)

    # Check for conflicts (ignore this booking itself)
    if has_conflict(
        db,
        room_id=new_room_id,
        start_time=new_start_time,
        end_time=new_end_time,
        ignore_booking_id=booking.id,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Room is already booked for this time range",
        )

    # Apply updates
    booking.room_id = new_room_id
    booking.start_time = new_start_time
    booking.end_time = new_end_time

    if update_data.status is not None:
        booking.status = update_data.status

    db.add(booking)
    db.commit()
    db.refresh(booking)
    return booking


# ---------- Cancel booking (soft) ----------


@router_v1.delete("/bookings/{booking_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(booking_rate_limiter)])
def cancel_booking(
    booking_id: int,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    """
    Cancel (soft-delete) an existing booking.

    Access
    ------
    - Owner of the booking.
    - Admin for any booking.
    - Auditor, moderator, and service_account cannot cancel bookings.

    Behavior
    --------
    - Sets the booking status to CANCELLED.
    - Does not physically delete the record.

    Parameters
    ----------
    booking_id : int
        ID of the booking to cancel.
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims.

    Returns
    -------
    None

    Raises
    ------
    HTTPException
        If the booking does not exist or the user is not allowed.
    """
    # ❗ block read-only / service accounts
    if claims["role"] in ("auditor", "moderator", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot cancel bookings",
        )
    booking = db.query(models.Booking).filter(models.Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Booking not found",
        )

    is_admin = claims["role"] == "admin"
    is_owner = booking.user_id == claims["user_id"]

    # Admin can cancel any; others only their own
    if not (is_admin or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to cancel this booking",
        )

    booking.status = models.BookingStatus.CANCELLED
    db.add(booking)
    db.commit()
    delete_prefix("rooms:availability:")
    return

app.include_router(router_v1)
