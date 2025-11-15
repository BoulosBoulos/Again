from datetime import datetime
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import models, schemas
from .auth import get_current_user_claims, require_roles
from .database import Base, engine, get_db

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Bookings Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "bookings", "status": "running"}


admin_facility_or_auditor = require_roles("admin", "facility_manager", "auditor")


def ensure_time_valid(start_time: datetime, end_time: datetime):
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

    - Ignores bookings with status=CANCELLED
    - If ignore_booking_id is provided, exclude that booking (useful when updating)
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


@app.get("/bookings/availability")
def check_availability(
    room_id: int,
    start_time: datetime,
    end_time: datetime,
    db: Session = Depends(get_db),
):
    """
    Check if a room is available for a given time range.

    Returns: {"room_id": ..., "available": true/false}
    """
    ensure_time_valid(start_time, end_time)
    busy = has_conflict(db, room_id, start_time, end_time)
    return {
        "room_id": room_id,
        "available": not busy,
    }


# ---------- Create booking (regular user) ----------


@app.post(
    "/bookings",
    response_model=schemas.BookingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_booking(
    booking_in: schemas.BookingCreate,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
        # ❗ Auditor and service accounts are read-only / system-only
    if claims["role"] in ("auditor", "service_account"):
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
    return booking


# ---------- My bookings (current user) ----------


@app.get("/bookings/me", response_model=List[schemas.BookingRead])
def list_my_bookings(
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    """
    Return booking history for the currently authenticated user.
    """
    user_id = claims["user_id"]
    bookings = (
        db.query(models.Booking)
        .filter(models.Booking.user_id == user_id)
        .order_by(models.Booking.start_time.desc())
        .all()
    )
    return bookings


# ---------- Admin / facility: list all bookings ----------


@app.get("/bookings", response_model=List[schemas.BookingRead])
def list_all_bookings(
    room_id: Optional[int] = Query(default=None, ge=1),
    user_id: Optional[int] = Query(default=None, ge=1),
    db: Session = Depends(get_db),
    _: Dict = Depends(admin_facility_or_auditor),
):
    """
    Admin/facility_manager: view all bookings.

    Optional filters:
    - room_id
    - user_id (useful for per-user booking history)
    """
    q = db.query(models.Booking)

    if room_id is not None:
        q = q.filter(models.Booking.room_id == room_id)

    if user_id is not None:
        q = q.filter(models.Booking.user_id == user_id)

    return q.order_by(models.Booking.start_time.desc()).all()


# ---------- Update booking (time/room/status) ----------


@app.put("/bookings/{booking_id}", response_model=schemas.BookingRead)
def update_booking(
    booking_id: int,
    update_data: schemas.BookingUpdate,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    if claims["role"] in ("auditor", "service_account"):
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

    is_admin_or_facility = claims["role"] in ("admin", "facility_manager")
    is_owner = booking.user_id == claims["user_id"]

    if not (is_admin_or_facility or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to update this booking",
        )

    # Determine new values (fallback to existing ones if not provided)
    new_room_id = update_data.room_id if update_data.room_id is not None else booking.room_id
    new_start_time = update_data.start_time if update_data.start_time is not None else booking.start_time
    new_end_time = update_data.end_time if update_data.end_time is not None else booking.end_time

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


@app.delete("/bookings/{booking_id}", status_code=status.HTTP_204_NO_CONTENT)
def cancel_booking(
    booking_id: int,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    # ❗ block read-only / service accounts
    if claims["role"] in ("auditor", "service_account"):
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

    is_admin_or_facility = claims["role"] in ("admin", "facility_manager")
    is_owner = booking.user_id == claims["user_id"]

    if not (is_admin_or_facility or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to cancel this booking",
        )

    booking.status = models.BookingStatus.CANCELLED
    db.add(booking)
    db.commit()
    return
