from typing import List, Optional
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import models, schemas
from .auth import require_roles
from .database import Base, engine, get_db

import os
import httpx

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Rooms Service", version="1.0.0")

BOOKINGS_SERVICE_URL = os.getenv(
    "BOOKINGS_SERVICE_URL",
    "http://bookings_service:8002",  # Docker internal URL
)


@app.get("/")
def root():
    """
    Health-check endpoint for the Rooms service.

    Returns
    -------
    dict
        A small JSON payload indicating that the service is running.
    """
    return {"service": "rooms", "status": "running"}


admin_or_facility = require_roles("admin", "facility_manager")


# ---------- Create room ----------


@app.post("/rooms", response_model=schemas.RoomRead, status_code=status.HTTP_201_CREATED)
def create_room(
    room_in: schemas.RoomCreate,
    db: Session = Depends(get_db),
    _: dict = Depends(admin_or_facility),
):
    """
    Create a new meeting room.

    Access
    ------
    - Allowed roles: admin, facility_manager.

    Behavior
    --------
    - Ensures that the room name is unique.
    - Stores capacity, equipment list, and location.

    Parameters
    ----------
    room_in : RoomCreate
        New room details.
    db : Session
        Database session.

    Returns
    -------
    RoomRead
        The created room.

    Raises
    ------
    HTTPException
        If a room with the same name already exists.
    """
    # ensure unique name
    existing = db.query(models.Room).filter(models.Room.name == room_in.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Room with this name already exists",
        )

    room = models.Room(
        name=room_in.name,
        capacity=room_in.capacity,
        equipment=room_in.equipment,
        location=room_in.location,
    )
    db.add(room)
    db.commit()
    db.refresh(room)
    return room


# ---------- List / search rooms ----------


@app.get("/rooms", response_model=List[schemas.RoomRead])
def list_rooms(
    min_capacity: Optional[int] = Query(default=None, ge=1),
    location: Optional[str] = None,
    equipment_contains: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Retrieve available rooms with optional filters.

    Behavior
    --------
    - Only returns rooms that are active and not out of service.
    - Supports filtering by:
      * minimum capacity
      * location substring
      * equipment substring (e.g. 'projector').

    Parameters
    ----------
    min_capacity : Optional[int]
        Minimum room capacity.
    location : Optional[str]
        Substring to match in the location field.
    equipment_contains : Optional[str]
        Substring to match in the equipment field.
    db : Session
        Database session.

    Returns
    -------
    List[RoomRead]
        List of rooms matching the filters.
    """
    query = db.query(models.Room).filter(models.Room.is_active.is_(True))

    if min_capacity is not None:
        query = query.filter(models.Room.capacity >= min_capacity)

    if location:
        query = query.filter(models.Room.location.ilike(f"%{location}%"))

    if equipment_contains:
        query = query.filter(models.Room.equipment.ilike(f"%{equipment_contains}%"))

    # Exclude out-of-service rooms from "available" search
    query = query.filter(models.Room.is_out_of_service.is_(False))

    return query.all()


@app.get("/rooms/{room_id}", response_model=schemas.RoomRead)
def get_room(room_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a single room by its ID.

    Parameters
    ----------
    room_id : int
        Identifier of the room.
    db : Session
        Database session.

    Returns
    -------
    RoomRead
        The requested room.

    Raises
    ------
    HTTPException
        If the room does not exist or is inactive.
    """
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room or not room.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    return room


# ---------- Update / delete rooms (admin or facility manager) ----------


@app.put("/rooms/{room_id}", response_model=schemas.RoomRead)
def update_room(
    room_id: int,
    update_data: schemas.RoomUpdate,
    db: Session = Depends(get_db),
    _: dict = Depends(admin_or_facility),
):
    """
    Update an existing room.

    Access
    ------
    - Allowed roles: admin, facility_manager.

    Behavior
    --------
    - Allows updating name, capacity, equipment, location, and out-of-service flag.
    - Ensures that the new name (if changed) remains unique.

    Parameters
    ----------
    room_id : int
        ID of the room to update.
    update_data : RoomUpdate
        Fields to update.
    db : Session
        Database session.

    Returns
    -------
    RoomRead
        The updated room.

    Raises
    ------
    HTTPException
        If the room is not found or the new name conflicts with another room.
    """
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room or not room.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    if update_data.name is not None and update_data.name != room.name:
        existing = (
            db.query(models.Room)
            .filter(models.Room.name == update_data.name)
            .first()
        )
        if existing and existing.id != room.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Room with this name already exists",
            )
        room.name = update_data.name

    if update_data.capacity is not None:
        room.capacity = update_data.capacity
    if update_data.equipment is not None:
        room.equipment = update_data.equipment
    if update_data.location is not None:
        room.location = update_data.location
    if update_data.is_out_of_service is not None:
        room.is_out_of_service = update_data.is_out_of_service

    db.add(room)
    db.commit()
    db.refresh(room)
    return room


@app.delete("/rooms/{room_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_room(
    room_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(admin_or_facility),
):
    """
    Soft-delete a room by marking it inactive.

    Access
    ------
    - Allowed roles: admin, facility_manager.

    Behavior
    --------
    - Sets is_active = False so the room is excluded from listings.

    Parameters
    ----------
    room_id : int
        ID of the room to delete.
    db : Session
        Database session.

    Returns
    -------
    None

    Raises
    ------
    HTTPException
        If the room is not found or already inactive.
    """
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room or not room.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    # soft-delete: mark inactive
    room.is_active = False
    db.add(room)
    db.commit()
    return


# ---------- Room status (stub for now) ----------


@app.get("/rooms/{room_id}/status")
def room_status(
    room_id: int,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db),
):
    """
    Report the status of a room, optionally for a time range.

    Behavior
    --------
    - If the room is missing or inactive -> HTTP 404.
    - If the room is marked out_of_service -> status = "out_of_service".
    - If no time range is provided:
        * status = "available" (structural availability only).
    - If start_time and end_time are provided:
        * Validates that end_time > start_time.
        * Calls Bookings service `/bookings/availability`.
        * Returns:
            - "available" if the room is free in that interval.
            - "booked" if the room is occupied in that interval.

    Parameters
    ----------
    room_id : int
        ID of the room to check.
    start_time : Optional[datetime]
        Start of the time window (ISO 8601).
    end_time : Optional[datetime]
        End of the time window (ISO 8601).
    db : Session
        Database session.

    Returns
    -------
    dict
        JSON object with keys {'room_id', 'status'}.

    Raises
    ------
    HTTPException
        If the room does not exist, the time range is invalid,
        or the Bookings service cannot be reached.
    """
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room or not room.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Room not found",
        )

    if room.is_out_of_service:
        return {"room_id": room.id, "status": "out_of_service"}

    # No time range -> just structural availability
    if start_time is None or end_time is None:
        return {"room_id": room.id, "status": "available"}

    if end_time <= start_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end_time must be after start_time",
        )

    # Ask Bookings service about time-based availability
    try:
        resp = httpx.get(
            f"{BOOKINGS_SERVICE_URL}/bookings/availability",
            params={
                "room_id": room.id,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
            timeout=5.0,
        )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to contact bookings service for availability",
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Bookings service returned an error when checking availability",
        )

    data = resp.json()
    status_str = "available" if data.get("available") else "booked"

    return {"room_id": room.id, "status": status_str}
