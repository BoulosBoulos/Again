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
    return {"service": "rooms", "status": "running"}


admin_or_facility = require_roles("admin", "facility_manager")


# ---------- Create room ----------


@app.post("/rooms", response_model=schemas.RoomRead, status_code=status.HTTP_201_CREATED)
def create_room(
    room_in: schemas.RoomCreate,
    db: Session = Depends(get_db),
    _: dict = Depends(admin_or_facility),
):
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
    Retrieve available rooms.

    - Filter by min_capacity
    - Filter by location substring
    - Filter by equipment substring (e.g. 'projector')
    - Excludes rooms marked out_of_service
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
    Room status:

    - If room is inactive or not found -> 404
    - If room is out_of_service -> "out_of_service"
    - If no start_time/end_time -> structural status only: "available"
    - If time range provided:
        - Calls Bookings service /bookings/availability
        - Returns "available" or "booked" based on that
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
