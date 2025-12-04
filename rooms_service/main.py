from typing import List, Optional
from datetime import datetime, timedelta, timezone
from jose import jwt
from .auth import SECRET_KEY, ALGORITHM

from fastapi import Depends, FastAPI, HTTPException, Query, status, Request, APIRouter
from fastapi.responses import JSONResponse

from .circuit_breaker import bookings_circuit_breaker

from sqlalchemy.orm import Session

from common.cache import get_cached_json, set_cached_json, delete_prefix


from . import models, schemas
from .auth import require_roles
from .database import Base, engine, get_db

import os
import httpx

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Rooms Service", version="1.0.0")

router_v1 = APIRouter(prefix="/api/v1")

SERVICE_NAME = "rooms"

SERVICE_ACCOUNT_USERNAME = "rooms_service"
SERVICE_ACCOUNT_USER_ID = 0
SERVICE_ACCOUNT_ROLE = "service_account"

BOOKINGS_SERVICE_URL = os.getenv(
    "BOOKINGS_SERVICE_URL",
    "http://bookings_service:8002",  # Docker internal URL
)


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
    Health-check endpoint for the Rooms service.

    Returns
    -------
    dict
        A small JSON payload indicating that the service is running.
    """
    return {"service": "rooms", "status": "running"}


admin_or_facility = require_roles("admin", "facility_manager")

viewer_roles = require_roles(
    "admin",
    "regular",
    "facility_manager",
    "auditor",
    "service_account",  # for inter-service calls if needed
)

def make_service_account_token() -> str:
    payload = {
        "sub": SERVICE_ACCOUNT_USERNAME,
        "role": SERVICE_ACCOUNT_ROLE,
        "user_id": SERVICE_ACCOUNT_USER_ID,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ---------- Create room ----------


@router_v1.post("/rooms", response_model=schemas.RoomRead, status_code=status.HTTP_201_CREATED)
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


@router_v1.get("/rooms", response_model=List[schemas.RoomRead])
def list_rooms(
    min_capacity: Optional[int] = Query(default=None, ge=1),
    location: Optional[str] = None,
    equipment_contains: Optional[str] = None,
    db: Session = Depends(get_db),
    _: dict = Depends(viewer_roles),   # <- RBAC: who can view/search rooms
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
    cacheable = (
        min_capacity is None
        and not location
        and not equipment_contains
    )

    cache_key = "rooms:all"

    if cacheable:
        cached = get_cached_json(cache_key)
        if cached is not None:
            return cached
    query = db.query(models.Room).filter(models.Room.is_active.is_(True))

    if min_capacity is not None:
        query = query.filter(models.Room.capacity >= min_capacity)

    if location:
        query = query.filter(models.Room.location.ilike(f"%{location}%"))

    if equipment_contains:
        query = query.filter(models.Room.equipment.ilike(f"%{equipment_contains}%"))

    # Exclude out-of-service rooms from "available" search
    query = query.filter(models.Room.is_out_of_service.is_(False))

    if cacheable:
        data = [schemas.RoomRead.model_validate(r).model_dump() for r in rooms]
        set_cached_json(cache_key, data, ttl_seconds=60)
        return data

    return query.all()


@router_v1.get("/rooms/{room_id}", response_model=schemas.RoomRead)
def get_room(
    room_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(viewer_roles),   # <- RBAC: who can view room details
):
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
    cache_key = f"room:{room_id}"
    cached = get_cached_json(cache_key)
    if cached is not None:
        return cached
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room or not room.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    data = schemas.RoomRead.model_validate(room).model_dump()
    set_cached_json(cache_key, data, ttl_seconds=300)
    return room


# ---------- Update / delete rooms (admin or facility manager) ----------


@router_v1.put("/rooms/{room_id}", response_model=schemas.RoomRead)
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


@router_v1.delete("/rooms/{room_id}", status_code=status.HTTP_204_NO_CONTENT)
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


@router_v1.get("/rooms/{room_id}/status")
def room_status(
    room_id: int,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db),
    _: dict = Depends(viewer_roles),   # <- RBAC: who can view room status
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

    # Generate a short-lived service account token for inter-service call
    token = make_service_account_token()
    headers = {"Authorization": f"Bearer {token}"}

    # ---- CIRCUIT BREAKER CHECK ----
    if not bookings_circuit_breaker.allow_request():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bookings service temporarily unavailable (circuit open)",
        )

    try:
        resp = httpx.get(
            f"{BOOKINGS_SERVICE_URL}/api/v1/bookings/availability",
            params={
                "room_id": room.id,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
            headers=headers,
            timeout=5.0,
        )
    except httpx.RequestError:
        bookings_circuit_breaker.record_failure()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to contact bookings service for availability",
        )

    if resp.status_code != 200:
        bookings_circuit_breaker.record_failure()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Bookings service returned an error when checking availability",
        )

    bookings_circuit_breaker.record_success()

    data = resp.json()
    status_str = "available" if data.get("available") else "booked"

    return {"room_id": room.id, "status": status_str}

app.include_router(router_v1)
