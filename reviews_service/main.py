from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import models, schemas
from .auth import get_current_user_claims, require_roles
from .database import Base, engine, get_db

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Reviews Service", version="1.0.0")


@app.get("/")
def root():
    return {"service": "reviews", "status": "running"}


admin_or_moderator = require_roles("admin", "moderator")
admin_mod_or_auditor = require_roles("admin", "moderator", "auditor")


def get_review_or_404(db: Session, review_id: int) -> models.Review:
    review = db.query(models.Review).filter(models.Review.id == review_id).first()
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Review not found",
        )
    return review


# ---------- Create review (authenticated user) ----------


@app.post(
    "/reviews",
    response_model=schemas.ReviewRead,
    status_code=status.HTTP_201_CREATED,
)
def create_review(
    review_in: schemas.ReviewCreate,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    # ❗ no writes for auditor / service_account
    if claims["role"] in ("auditor", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot create reviews",
        )
    # Optional: prevent duplicate review per user/room
    existing = (
        db.query(models.Review)
        .filter(
            models.Review.user_id == claims["user_id"],
            models.Review.room_id == review_in.room_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have already reviewed this room",
        )

    review = models.Review(
        user_id=claims["user_id"],
        room_id=review_in.room_id,
        rating=review_in.rating,
        comment=review_in.comment,
    )
    db.add(review)
    db.commit()
    db.refresh(review)
    return review


# ---------- Public: list visible reviews for a room ----------


@app.get("/reviews/room/{room_id}", response_model=List[schemas.ReviewRead])
def list_room_reviews(
    room_id: int,
    db: Session = Depends(get_db),
):
    """
    Public endpoint: returns only non-hidden reviews for a room.
    """
    reviews = (
        db.query(models.Review)
        .filter(
            models.Review.room_id == room_id,
            models.Review.is_hidden.is_(False),
        )
        .order_by(models.Review.created_at.desc())
        .all()
    )
    return reviews


# ---------- Admin/moderator: list all reviews with filters ----------


@app.get("/reviews", response_model=List[schemas.ReviewRead])
def list_all_reviews(
    room_id: Optional[int] = Query(default=None, ge=1),
    user_id: Optional[int] = Query(default=None, ge=1),
    only_flagged: bool = False,
    include_hidden: bool = True,
    db: Session = Depends(get_db),
    _: Dict = Depends(admin_mod_or_auditor),
):
    """
    Admin/moderator view.

    Optional filters:
    - room_id
    - user_id
    - only_flagged
    - include_hidden (if False, hides hidden reviews)
    """
    q = db.query(models.Review)

    if room_id is not None:
        q = q.filter(models.Review.room_id == room_id)

    if user_id is not None:
        q = q.filter(models.Review.user_id == user_id)

    if only_flagged:
        q = q.filter(models.Review.is_flagged.is_(True))

    if not include_hidden:
        q = q.filter(models.Review.is_hidden.is_(False))

    return q.order_by(models.Review.created_at.desc()).all()


# ---------- Update review (owner or admin/moderator) ----------


@app.put("/reviews/{review_id}", response_model=schemas.ReviewRead)
def update_review(
    review_id: int,
    update_data: schemas.ReviewUpdate,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    # ❗ no writes for auditor / service_account
    if claims["role"] in ("auditor", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot modify reviews",
        )
    review = get_review_or_404(db, review_id)

    is_admin_or_mod = claims["role"] in ("admin", "moderator")
    is_owner = review.user_id == claims["user_id"]

    if not (is_admin_or_mod or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to update this review",
        )

    if update_data.rating is not None:
        review.rating = update_data.rating
    if update_data.comment is not None:
        review.comment = update_data.comment

    db.add(review)
    db.commit()
    db.refresh(review)
    return review


# ---------- Delete review (owner or admin/moderator) ----------


@app.delete("/reviews/{review_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_review(
    review_id: int,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    # ❗ no writes for auditor / service_account
    if claims["role"] in ("auditor", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot delete reviews",
        )

    review = get_review_or_404(db, review_id)

    is_admin_or_mod = claims["role"] in ("admin", "moderator")
    is_owner = review.user_id == claims["user_id"]

    if not (is_admin_or_mod or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to delete this review",
        )

    db.delete(review)
    db.commit()
    return


# ---------- Flag / hide / unhide ----------


@app.post("/reviews/{review_id}/flag", response_model=schemas.ReviewRead)
def flag_review(
    review_id: int,
    db: Session = Depends(get_db),
    claims: Dict = Depends(get_current_user_claims),
):
    """
    Any authenticated user can flag a review.
    """
    # ❗ no writes for auditor / service_account
    if claims["role"] in ("auditor", "service_account"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This role cannot flag reviews",
        )
    _ = claims  # ensure dependency runs
    review = get_review_or_404(db, review_id)

    review.is_flagged = True
    db.add(review)
    db.commit()
    db.refresh(review)
    return review


@app.post("/reviews/{review_id}/hide", response_model=schemas.ReviewRead)
def hide_review(
    review_id: int,
    db: Session = Depends(get_db),
    _: Dict = Depends(admin_or_moderator),
):
    """
    Admin/moderator can hide a review from public room view.
    """
    review = get_review_or_404(db, review_id)
    review.is_hidden = True
    db.add(review)
    db.commit()
    db.refresh(review)
    return review


@app.post("/reviews/{review_id}/unhide", response_model=schemas.ReviewRead)
def unhide_review(
    review_id: int,
    db: Session = Depends(get_db),
    _: Dict = Depends(admin_or_moderator),
):
    """
    Admin/moderator can unhide a review.
    """
    review = get_review_or_404(db, review_id)
    review.is_hidden = False
    db.add(review)
    db.commit()
    db.refresh(review)
    return review

@app.post("/reviews/{review_id}/unflag", response_model=schemas.ReviewRead)
def unflag_review(
    review_id: int,
    db: Session = Depends(get_db),
    _: Dict = Depends(admin_or_moderator),
):
    """
    Admin/moderator: clear the flag on a review.
    """
    review = get_review_or_404(db, review_id)
    review.is_flagged = False
    db.add(review)
    db.commit()
    db.refresh(review)
    return review
