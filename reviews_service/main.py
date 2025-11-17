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
    """
    Health-check endpoint for the Reviews service.

    Returns
    -------
    dict
        A small JSON payload indicating that the service is running.
    """
    return {"service": "reviews", "status": "running"}


admin_or_moderator = require_roles("admin", "moderator")
admin_mod_or_auditor = require_roles("admin", "moderator", "auditor")


def get_review_or_404(db: Session, review_id: int) -> models.Review:
    """
    Load a review by ID or raise HTTP 404.

    Parameters
    ----------
    db : Session
        Database session.
    review_id : int
        Identifier of the review.

    Returns
    -------
    Review
        The matching review instance.

    Raises
    ------
    HTTPException
        If the review does not exist.
    """
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
    """
    Create a new review for a meeting room.

    Access
    ------
    - Denied for roles: auditor, service_account.
    - Allowed for: regular, admin, facility_manager, moderator.

    Behavior
    --------
    - Each user can only submit one review per room.
    - Rating and comment are validated through Pydantic.
    - The authenticated user's ID is used as the review owner.

    Parameters
    ----------
    review_in : ReviewCreate
        Room ID, rating, and comment.
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims containing user_id and role.

    Returns
    -------
    ReviewRead
        The newly created review.

    Raises
    ------
    HTTPException
        If the role is read-only or the user already reviewed this room.
    """
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
    Public endpoint: list visible reviews for a specific room.

    Behavior
    --------
    - Returns only reviews where is_hidden is False.
    - Sorted by creation time in descending order.

    Parameters
    ----------
    room_id : int
        Room whose reviews are requested.
    db : Session
        Database session.

    Returns
    -------
    List[ReviewRead]
        Non-hidden reviews for the given room.
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
    Admin/Moderator/Auditor view of all reviews with filters.

    Access
    ------
    - Allowed roles: admin, moderator, auditor.

    Optional filters
    ----------------
    - room_id : filter by room.
    - user_id : filter by review author.
    - only_flagged : if True, only return flagged reviews.
    - include_hidden : if False, exclude hidden reviews.

    Parameters
    ----------
    room_id : Optional[int]
        Room filter.
    user_id : Optional[int]
        User filter.
    only_flagged : bool
        Whether to restrict results to flagged reviews.
    include_hidden : bool
        Whether to include hidden reviews in the response.
    db : Session
        Database session.

    Returns
    -------
    List[ReviewRead]
        Reviews matching the specified filters.
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
    """
    Update an existing review's rating and/or comment.

    Access
    ------
    - Review owner.
    - Admin or moderator.
    - Auditor and service_account cannot modify reviews.

    Behavior
    --------
    - Only provided fields are updated.
    - Uses Pydantic validation for rating and comment.

    Parameters
    ----------
    review_id : int
        ID of the review to update.
    update_data : ReviewUpdate
        New rating and/or comment.
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims.

    Returns
    -------
    ReviewRead
        Updated review.

    Raises
    ------
    HTTPException
        If the review does not exist or the user is not allowed.
    """
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
    """
    Permanently delete a review.

    Access
    ------
    - Review owner.
    - Admin or moderator.
    - Auditor and service_account cannot delete reviews.

    Parameters
    ----------
    review_id : int
        ID of the review to delete.
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
        If the review does not exist or the user is not allowed.
    """
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
    Flag a review as potentially inappropriate.

    Access
    ------
    - Any authenticated user except auditor and service_account.

    Behavior
    --------
    - Sets is_flagged = True on the review.

    Parameters
    ----------
    review_id : int
        ID of the review to flag.
    db : Session
        Database session.
    claims : Dict
        Decoded JWT claims.

    Returns
    -------
    ReviewRead
        The updated review after flagging.

    Raises
    ------
    HTTPException
        If the review does not exist or user role is read-only.
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
    Hide a review from public room listings.

    Access
    ------
    - Admin or moderator.

    Behavior
    --------
    - Sets is_hidden = True.

    Parameters
    ----------
    review_id : int
        ID of the review to hide.
    db : Session
        Database session.

    Returns
    -------
    ReviewRead
        The updated review after hiding.
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
    Unhide a previously hidden review.

    Access
    ------
    - Admin or moderator.

    Behavior
    --------
    - Sets is_hidden = False.

    Parameters
    ----------
    review_id : int
        ID of the review to unhide.
    db : Session
        Database session.

    Returns
    -------
    ReviewRead
        The updated review after unhiding.
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
    Clear the flag on a review.

    Access
    ------
    - Admin or moderator.

    Behavior
    --------
    - Sets is_flagged = False.

    Parameters
    ----------
    review_id : int
        ID of the review to unflag.
    db : Session
        Database session.

    Returns
    -------
    ReviewRead
        The updated review after unflagging.
    """
    review = get_review_or_404(db, review_id)
    review.is_flagged = False
    db.add(review)
    db.commit()
    db.refresh(review)
    return review
