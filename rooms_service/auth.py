from typing import Callable, Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

# MUST MATCH users_service.auth
SECRET_KEY = "super-secret-smart-meeting-room-key"
ALGORITHM = "HS256"

security = HTTPBearer()


async def get_current_user_claims(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    Decode a JWT bearer token and extract user claims.

    The token is expected in the Authorization header as a Bearer token.

    Parameters
    ----------
    credentials : HTTPAuthorizationCredentials
        Authorization header parsed by FastAPI's HTTPBearer.

    Returns
    -------
    Dict[str, Any]
        A dictionary containing at least:
        - 'username' : str
        - 'role' : str

    Raises
    ------
    HTTPException
        If the token is missing, invalid, or cannot be decoded.
    """
    token = credentials.credentials

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return {"username": username, "role": role}


def require_roles(*allowed_roles: str) -> Callable:
    """
    Build a dependency that enforces a set of allowed roles.

    Parameters
    ----------
    allowed_roles : str
        One or more role names that are permitted to access a route.

    Returns
    -------
    Callable
        A FastAPI dependency that checks the caller's role and raises
        HTTP 403 if access is not allowed.
    """

    async def dependency(claims: Dict[str, Any] = Depends(get_current_user_claims)) -> Dict[str, Any]:
        if claims["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return claims

    return dependency
