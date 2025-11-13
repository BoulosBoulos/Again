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
    Decode JWT from Authorization: Bearer <token>
    and return {"username": ..., "role": ...}.
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
    Dependency factory: require one of the given roles to access an endpoint.
    """

    async def dependency(claims: Dict[str, Any] = Depends(get_current_user_claims)) -> Dict[str, Any]:
        if claims["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return claims

    return dependency
