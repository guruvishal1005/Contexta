"""
Contexta Backend - JWT Authentication

JWT token creation and verification utilities.
"""

from typing import Optional, List
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
import structlog

from app.config import get_settings
from app.models.user import UserRole

logger = structlog.get_logger()
settings = get_settings()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class Token(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Token payload data."""
    user_id: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    logger.debug(
        "Access token created",
        user_id=data.get("sub"),
        expires=expire.isoformat()
    )
    
    return encoded_jwt


def create_refresh_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        data: Payload data to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT refresh token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    logger.debug(
        "Refresh token created",
        user_id=data.get("sub"),
        expires=expire.isoformat()
    )
    
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> TokenData:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token to verify
        token_type: Expected token type ('access' or 'refresh')
        
    Returns:
        Decoded token data
        
    Raises:
        HTTPException: If token is invalid
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        
        # Verify token type
        if payload.get("type") != token_type:
            logger.warning(
                "Token type mismatch",
                expected=token_type,
                actual=payload.get("type")
            )
            raise credentials_exception
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        token_data = TokenData(
            user_id=user_id,
            email=payload.get("email"),
            role=payload.get("role"),
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
        )
        
        return token_data
        
    except JWTError as e:
        logger.warning("JWT verification failed", error=str(e))
        raise credentials_exception


async def get_current_user(
    token: str = Depends(oauth2_scheme)
) -> TokenData:
    """
    FastAPI dependency to get current user from JWT token.
    
    Args:
        token: JWT token from request header
        
    Returns:
        Token data with user information
    """
    return verify_token(token, "access")


async def get_current_active_user(
    current_user: TokenData = Depends(get_current_user)
) -> TokenData:
    """
    FastAPI dependency to get current active user.
    
    Can be extended to check if user is active in database.
    
    Args:
        current_user: Current user from token
        
    Returns:
        Active user token data
    """
    # In production, you would verify user is still active in DB
    return current_user


def require_role(allowed_roles: List[UserRole]):
    """
    FastAPI dependency factory for role-based access control.
    
    Args:
        allowed_roles: List of roles that can access the endpoint
        
    Returns:
        Dependency function
        
    Usage:
        @router.get("/admin", dependencies=[Depends(require_role([UserRole.ADMIN]))])
    """
    async def role_checker(
        current_user: TokenData = Depends(get_current_active_user)
    ) -> TokenData:
        if current_user.role is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User role not found"
            )
        
        try:
            user_role = UserRole(current_user.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid user role"
            )
        
        if user_role not in allowed_roles:
            logger.warning(
                "Access denied - insufficient role",
                user_id=current_user.user_id,
                user_role=current_user.role,
                required_roles=[r.value for r in allowed_roles]
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return current_user
    
    return role_checker


def create_tokens_for_user(
    user_id: str,
    email: str,
    role: str
) -> Token:
    """
    Create both access and refresh tokens for a user.
    
    Args:
        user_id: User's ID
        email: User's email
        role: User's role
        
    Returns:
        Token object with both tokens
    """
    token_data = {
        "sub": user_id,
        "email": email,
        "role": role
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


# Optional auth scheme for demo purposes
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme_optional)
) -> Optional[TokenData]:
    """
    FastAPI dependency to optionally get current user from JWT token.
    Returns None if no token or invalid token (for demo mode).
    
    Args:
        token: Optional JWT token from request header
        
    Returns:
        Token data with user information, or None for demo mode
    """
    if token is None:
        # Demo mode - return a demo user
        return TokenData(
            user_id="demo-user",
            email="demo@contexta.io",
            role="analyst",
            exp=datetime.now(timezone.utc) + timedelta(hours=24)
        )
    
    try:
        return verify_token(token, "access")
    except HTTPException:
        # Invalid token - fall back to demo mode
        return TokenData(
            user_id="demo-user",
            email="demo@contexta.io",
            role="analyst",
            exp=datetime.now(timezone.utc) + timedelta(hours=24)
        )
