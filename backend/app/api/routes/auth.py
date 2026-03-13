"""
Contexta Backend - Authentication Routes

Handles user authentication, registration, and token management.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserResponse, UserLogin
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    verify_token,
    Token,
    create_tokens_for_user,
    get_current_active_user,
    TokenData,
)
from app.auth.password import hash_password, verify_password
from app.ledger.chain import get_ledger, LedgerEventTypes

logger = structlog.get_logger()
router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.
    
    - **email**: User's email address (must be unique)
    - **password**: User's password (min 8 characters)
    - **full_name**: User's full name
    """
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username already exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    existing_username = result.scalar_one_or_none()
    
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create new user
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=UserRole.ANALYST  # Default role
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.ACCESS_GRANTED,
        data={
            "user_id": str(user.id),
            "email": user.email,
            "action": "user_registered"
        },
        actor="system"
    )
    
    logger.info("User registered", user_id=str(user.id), email=user.email)
    
    return user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return tokens.
    
    Uses OAuth2 password flow.
    """
    # Find user
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning("Login failed", email=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    # Create tokens
    tokens = create_tokens_for_user(
        user_id=str(user.id),
        email=user.email,
        role=user.role.value
    )
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.USER_LOGIN,
        data={
            "user_id": str(user.id),
            "email": user.email
        },
        actor=str(user.id)
    )
    
    logger.info("User logged in", user_id=str(user.id), email=user.email)
    
    return tokens


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using a valid refresh token.
    """
    # Verify refresh token
    token_data = verify_token(refresh_token, token_type="refresh")
    
    # Verify user still exists and is active
    result = await db.execute(
        select(User).where(User.id == token_data.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new tokens
    tokens = create_tokens_for_user(
        user_id=str(user.id),
        email=user.email,
        role=user.role.value
    )
    
    logger.debug("Token refreshed", user_id=str(user.id))
    
    return tokens


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current authenticated user's information.
    """
    result = await db.execute(
        select(User).where(User.id == current_user.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.post("/logout")
async def logout(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Logout current user.
    
    Note: In a production system, you would add the token to a blacklist
    or use short-lived tokens with a refresh token rotation strategy.
    """
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.USER_LOGOUT,
        data={
            "user_id": current_user.user_id,
            "email": current_user.email
        },
        actor=current_user.user_id
    )
    
    logger.info("User logged out", user_id=current_user.user_id)
    
    return {"message": "Successfully logged out"}
