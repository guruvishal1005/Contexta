"""
Contexta Backend - User Model

This module defines the User model for authentication and authorization.
"""

from sqlalchemy import Column, String, Boolean, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from app.models.base import BaseModel


class UserRole(str, enum.Enum):
    """User role enumeration for RBAC."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(BaseModel):
    """
    User model for authentication and authorization.
    
    Attributes:
        email: Unique email address
        username: Unique username
        hashed_password: Bcrypt hashed password
        full_name: User's full name
        role: User role (admin, analyst, viewer)
        is_active: Whether user account is active
        is_verified: Whether email is verified
    """
    
    __tablename__ = "users"
    
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(SQLEnum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    incidents = relationship("Incident", back_populates="created_by_user", lazy="dynamic")
    
    def __repr__(self) -> str:
        return f"<User(username={self.username}, email={self.email}, role={self.role})>"
