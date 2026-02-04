"""
Contexta Backend - Base Model

This module provides the base model class and common mixins for all database models.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, String
from sqlalchemy import Uuid as UUID
from sqlalchemy.orm import declared_attr

from app.database import Base


class TimestampMixin:
    """Mixin that adds created_at and updated_at timestamps to models."""
    
    @declared_attr
    def created_at(cls):
        return Column(DateTime, default=datetime.utcnow, nullable=False)
    
    @declared_attr
    def updated_at(cls):
        return Column(
            DateTime,
            default=datetime.utcnow,
            onupdate=datetime.utcnow,
            nullable=False
        )


class BaseModel(Base, TimestampMixin):
    """
    Abstract base model with common fields.
    
    Provides:
    - UUID primary key
    - Created/Updated timestamps
    """
    
    __abstract__ = True
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True
    )
    
    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }
