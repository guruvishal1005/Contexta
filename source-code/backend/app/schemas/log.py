"""
Contexta Backend - Security Log Schemas

Pydantic schemas for security log requests and responses.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field

from app.models.log import LogSeverity, LogCategory


class SecurityLogBase(BaseModel):
    """Base security log schema."""
    source: str = Field(..., min_length=1, max_length=100)
    category: LogCategory
    severity: LogSeverity
    message: str


class SecurityLogCreate(SecurityLogBase):
    """Schema for creating a security log."""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    username: Optional[str] = None
    asset_id: Optional[UUID] = None
    raw_log: Dict[str, Any] = Field(default_factory=dict)
    indicators: Dict[str, Any] = Field(default_factory=dict)


class SecurityLogResponse(SecurityLogBase):
    """Schema for security log response."""
    id: UUID
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    username: Optional[str]
    asset_id: Optional[UUID]
    raw_log: Dict[str, Any]
    indicators: Dict[str, Any]
    is_correlated: str
    correlation_data: Dict[str, Any]
    created_at: datetime
    
    class Config:
        from_attributes = True
