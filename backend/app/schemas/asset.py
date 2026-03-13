"""
Contexta Backend - Asset Schemas

Pydantic schemas for asset-related requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field

from app.models.asset import AssetType, ExposureLevel, AssetCriticality


class AssetBase(BaseModel):
    """Base asset schema with common fields."""
    name: str = Field(..., min_length=1, max_length=255)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: AssetType
    os: Optional[str] = None
    software: List[str] = Field(default_factory=list)
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    criticality: AssetCriticality = AssetCriticality.DEV_TEST
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    location: Optional[str] = None
    daily_revenue_impact: float = Field(default=0.0, ge=0)


class AssetCreate(AssetBase):
    """Schema for creating a new asset."""
    asset_metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    """Schema for updating an asset."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[AssetType] = None
    os: Optional[str] = None
    software: Optional[List[str]] = None
    exposure_level: Optional[ExposureLevel] = None
    criticality: Optional[AssetCriticality] = None
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    location: Optional[str] = None
    daily_revenue_impact: Optional[float] = Field(None, ge=0)
    is_active: Optional[bool] = None
    asset_metadata: Optional[Dict[str, Any]] = None


class AssetResponse(AssetBase):
    """Schema for asset response."""
    id: UUID
    is_active: bool
    asset_metadata: Dict[str, Any]
    exposure_score: int
    criticality_score: int
    business_impact_score: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True
