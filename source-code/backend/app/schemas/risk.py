"""
Contexta Backend - Risk Schemas

Pydantic schemas for risk-related requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field

from app.models.risk import RiskStatus


class BWVSComponents(BaseModel):
    """Schema for BWVS score components."""
    cvss_score: float = Field(..., ge=0, le=10, description="CVSS base score")
    exploit_activity: float = Field(..., ge=0, le=10, description="Exploit activity score")
    exposure_level: float = Field(..., ge=0, le=10, description="Asset exposure score")
    asset_criticality: float = Field(..., ge=0, le=10, description="Asset criticality score")
    business_impact: float = Field(..., ge=0, le=10, description="Business impact score")
    ai_relevance: float = Field(..., ge=0, le=10, description="AI relevance score")
    final_bwvs: float = Field(..., ge=0, le=100, description="Final BWVS score")


class RiskResponse(BaseModel):
    """Schema for risk response."""
    id: UUID
    title: str
    description: Optional[str]
    cve_id: Optional[UUID]
    asset_id: Optional[UUID]
    bwvs_score: float
    priority_score: float
    status: RiskStatus
    ai_relevance_score: float
    ai_analysis: Dict[str, Any]
    freshness_factor: float
    trend_factor: float
    first_seen: datetime
    last_seen: datetime
    related_logs: List[str]
    remediation_notes: Optional[str]
    is_top_10: bool
    bwvs_components: Optional[BWVSComponents] = None
    cve_data: Optional[Dict[str, Any]] = None
    asset_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class RiskListResponse(BaseModel):
    """Schema for paginated risk list response."""
    items: List[RiskResponse]
    total: int
    page: int
    page_size: int
    pages: int


class Top10Response(BaseModel):
    """Schema for Top 10 risks response."""
    risks: List[RiskResponse]
    last_calculated: datetime
    calculation_interval_minutes: int = 5


# Alias for backward compatibility
TopRisksResponse = Top10Response
