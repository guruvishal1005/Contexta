"""
Contexta Backend - CVE Schemas

Pydantic schemas for CVE-related requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field


class CVEBase(BaseModel):
    """Base CVE schema with common fields."""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    cvss_score: float = Field(default=0.0, ge=0, le=10)
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None
    affected_software: List[str] = Field(default_factory=list)
    attack_vector: Optional[str] = None


class CVECreate(CVEBase):
    """Schema for creating a new CVE."""
    published_date: Optional[datetime] = None
    has_exploit: bool = False
    exploit_sources: List[str] = Field(default_factory=list)
    cisa_kev: bool = False
    references: List[str] = Field(default_factory=list)


class CVEResponse(CVEBase):
    """Schema for CVE response."""
    id: UUID
    published_date: Optional[datetime]
    last_modified: Optional[datetime]
    has_exploit: bool
    exploit_sources: List[str]
    cisa_kev: bool
    references: List[str]
    ai_extracted_data: Dict[str, Any]
    is_processed: bool
    exploit_activity_score: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class CVEListResponse(BaseModel):
    """Schema for paginated CVE list response."""
    items: List[CVEResponse]
    total: int
    page: int
    page_size: int
    pages: int
