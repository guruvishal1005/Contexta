"""
Contexta Backend - Incident Schemas

Pydantic schemas for incident-related requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field

from app.models.incident import IncidentStatus, IncidentSeverity


class IncidentCreate(BaseModel):
    """Schema for creating an incident."""
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    risk_id: Optional[UUID] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    assigned_to: Optional[str] = None
    affected_assets: List[UUID] = Field(default_factory=list)
    iocs: Dict[str, Any] = Field(default_factory=dict)


class IncidentUpdate(BaseModel):
    """Schema for updating an incident."""
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_to: Optional[str] = None
    affected_assets: Optional[List[UUID]] = None
    iocs: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None


class TimelineEvent(BaseModel):
    """Schema for incident timeline event."""
    timestamp: str
    event: str
    details: Optional[str] = None


class IncidentResponse(BaseModel):
    """Schema for incident response."""
    id: UUID
    title: str
    description: Optional[str]
    risk_id: Optional[UUID]
    status: IncidentStatus
    severity: IncidentSeverity
    created_by: Optional[UUID]
    assigned_to: Optional[str]
    timeline: List[TimelineEvent]
    affected_assets: List[UUID]
    iocs: Dict[str, Any]
    notes: Optional[str]
    resolution: Optional[str]
    resolved_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class IncidentAnalysisResponse(BaseModel):
    """Schema for incident analysis response."""
    id: UUID
    incident_id: UUID
    agent_type: str
    analysis_result: Dict[str, Any]
    confidence_score: float
    recommendations: List[str]
    consensus_report: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class AgentAnalysisRequest(BaseModel):
    """Schema for requesting agent analysis."""
    incident_id: UUID
    agents: List[str] = Field(
        default=["analyst", "intel", "forensics", "business", "response"],
        description="List of agent types to run"
    )
    generate_consensus: bool = Field(default=True)


class AgentAnalysisResponse(BaseModel):
    """Schema for agent analysis response."""
    incident_id: UUID
    analyses: List[IncidentAnalysisResponse]
    consensus_report: Optional[str] = None
    total_processing_time: float
