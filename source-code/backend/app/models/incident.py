"""
Contexta Backend - Incident Model

This module defines the Incident and IncidentAnalysis models.
"""

from sqlalchemy import Column, String, Float, Text, Enum as SQLEnum, JSON, ForeignKey, DateTime
from sqlalchemy import Uuid as UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.models.base import BaseModel


class IncidentStatus(str, enum.Enum):
    """Incident status enumeration."""
    OPEN = "open"
    ANALYZING = "analyzing"
    RESPONDING = "responding"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(str, enum.Enum):
    """Incident severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Incident(BaseModel):
    """
    Incident model for tracking security incidents.
    
    Created when analyst selects a risk from Top 10 for investigation.
    
    Attributes:
        title: Incident title
        description: Incident description
        risk_id: Source risk
        status: Current incident status
        severity: Incident severity
        created_by: User who created the incident
        assigned_to: Assigned analyst
        timeline: Event timeline (JSON array)
        affected_assets: List of affected asset IDs
        iocs: Indicators of Compromise (JSON)
        notes: Investigation notes
        resolution: Resolution summary
        resolved_at: Resolution timestamp
    """
    
    __tablename__ = "incidents"
    
    title = Column(String(500), nullable=False)
    description = Column(Text)
    risk_id = Column(UUID(as_uuid=True), ForeignKey("risks.id"), nullable=True)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True)
    severity = Column(SQLEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_to = Column(String(255))
    timeline = Column(JSON, default=list)  # [{timestamp, event, details}, ...]
    affected_assets = Column(JSON, default=list)  # List of asset IDs
    iocs = Column(JSON, default=dict)  # {ips: [], domains: [], hashes: [], etc.}
    notes = Column(Text)
    resolution = Column(Text)
    resolved_at = Column(DateTime)
    
    # Relationships
    risk = relationship("Risk", back_populates="incidents")
    created_by_user = relationship("User", back_populates="incidents")
    analyses = relationship("IncidentAnalysis", back_populates="incident", lazy="dynamic")
    
    def add_timeline_event(self, event: str, details: str = None) -> None:
        """Add event to incident timeline."""
        if self.timeline is None:
            self.timeline = []
        self.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "details": details
        })
    
    def __repr__(self) -> str:
        return f"<Incident(title={self.title[:50]}, status={self.status}, severity={self.severity})>"


class IncidentAnalysis(BaseModel):
    """
    Multi-agent analysis results for an incident.
    
    Stores analysis from each SOC agent.
    
    Attributes:
        incident_id: Parent incident
        agent_type: Type of agent (analyst, intel, forensics, business, response)
        analysis_result: Agent's analysis (JSON)
        confidence_score: Confidence in analysis (0-100)
        recommendations: Agent recommendations (JSON array)
        consensus_report: Final consensus report (only for orchestrator result)
        raw_response: Raw Gemini API response
    """
    
    __tablename__ = "incident_analyses"
    
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True)
    agent_type = Column(String(50), nullable=False, index=True)
    analysis_result = Column(JSON, default=dict)
    confidence_score = Column(Float, default=0.0)
    recommendations = Column(JSON, default=list)
    consensus_report = Column(Text)
    raw_response = Column(Text)
    
    # Relationships
    incident = relationship("Incident", back_populates="analyses")
    
    def __repr__(self) -> str:
        return f"<IncidentAnalysis(incident_id={self.incident_id}, agent={self.agent_type})>"
