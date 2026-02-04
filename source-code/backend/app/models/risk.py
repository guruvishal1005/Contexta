"""
Contexta Backend - Risk Model

This module defines the Risk and RiskScore models for risk tracking.
"""

from sqlalchemy import Column, String, Float, Integer, Text, Boolean, JSON, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy import Uuid as UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.models.base import BaseModel


class RiskStatus(str, enum.Enum):
    """Risk status enumeration."""
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class Risk(BaseModel):
    """
    Risk model representing correlated threats.
    
    Combines CVE, asset, and log data into actionable risk items.
    
    Attributes:
        title: Risk title
        description: Risk description
        cve_id: Related CVE
        asset_id: Affected asset
        bwvs_score: Business-Weighted Vulnerability Score (0-100)
        priority_score: Dynamic priority score
        status: Current risk status
        ai_relevance_score: AI-calculated relevance (0-100)
        ai_analysis: AI-generated analysis (JSON)
        freshness_factor: Time-based freshness (0-1)
        trend_factor: Trend multiplier (0.5-2.0)
        first_seen: When risk was first detected
        last_seen: When risk was last observed
        related_logs: Related log IDs (JSON array)
        remediation_notes: Remediation guidance
        is_top_10: Whether in current Top 10
    """
    
    __tablename__ = "risks"
    
    title = Column(String(500), nullable=False)
    description = Column(Text)
    cve_id = Column(UUID(as_uuid=True), ForeignKey("cves.id"), nullable=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    bwvs_score = Column(Float, default=0.0, index=True)
    priority_score = Column(Float, default=0.0, index=True)
    status = Column(SQLEnum(RiskStatus), default=RiskStatus.ACTIVE, index=True)
    ai_relevance_score = Column(Float, default=0.0)
    ai_analysis = Column(JSON, default=dict)
    freshness_factor = Column(Float, default=1.0)
    trend_factor = Column(Float, default=1.0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    related_logs = Column(JSON, default=list)  # List of log IDs
    remediation_notes = Column(Text)
    is_top_10 = Column(Boolean, default=False, index=True)
    
    # Relationships
    cve = relationship("CVE", back_populates="risks")
    asset = relationship("Asset", back_populates="risks")
    scores = relationship("RiskScore", back_populates="risk", lazy="dynamic")
    incidents = relationship("Incident", back_populates="risk", lazy="dynamic")
    
    def __repr__(self) -> str:
        return f"<Risk(title={self.title[:50]}, bwvs={self.bwvs_score}, status={self.status})>"


class RiskScore(BaseModel):
    """
    Historical risk score tracking.
    
    Stores BWVS component scores for auditing and trend analysis.
    
    Attributes:
        risk_id: Parent risk
        cvss_score: CVSS component (0-10)
        exploit_activity: Exploit activity component (0-10)
        exposure_level: Exposure level component (0-10)
        asset_criticality: Asset criticality component (0-10)
        business_impact: Business impact component (0-10)
        ai_relevance: AI relevance component (0-10)
        final_bwvs: Calculated BWVS (0-100)
        calculation_timestamp: When score was calculated
    """
    
    __tablename__ = "risk_scores"
    
    risk_id = Column(UUID(as_uuid=True), ForeignKey("risks.id"), nullable=False, index=True)
    cvss_score = Column(Float, default=0.0)
    exploit_activity = Column(Float, default=0.0)
    exposure_level = Column(Float, default=0.0)
    asset_criticality = Column(Float, default=0.0)
    business_impact = Column(Float, default=0.0)
    ai_relevance = Column(Float, default=0.0)
    final_bwvs = Column(Float, default=0.0)
    calculation_timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    risk = relationship("Risk", back_populates="scores")
    
    def __repr__(self) -> str:
        return f"<RiskScore(risk_id={self.risk_id}, bwvs={self.final_bwvs})>"
