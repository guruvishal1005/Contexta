"""
Contexta Backend - Security Log Model

This module defines the SecurityLog model for storing SIEM-like security events.
"""

from sqlalchemy import Column, String, Text, Integer, Enum as SQLEnum, JSON, ForeignKey
from sqlalchemy import Uuid as UUID
from sqlalchemy.orm import relationship
import enum

from app.models.base import BaseModel


class LogSeverity(str, enum.Enum):
    """Log severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogCategory(str, enum.Enum):
    """Security log categories."""
    LOGIN_FAILURE = "login_failure"
    PORT_SCAN = "port_scan"
    MALWARE_ALERT = "malware_alert"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    ANOMALY = "anomaly"


class SecurityLog(BaseModel):
    """
    Security log model for storing SIEM-like events.
    
    Attributes:
        source: Log source system
        category: Log category
        severity: Severity level
        message: Log message
        source_ip: Source IP address
        destination_ip: Destination IP address
        source_port: Source port
        destination_port: Destination port
        username: Associated username
        asset_id: Related asset
        raw_log: Original raw log data (JSON)
        indicators: Extracted IOCs (JSON)
        is_correlated: Whether correlated with CVE/Risk
        correlation_data: Correlation details (JSON)
    """
    
    __tablename__ = "security_logs"
    
    source = Column(String(100), nullable=False, index=True)
    category = Column(SQLEnum(LogCategory), nullable=False, index=True)
    severity = Column(SQLEnum(LogSeverity), nullable=False, index=True)
    message = Column(Text, nullable=False)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    username = Column(String(100), index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    raw_log = Column(JSON, default=dict)
    indicators = Column(JSON, default=dict)  # {"ips": [], "domains": [], "hashes": []}
    is_correlated = Column(String(10), default="false")
    correlation_data = Column(JSON, default=dict)
    
    # Relationships
    asset = relationship("Asset", back_populates="security_logs")
    
    def __repr__(self) -> str:
        return f"<SecurityLog(category={self.category}, severity={self.severity}, source_ip={self.source_ip})>"
