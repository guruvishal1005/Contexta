"""
Contexta Backend - CVE Model

This module defines the CVE model for storing vulnerability information.
"""

from sqlalchemy import Column, String, Float, Text, Boolean, JSON, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime

from app.models.base import BaseModel


class CVE(BaseModel):
    """
    CVE (Common Vulnerabilities and Exposures) model.
    
    Stores vulnerability information from NVD/CISA feeds.
    
    Attributes:
        cve_id: Unique CVE identifier (e.g., CVE-2024-1234)
        description: Vulnerability description
        cvss_score: CVSS v3 base score (0-10)
        cvss_vector: CVSS v3 vector string
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        affected_software: List of affected software/products
        attack_vector: Attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)
        published_date: When CVE was published
        last_modified: When CVE was last modified
        has_exploit: Whether public exploit exists
        exploit_sources: Sources of known exploits (JSON array)
        cisa_kev: Whether in CISA Known Exploited Vulnerabilities
        references: Reference URLs (JSON array)
        ai_extracted_data: AI-extracted context (JSON)
        is_processed: Whether AI processing is complete
    """
    
    __tablename__ = "cves"
    
    cve_id = Column(String(20), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, default=0.0, index=True)
    cvss_vector = Column(String(255))
    severity = Column(String(20), index=True)
    affected_software = Column(JSON, default=list)
    attack_vector = Column(String(50))
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    has_exploit = Column(Boolean, default=False, index=True)
    exploit_sources = Column(JSON, default=list)  # ["github", "exploit-db", etc.]
    cisa_kev = Column(Boolean, default=False, index=True)
    references = Column(JSON, default=list)
    ai_extracted_data = Column(JSON, default=dict)
    is_processed = Column(Boolean, default=False)
    
    # Relationships
    risks = relationship("Risk", back_populates="cve", lazy="dynamic")
    
    @property
    def exploit_activity_score(self) -> int:
        """
        Calculate exploit activity score for BWVS.
        
        Scoring:
        - Public exploit (exploit-db, metasploit): 10
        - GitHub PoC: 8
        - Threat reports only: 6
        - No evidence: 2
        """
        if self.cisa_kev or "exploit-db" in (self.exploit_sources or []) or "metasploit" in (self.exploit_sources or []):
            return 10
        elif "github" in (self.exploit_sources or []):
            return 8
        elif self.has_exploit or len(self.exploit_sources or []) > 0:
            return 6
        else:
            return 2
    
    def __repr__(self) -> str:
        return f"<CVE(cve_id={self.cve_id}, cvss={self.cvss_score}, severity={self.severity})>"
