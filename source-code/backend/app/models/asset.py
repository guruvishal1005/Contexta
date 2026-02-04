"""
Contexta Backend - Asset Model

This module defines the Asset model for tracking organizational assets.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, Enum as SQLEnum, Text, JSON
from sqlalchemy.orm import relationship
import enum

from app.models.base import BaseModel


class AssetType(str, enum.Enum):
    """Type of asset."""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"
    APPLICATION = "application"
    CLOUD_SERVICE = "cloud_service"
    IOT_DEVICE = "iot_device"


class ExposureLevel(str, enum.Enum):
    """
    Asset exposure level for BWVS calculation.
    
    Scores:
    - INTERNET_FACING: 10
    - VPN: 7
    - INTERNAL: 4
    - ISOLATED: 1
    """
    INTERNET_FACING = "internet_facing"
    VPN = "vpn"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class AssetCriticality(str, enum.Enum):
    """
    Asset criticality for BWVS calculation.
    
    Scores:
    - PAYMENT_PAYROLL: 10
    - CORE_BACKEND: 8
    - CRM_HR: 6
    - DEV_TEST: 3
    """
    PAYMENT_PAYROLL = "payment_payroll"
    CORE_BACKEND = "core_backend"
    CRM_HR = "crm_hr"
    DEV_TEST = "dev_test"


class Asset(BaseModel):
    """
    Asset model representing organizational assets.
    
    Attributes:
        name: Asset name
        hostname: Network hostname
        ip_address: IP address
        asset_type: Type of asset
        os: Operating system
        software: Installed software (JSON array)
        exposure_level: Network exposure level
        criticality: Business criticality
        business_unit: Associated business unit
        owner: Asset owner/contact
        location: Physical/logical location
        daily_revenue_impact: Estimated daily revenue impact in INR
        is_active: Whether asset is currently active
        metadata: Additional metadata (JSON)
    """
    
    __tablename__ = "assets"
    
    name = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255), unique=True, index=True)
    ip_address = Column(String(45), index=True)  # Supports IPv6
    asset_type = Column(SQLEnum(AssetType), nullable=False)
    os = Column(String(100))
    software = Column(JSON, default=list)  # List of installed software
    exposure_level = Column(
        SQLEnum(ExposureLevel),
        default=ExposureLevel.INTERNAL,
        nullable=False
    )
    criticality = Column(
        SQLEnum(AssetCriticality),
        default=AssetCriticality.DEV_TEST,
        nullable=False
    )
    business_unit = Column(String(100))
    owner = Column(String(255))
    location = Column(String(255))
    daily_revenue_impact = Column(Float, default=0.0)  # In INR Lakhs
    is_active = Column(Boolean, default=True)
    asset_metadata = Column(JSON, default=dict)
    
    # Relationships
    risks = relationship("Risk", back_populates="asset", lazy="dynamic")
    security_logs = relationship("SecurityLog", back_populates="asset", lazy="dynamic")
    
    @property
    def exposure_score(self) -> int:
        """Get exposure level score for BWVS."""
        scores = {
            ExposureLevel.INTERNET_FACING: 10,
            ExposureLevel.VPN: 7,
            ExposureLevel.INTERNAL: 4,
            ExposureLevel.ISOLATED: 1,
        }
        return scores.get(self.exposure_level, 4)
    
    @property
    def criticality_score(self) -> int:
        """Get criticality score for BWVS."""
        scores = {
            AssetCriticality.PAYMENT_PAYROLL: 10,
            AssetCriticality.CORE_BACKEND: 8,
            AssetCriticality.CRM_HR: 6,
            AssetCriticality.DEV_TEST: 3,
        }
        return scores.get(self.criticality, 3)
    
    @property
    def business_impact_score(self) -> int:
        """
        Get business impact score based on daily revenue impact.
        
        Scoring (in INR Lakhs):
        - > 10L: 10
        - 5-10L: 8
        - 1-5L: 6
        - < 1L: 3
        """
        if self.daily_revenue_impact > 10:
            return 10
        elif self.daily_revenue_impact >= 5:
            return 8
        elif self.daily_revenue_impact >= 1:
            return 6
        else:
            return 3
    
    def __repr__(self) -> str:
        return f"<Asset(name={self.name}, type={self.asset_type}, criticality={self.criticality})>"
