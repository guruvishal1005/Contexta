"""
Contexta Backend - Asset Service

This module provides asset management capabilities.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.asset import Asset, AssetType, ExposureLevel, AssetCriticality

logger = structlog.get_logger()


class AssetService:
    """
    Service for managing organizational assets.
    
    Provides methods for:
    - Asset CRUD operations
    - Asset querying and filtering
    - Software inventory matching
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize service with database session."""
        self.db = db
    
    async def create_asset(self, asset_data: Dict[str, Any]) -> Asset:
        """
        Create a new asset.
        
        Args:
            asset_data: Asset data dictionary
            
        Returns:
            Created Asset model
        """
        asset = Asset(**asset_data)
        self.db.add(asset)
        await self.db.flush()
        logger.info("Created asset", name=asset.name, hostname=asset.hostname)
        return asset
    
    async def get_by_id(self, id: UUID) -> Optional[Asset]:
        """
        Get asset by ID.
        
        Args:
            id: Asset UUID
            
        Returns:
            Asset model or None
        """
        result = await self.db.execute(
            select(Asset).where(Asset.id == id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_hostname(self, hostname: str) -> Optional[Asset]:
        """
        Get asset by hostname.
        
        Args:
            hostname: Asset hostname
            
        Returns:
            Asset model or None
        """
        result = await self.db.execute(
            select(Asset).where(Asset.hostname == hostname)
        )
        return result.scalar_one_or_none()
    
    async def get_by_ip(self, ip_address: str) -> Optional[Asset]:
        """
        Get asset by IP address.
        
        Args:
            ip_address: Asset IP address
            
        Returns:
            Asset model or None
        """
        result = await self.db.execute(
            select(Asset).where(Asset.ip_address == ip_address)
        )
        return result.scalar_one_or_none()
    
    async def update_asset(self, asset: Asset, update_data: Dict[str, Any]) -> Asset:
        """
        Update an existing asset.
        
        Args:
            asset: Asset model to update
            update_data: Fields to update
            
        Returns:
            Updated Asset model
        """
        for key, value in update_data.items():
            if hasattr(asset, key) and value is not None:
                setattr(asset, key, value)
        asset.updated_at = datetime.utcnow()
        await self.db.flush()
        logger.info("Updated asset", id=str(asset.id), name=asset.name)
        return asset
    
    async def delete_asset(self, asset: Asset) -> bool:
        """
        Delete an asset (soft delete by setting is_active=False).
        
        Args:
            asset: Asset to delete
            
        Returns:
            True if successful
        """
        asset.is_active = False
        asset.updated_at = datetime.utcnow()
        await self.db.flush()
        logger.info("Deactivated asset", id=str(asset.id))
        return True
    
    async def list_assets(
        self,
        page: int = 1,
        page_size: int = 20,
        asset_type: Optional[AssetType] = None,
        exposure_level: Optional[ExposureLevel] = None,
        criticality: Optional[AssetCriticality] = None,
        is_active: bool = True,
        search: Optional[str] = None
    ) -> tuple[List[Asset], int]:
        """
        List assets with pagination and filters.
        
        Args:
            page: Page number (1-indexed)
            page_size: Items per page
            asset_type: Filter by asset type
            exposure_level: Filter by exposure level
            criticality: Filter by criticality
            is_active: Filter by active status
            search: Search in name, hostname, IP
            
        Returns:
            Tuple of (Asset list, total count)
        """
        query = select(Asset).where(Asset.is_active == is_active)
        count_query = select(func.count(Asset.id)).where(Asset.is_active == is_active)
        
        if asset_type:
            query = query.where(Asset.asset_type == asset_type)
            count_query = count_query.where(Asset.asset_type == asset_type)
        
        if exposure_level:
            query = query.where(Asset.exposure_level == exposure_level)
            count_query = count_query.where(Asset.exposure_level == exposure_level)
        
        if criticality:
            query = query.where(Asset.criticality == criticality)
            count_query = count_query.where(Asset.criticality == criticality)
        
        if search:
            search_filter = or_(
                Asset.name.ilike(f"%{search}%"),
                Asset.hostname.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%")
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)
        
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        offset = (page - 1) * page_size
        query = query.order_by(Asset.name).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        assets = result.scalars().all()
        
        return list(assets), total
    
    async def find_assets_with_software(self, software_name: str) -> List[Asset]:
        """
        Find assets that have specific software installed.
        
        Args:
            software_name: Software name to search for
            
        Returns:
            List of matching assets
        """
        # This query checks if the software array contains the software name
        # Using case-insensitive search
        query = (
            select(Asset)
            .where(Asset.is_active == True)
        )
        result = await self.db.execute(query)
        assets = result.scalars().all()
        
        # Filter in Python for flexible matching
        matching_assets = []
        software_lower = software_name.lower()
        for asset in assets:
            if asset.software:
                for sw in asset.software:
                    if software_lower in sw.lower():
                        matching_assets.append(asset)
                        break
        
        return matching_assets
    
    async def get_critical_assets(self) -> List[Asset]:
        """
        Get all critical assets (PAYMENT_PAYROLL or CORE_BACKEND).
        
        Returns:
            List of critical assets
        """
        query = (
            select(Asset)
            .where(Asset.is_active == True)
            .where(
                or_(
                    Asset.criticality == AssetCriticality.PAYMENT_PAYROLL,
                    Asset.criticality == AssetCriticality.CORE_BACKEND
                )
            )
            .order_by(Asset.criticality)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def get_internet_facing_assets(self) -> List[Asset]:
        """
        Get all internet-facing assets.
        
        Returns:
            List of internet-facing assets
        """
        query = (
            select(Asset)
            .where(Asset.is_active == True)
            .where(Asset.exposure_level == ExposureLevel.INTERNET_FACING)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def get_all_active_assets(self) -> List[Asset]:
        """
        Get all active assets.
        
        Returns:
            List of all active assets
        """
        query = select(Asset).where(Asset.is_active == True)
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def create_sample_assets(self) -> List[Asset]:
        """
        Create sample assets for demonstration.
        
        Returns:
            List of created assets
        """
        sample_assets = [
            {
                "name": "Web Server 01",
                "hostname": "web-srv-01.contexta.local",
                "ip_address": "10.0.1.10",
                "asset_type": AssetType.SERVER,
                "os": "Ubuntu 22.04 LTS",
                "software": ["nginx/1.24.0", "nodejs/18.17.0", "postgresql-client/15"],
                "exposure_level": ExposureLevel.INTERNET_FACING,
                "criticality": AssetCriticality.CORE_BACKEND,
                "business_unit": "Engineering",
                "owner": "Platform Team",
                "location": "AWS us-east-1",
                "daily_revenue_impact": 8.5,  # 8.5 Lakhs
            },
            {
                "name": "Payment Gateway",
                "hostname": "payment-gw.contexta.local",
                "ip_address": "10.0.2.5",
                "asset_type": AssetType.APPLICATION,
                "os": "RHEL 8",
                "software": ["java/17", "spring-boot/3.1.0", "apache-tomcat/10.1"],
                "exposure_level": ExposureLevel.INTERNET_FACING,
                "criticality": AssetCriticality.PAYMENT_PAYROLL,
                "business_unit": "Finance",
                "owner": "Payments Team",
                "location": "AWS us-east-1",
                "daily_revenue_impact": 25.0,  # 25 Lakhs
            },
            {
                "name": "Internal Database",
                "hostname": "db-master.contexta.local",
                "ip_address": "10.0.3.10",
                "asset_type": AssetType.DATABASE,
                "os": "Ubuntu 22.04 LTS",
                "software": ["postgresql/15.3", "pgbouncer/1.19"],
                "exposure_level": ExposureLevel.INTERNAL,
                "criticality": AssetCriticality.CORE_BACKEND,
                "business_unit": "Engineering",
                "owner": "DBA Team",
                "location": "AWS us-east-1",
                "daily_revenue_impact": 15.0,
            },
            {
                "name": "HR Portal",
                "hostname": "hr-portal.contexta.local",
                "ip_address": "10.0.4.20",
                "asset_type": AssetType.APPLICATION,
                "os": "Windows Server 2022",
                "software": ["IIS/10.0", ".NET/6.0", "MSSQL-Client/2019"],
                "exposure_level": ExposureLevel.VPN,
                "criticality": AssetCriticality.CRM_HR,
                "business_unit": "Human Resources",
                "owner": "HR Team",
                "location": "On-premises",
                "daily_revenue_impact": 2.0,
            },
            {
                "name": "Development Server",
                "hostname": "dev-srv-01.contexta.local",
                "ip_address": "10.0.5.100",
                "asset_type": AssetType.SERVER,
                "os": "Ubuntu 22.04 LTS",
                "software": ["docker/24.0", "kubernetes/1.28", "jenkins/2.401"],
                "exposure_level": ExposureLevel.INTERNAL,
                "criticality": AssetCriticality.DEV_TEST,
                "business_unit": "Engineering",
                "owner": "DevOps Team",
                "location": "On-premises",
                "daily_revenue_impact": 0.5,
            },
            {
                "name": "VPN Gateway",
                "hostname": "vpn-gw.contexta.local",
                "ip_address": "203.0.113.50",
                "asset_type": AssetType.NETWORK_DEVICE,
                "os": "FortiOS 7.2",
                "software": ["FortiClient/7.2", "SSL-VPN"],
                "exposure_level": ExposureLevel.INTERNET_FACING,
                "criticality": AssetCriticality.CORE_BACKEND,
                "business_unit": "IT",
                "owner": "Network Team",
                "location": "DMZ",
                "daily_revenue_impact": 5.0,
            },
            {
                "name": "File Server",
                "hostname": "file-srv.contexta.local",
                "ip_address": "10.0.6.15",
                "asset_type": AssetType.SERVER,
                "os": "Windows Server 2022",
                "software": ["SMB/3.1.1", "DFS"],
                "exposure_level": ExposureLevel.INTERNAL,
                "criticality": AssetCriticality.CRM_HR,
                "business_unit": "IT",
                "owner": "IT Team",
                "location": "On-premises",
                "daily_revenue_impact": 1.5,
            },
            {
                "name": "IoT Sensor Gateway",
                "hostname": "iot-gw.contexta.local",
                "ip_address": "10.0.7.1",
                "asset_type": AssetType.IOT_DEVICE,
                "os": "Embedded Linux",
                "software": ["MQTT/3.1.1", "Node-RED/3.0"],
                "exposure_level": ExposureLevel.ISOLATED,
                "criticality": AssetCriticality.DEV_TEST,
                "business_unit": "Operations",
                "owner": "Facilities Team",
                "location": "Factory Floor",
                "daily_revenue_impact": 0.3,
            },
        ]
        
        created_assets = []
        for asset_data in sample_assets:
            # Check if asset already exists
            existing = await self.get_by_hostname(asset_data["hostname"])
            if not existing:
                asset = await self.create_asset(asset_data)
                created_assets.append(asset)
            else:
                created_assets.append(existing)
        
        logger.info("Created sample assets", count=len(created_assets))
        return created_assets
