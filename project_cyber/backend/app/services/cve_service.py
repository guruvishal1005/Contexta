"""
Contexta Backend - CVE Service

This module provides CVE management and querying capabilities.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.cve import CVE
from app.services.gemini_service import gemini_service

logger = structlog.get_logger()


class CVEService:
    """
    Service for managing CVE data.
    
    Provides methods for:
    - Creating/updating CVEs from feed data
    - Querying CVEs with filters
    - AI-powered context extraction
    - Exploit activity tracking
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize service with database session."""
        self.db = db
    
    async def create_cve(self, cve_data: Dict[str, Any]) -> CVE:
        """
        Create a new CVE record.
        
        Args:
            cve_data: CVE data dictionary
            
        Returns:
            Created CVE model
        """
        cve = CVE(**cve_data)
        self.db.add(cve)
        await self.db.flush()
        logger.info("Created CVE", cve_id=cve.cve_id)
        return cve
    
    async def get_by_cve_id(self, cve_id: str) -> Optional[CVE]:
        """
        Get CVE by CVE ID (e.g., CVE-2024-1234).
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE model or None
        """
        result = await self.db.execute(
            select(CVE).where(CVE.cve_id == cve_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_id(self, id: UUID) -> Optional[CVE]:
        """
        Get CVE by internal UUID.
        
        Args:
            id: Internal UUID
            
        Returns:
            CVE model or None
        """
        result = await self.db.execute(
            select(CVE).where(CVE.id == id)
        )
        return result.scalar_one_or_none()
    
    async def update_cve(self, cve: CVE, update_data: Dict[str, Any]) -> CVE:
        """
        Update an existing CVE.
        
        Args:
            cve: CVE model to update
            update_data: Fields to update
            
        Returns:
            Updated CVE model
        """
        for key, value in update_data.items():
            if hasattr(cve, key):
                setattr(cve, key, value)
        cve.updated_at = datetime.utcnow()
        await self.db.flush()
        logger.info("Updated CVE", cve_id=cve.cve_id)
        return cve
    
    async def upsert_cve(self, cve_data: Dict[str, Any]) -> CVE:
        """
        Create or update a CVE based on cve_id.
        
        Args:
            cve_data: CVE data dictionary
            
        Returns:
            Created or updated CVE model
        """
        existing = await self.get_by_cve_id(cve_data["cve_id"])
        if existing:
            return await self.update_cve(existing, cve_data)
        return await self.create_cve(cve_data)
    
    async def list_cves(
        self,
        page: int = 1,
        page_size: int = 20,
        severity: Optional[str] = None,
        has_exploit: Optional[bool] = None,
        min_cvss: Optional[float] = None,
        search: Optional[str] = None
    ) -> tuple[List[CVE], int]:
        """
        List CVEs with pagination and filters.
        
        Args:
            page: Page number (1-indexed)
            page_size: Items per page
            severity: Filter by severity
            has_exploit: Filter by exploit availability
            min_cvss: Minimum CVSS score
            search: Search in CVE ID and description
            
        Returns:
            Tuple of (CVE list, total count)
        """
        query = select(CVE)
        count_query = select(func.count(CVE.id))
        
        # Apply filters
        if severity:
            query = query.where(CVE.severity == severity)
            count_query = count_query.where(CVE.severity == severity)
        
        if has_exploit is not None:
            query = query.where(CVE.has_exploit == has_exploit)
            count_query = count_query.where(CVE.has_exploit == has_exploit)
        
        if min_cvss is not None:
            query = query.where(CVE.cvss_score >= min_cvss)
            count_query = count_query.where(CVE.cvss_score >= min_cvss)
        
        if search:
            search_filter = or_(
                CVE.cve_id.ilike(f"%{search}%"),
                CVE.description.ilike(f"%{search}%")
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)
        
        # Get total count
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * page_size
        query = query.order_by(CVE.cvss_score.desc()).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        cves = result.scalars().all()
        
        return list(cves), total
    
    async def get_high_severity_cves(
        self,
        min_cvss: float = 7.0,
        limit: int = 50
    ) -> List[CVE]:
        """
        Get high severity CVEs for risk calculation.
        
        Args:
            min_cvss: Minimum CVSS score
            limit: Maximum number of results
            
        Returns:
            List of high severity CVEs
        """
        query = (
            select(CVE)
            .where(CVE.cvss_score >= min_cvss)
            .order_by(CVE.cvss_score.desc(), CVE.created_at.desc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def get_exploited_cves(self, limit: int = 100) -> List[CVE]:
        """
        Get CVEs with known exploits.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of exploited CVEs
        """
        query = (
            select(CVE)
            .where(or_(CVE.has_exploit == True, CVE.cisa_kev == True))
            .order_by(CVE.cvss_score.desc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def process_with_ai(self, cve: CVE) -> CVE:
        """
        Process CVE with Gemini AI for context extraction.
        
        Args:
            cve: CVE to process
            
        Returns:
            Updated CVE with AI data
        """
        if cve.is_processed:
            return cve
        
        try:
            ai_data = await gemini_service.extract_threat_context(cve.description)
            cve.ai_extracted_data = ai_data
            cve.is_processed = True
            await self.db.flush()
            logger.info("Processed CVE with AI", cve_id=cve.cve_id)
        except Exception as e:
            logger.error("AI processing failed", cve_id=cve.cve_id, error=str(e))
        
        return cve
    
    async def get_unprocessed_cves(self, limit: int = 50) -> List[CVE]:
        """
        Get CVEs that haven't been processed by AI.
        
        Args:
            limit: Maximum number to return
            
        Returns:
            List of unprocessed CVEs
        """
        query = (
            select(CVE)
            .where(CVE.is_processed == False)
            .order_by(CVE.cvss_score.desc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def mark_as_exploited(
        self,
        cve_id: str,
        source: str
    ) -> Optional[CVE]:
        """
        Mark a CVE as having a known exploit.
        
        Args:
            cve_id: CVE identifier
            source: Exploit source (e.g., 'github', 'exploit-db')
            
        Returns:
            Updated CVE or None
        """
        cve = await self.get_by_cve_id(cve_id)
        if not cve:
            return None
        
        cve.has_exploit = True
        if not cve.exploit_sources:
            cve.exploit_sources = []
        if source not in cve.exploit_sources:
            cve.exploit_sources.append(source)
        
        await self.db.flush()
        logger.info("Marked CVE as exploited", cve_id=cve_id, source=source)
        return cve

    # Alias methods for route compatibility
    async def get_cve_by_id(self, cve_id: str) -> Optional[CVE]:
        """Alias for get_by_cve_id for route compatibility."""
        return await self.get_by_cve_id(cve_id)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get CVE statistics.
        
        Returns:
            Dictionary with CVE statistics
        """
        from sqlalchemy import func
        
        # Total count
        total_result = await self.db.execute(select(func.count(CVE.id)))
        total = total_result.scalar() or 0
        
        # Critical/High severity count
        critical_result = await self.db.execute(
            select(func.count(CVE.id)).where(CVE.cvss_score >= 9.0)
        )
        critical = critical_result.scalar() or 0
        
        high_result = await self.db.execute(
            select(func.count(CVE.id)).where(CVE.cvss_score >= 7.0, CVE.cvss_score < 9.0)
        )
        high = high_result.scalar() or 0
        
        # Exploited count
        exploited_result = await self.db.execute(
            select(func.count(CVE.id)).where(CVE.has_exploit == True)
        )
        exploited = exploited_result.scalar() or 0
        
        # KEV count
        kev_result = await self.db.execute(
            select(func.count(CVE.id)).where(CVE.cisa_kev == True)
        )
        kev = kev_result.scalar() or 0
        
        return {
            "total": total,
            "critical": critical,
            "high": high,
            "exploited": exploited,
            "kev": kev,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": total - critical - high,
            }
        }
    
    async def get_trending_cves(self, limit: int = 10) -> List[CVE]:
        """
        Get trending CVEs (recent, high severity, exploited).
        
        Args:
            limit: Maximum number to return
            
        Returns:
            List of trending CVEs
        """
        query = (
            select(CVE)
            .where(CVE.cvss_score >= 7.0)
            .order_by(CVE.published_date.desc(), CVE.cvss_score.desc())
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
    
    async def search_by_product(
        self,
        product_name: str,
        vendor: str = None,
        limit: int = 50
    ) -> List[CVE]:
        """
        Search CVEs by product name and optionally vendor.
        
        Args:
            product_name: Product name to search for
            vendor: Optional vendor name
            limit: Maximum results
            
        Returns:
            List of matching CVEs
        """
        query = select(CVE).where(
            CVE.affected_products.contains([{"product": product_name}])
        )
        
        if vendor:
            query = query.where(
                CVE.affected_products.contains([{"vendor": vendor}])
            )
        
        query = query.order_by(CVE.cvss_score.desc()).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())
