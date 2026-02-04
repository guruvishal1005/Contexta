"""
Contexta Backend - Risk Service

This module provides risk management and Top 10 calculation capabilities.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta
from sqlalchemy import select, func, update, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.models.risk import Risk, RiskScore, RiskStatus
from app.models.cve import CVE
from app.models.asset import Asset
from app.services.gemini_service import gemini_service
from app.risk_engine.bwvs import BWVSCalculator

logger = structlog.get_logger()


class RiskService:
    """
    Service for managing risks and calculating Top 10.
    
    Provides methods for:
    - Risk CRUD operations
    - BWVS calculation
    - Top 10 ranking with dynamic priority
    - Risk correlation
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize service with database session."""
        self.db = db
        self.bwvs_calculator = BWVSCalculator()
    
    async def create_risk(
        self,
        title: str,
        description: str = None,
        cve_id: UUID = None,
        asset_id: UUID = None,
        related_logs: List[str] = None
    ) -> Risk:
        """
        Create a new risk.
        
        Args:
            title: Risk title
            description: Risk description
            cve_id: Related CVE UUID
            asset_id: Affected asset UUID
            related_logs: Related log IDs
            
        Returns:
            Created Risk model
        """
        risk = Risk(
            title=title,
            description=description,
            cve_id=cve_id,
            asset_id=asset_id,
            related_logs=related_logs or [],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        self.db.add(risk)
        await self.db.flush()
        logger.info("Created risk", id=str(risk.id), title=title)
        return risk
    
    async def get_by_id(self, id: UUID) -> Optional[Risk]:
        """Get risk by ID with related data."""
        result = await self.db.execute(
            select(Risk)
            .options(selectinload(Risk.cve), selectinload(Risk.asset))
            .where(Risk.id == id)
        )
        return result.scalar_one_or_none()
    
    async def update_risk(self, risk: Risk, update_data: Dict[str, Any]) -> Risk:
        """Update an existing risk."""
        for key, value in update_data.items():
            if hasattr(risk, key) and value is not None:
                setattr(risk, key, value)
        risk.updated_at = datetime.utcnow()
        await self.db.flush()
        return risk
    
    async def calculate_bwvs(self, risk: Risk) -> RiskScore:
        """
        Calculate BWVS score for a risk.
        
        Args:
            risk: Risk to calculate score for
            
        Returns:
            RiskScore with all components
        """
        # Get related CVE and Asset
        cve = None
        asset = None
        
        if risk.cve_id:
            cve_result = await self.db.execute(
                select(CVE).where(CVE.id == risk.cve_id)
            )
            cve = cve_result.scalar_one_or_none()
        
        if risk.asset_id:
            asset_result = await self.db.execute(
                select(Asset).where(Asset.id == risk.asset_id)
            )
            asset = asset_result.scalar_one_or_none()
        
        # Calculate AI relevance if not already done
        ai_relevance_pct = risk.ai_relevance_score
        if ai_relevance_pct == 0 and cve and asset:
            try:
                ai_result = await gemini_service.calculate_relevance_score(
                    cve.description,
                    {
                        "name": asset.name,
                        "type": asset.asset_type.value,
                        "software": asset.software,
                        "criticality": asset.criticality.value
                    }
                )
                ai_relevance_pct = ai_result.get("relevance_percentage", 50)
                risk.ai_relevance_score = ai_relevance_pct
                risk.ai_analysis = ai_result
            except Exception as e:
                logger.error("AI relevance calculation failed", error=str(e))
                ai_relevance_pct = 50
        
        # Calculate BWVS components
        score = self.bwvs_calculator.calculate(
            cvss_score=cve.cvss_score if cve else 5.0,
            exploit_activity_score=cve.exploit_activity_score if cve else 2,
            exposure_score=asset.exposure_score if asset else 4,
            criticality_score=asset.criticality_score if asset else 3,
            business_impact_score=asset.business_impact_score if asset else 3,
            ai_relevance_percentage=ai_relevance_pct
        )
        
        # Save score history
        risk_score = RiskScore(
            risk_id=risk.id,
            cvss_score=score["cvss_score"],
            exploit_activity=score["exploit_activity"],
            exposure_level=score["exposure_level"],
            asset_criticality=score["asset_criticality"],
            business_impact=score["business_impact"],
            ai_relevance=score["ai_relevance"],
            final_bwvs=score["final_bwvs"],
            calculation_timestamp=datetime.utcnow()
        )
        self.db.add(risk_score)
        
        # Update risk with new BWVS
        risk.bwvs_score = score["final_bwvs"]
        risk.last_seen = datetime.utcnow()
        
        await self.db.flush()
        logger.info("Calculated BWVS", risk_id=str(risk.id), bwvs=score["final_bwvs"])
        
        return risk_score
    
    async def calculate_priority_score(self, risk: Risk) -> float:
        """
        Calculate dynamic priority score.
        
        Priority = BWVS × Freshness × TrendFactor
        
        Args:
            risk: Risk to calculate priority for
            
        Returns:
            Priority score
        """
        # Calculate freshness factor (decays over time)
        # Fresh = 1.0, 24h old = 0.9, 7d old = 0.7, 30d old = 0.5
        age = datetime.utcnow() - risk.first_seen
        age_hours = age.total_seconds() / 3600
        
        if age_hours < 24:
            freshness = 1.0
        elif age_hours < 168:  # 7 days
            freshness = 1.0 - (age_hours - 24) * 0.0004  # Gradual decay
        elif age_hours < 720:  # 30 days
            freshness = 0.7 - (age_hours - 168) * 0.0004
        else:
            freshness = 0.5
        
        freshness = max(0.5, min(1.0, freshness))
        
        # Trend factor (could be enhanced with historical data)
        # For now, use static value or adjust based on recurrence
        trend_factor = risk.trend_factor or 1.0
        
        # Calculate priority
        priority = risk.bwvs_score * freshness * trend_factor
        
        # Update risk
        risk.freshness_factor = freshness
        risk.priority_score = priority
        
        await self.db.flush()
        return priority
    
    async def update_top_10(self) -> List[Risk]:
        """
        Update Top 10 risks based on priority score.
        
        Returns:
            List of Top 10 risks
        """
        # Reset all is_top_10 flags
        await self.db.execute(
            update(Risk).values(is_top_10=False)
        )
        
        # Get all active risks
        result = await self.db.execute(
            select(Risk)
            .options(selectinload(Risk.cve), selectinload(Risk.asset))
            .where(Risk.status == RiskStatus.ACTIVE)
            .order_by(Risk.priority_score.desc())
        )
        all_risks = result.scalars().all()
        
        # Recalculate priorities and get top 10
        for risk in all_risks:
            await self.calculate_priority_score(risk)
        
        # Re-sort and get top 10
        sorted_risks = sorted(all_risks, key=lambda r: r.priority_score, reverse=True)
        top_10 = sorted_risks[:10]
        
        # Mark top 10
        for risk in top_10:
            risk.is_top_10 = True
        
        await self.db.flush()
        logger.info("Updated Top 10 risks", count=len(top_10))
        
        return top_10
    
    async def get_top_10(self) -> List[Risk]:
        """
        Get current Top 10 risks.
        
        Returns:
            List of Top 10 risks
        """
        result = await self.db.execute(
            select(Risk)
            .options(selectinload(Risk.cve), selectinload(Risk.asset))
            .where(Risk.is_top_10 == True)
            .order_by(Risk.priority_score.desc())
        )
        return list(result.scalars().all())
    
    async def list_risks(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[RiskStatus] = None,
        min_bwvs: Optional[float] = None
    ) -> tuple[List[Risk], int]:
        """
        List risks with pagination.
        
        Args:
            page: Page number
            page_size: Items per page
            status: Filter by status
            min_bwvs: Minimum BWVS score
            
        Returns:
            Tuple of (Risk list, total count)
        """
        query = select(Risk).options(
            selectinload(Risk.cve),
            selectinload(Risk.asset)
        )
        count_query = select(func.count(Risk.id))
        
        if status:
            query = query.where(Risk.status == status)
            count_query = count_query.where(Risk.status == status)
        
        if min_bwvs is not None:
            query = query.where(Risk.bwvs_score >= min_bwvs)
            count_query = count_query.where(Risk.bwvs_score >= min_bwvs)
        
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        offset = (page - 1) * page_size
        query = query.order_by(Risk.priority_score.desc()).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        risks = result.scalars().all()
        
        return list(risks), total
    
    async def correlate_cve_with_assets(self, cve: CVE) -> List[Risk]:
        """
        Create risks by correlating a CVE with affected assets.
        
        Args:
            cve: CVE to correlate
            
        Returns:
            List of created risks
        """
        created_risks = []
        
        # Get all active assets
        result = await self.db.execute(
            select(Asset).where(Asset.is_active == True)
        )
        assets = result.scalars().all()
        
        # Match CVE affected software with asset software
        for asset in assets:
            if not asset.software:
                continue
            
            matched = False
            for affected in (cve.affected_software or []):
                affected_lower = affected.lower()
                for installed in asset.software:
                    if affected_lower in installed.lower():
                        matched = True
                        break
                if matched:
                    break
            
            if matched:
                # Check if risk already exists
                existing_result = await self.db.execute(
                    select(Risk).where(
                        and_(Risk.cve_id == cve.id, Risk.asset_id == asset.id)
                    )
                )
                existing = existing_result.scalar_one_or_none()
                
                if not existing:
                    risk = await self.create_risk(
                        title=f"{cve.cve_id} affects {asset.name}",
                        description=f"Vulnerability {cve.cve_id} ({cve.severity}) detected on {asset.name}. {cve.description[:500]}",
                        cve_id=cve.id,
                        asset_id=asset.id
                    )
                    await self.calculate_bwvs(risk)
                    created_risks.append(risk)
                else:
                    # Update existing risk's last_seen
                    existing.last_seen = datetime.utcnow()
        
        logger.info("Correlated CVE with assets", cve_id=cve.cve_id, risks_created=len(created_risks))
        return created_risks
    
    async def get_risk_score_history(
        self,
        risk_id: UUID,
        limit: int = 100
    ) -> List[RiskScore]:
        """
        Get historical BWVS scores for a risk.
        
        Args:
            risk_id: Risk UUID
            limit: Maximum scores to return
            
        Returns:
            List of RiskScore records
        """
        result = await self.db.execute(
            select(RiskScore)
            .where(RiskScore.risk_id == risk_id)
            .order_by(RiskScore.calculation_timestamp.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_top_risks(self, limit: int = 10) -> List[Risk]:
        """
        Get top risks by BWVS score.
        Alias for get_top_10 with configurable limit.
        
        Args:
            limit: Maximum number to return
            
        Returns:
            List of top risks
        """
        result = await self.db.execute(
            select(Risk)
            .options(selectinload(Risk.cve), selectinload(Risk.asset))
            .where(Risk.status != RiskStatus.RESOLVED)
            .order_by(Risk.bwvs_score.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
    
    async def get_risk_statistics(self) -> Dict[str, Any]:
        """
        Get risk statistics.
        
        Returns:
            Dictionary with risk statistics
        """
        from sqlalchemy import func
        
        # Total count
        total_result = await self.db.execute(select(func.count(Risk.id)))
        total = total_result.scalar() or 0
        
        # By status
        active_result = await self.db.execute(
            select(func.count(Risk.id)).where(Risk.status == RiskStatus.ACTIVE)
        )
        active_count = active_result.scalar() or 0
        
        investigating_result = await self.db.execute(
            select(func.count(Risk.id)).where(Risk.status == RiskStatus.INVESTIGATING)
        )
        investigating = investigating_result.scalar() or 0
        
        mitigating_result = await self.db.execute(
            select(func.count(Risk.id)).where(Risk.status == RiskStatus.MITIGATING)
        )
        mitigating = mitigating_result.scalar() or 0
        
        resolved_result = await self.db.execute(
            select(func.count(Risk.id)).where(Risk.status == RiskStatus.RESOLVED)
        )
        resolved = resolved_result.scalar() or 0
        
        # Critical risks (BWVS >= 80)
        critical_result = await self.db.execute(
            select(func.count(Risk.id)).where(Risk.bwvs_score >= 80)
        )
        critical = critical_result.scalar() or 0
        
        # High risks (BWVS >= 60)
        high_result = await self.db.execute(
            select(func.count(Risk.id)).where(Risk.bwvs_score >= 60, Risk.bwvs_score < 80)
        )
        high = high_result.scalar() or 0
        
        # Average BWVS
        avg_result = await self.db.execute(select(func.avg(Risk.bwvs_score)))
        avg_bwvs = avg_result.scalar() or 0
        
        return {
            "total": total,
            "by_status": {
                "active": active_count,
                "investigating": investigating,
                "mitigating": mitigating,
                "resolved": resolved
            },
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": total - critical - high
            },
            "average_bwvs": round(float(avg_bwvs), 2),
            "top_10_count": min(total, 10)
        }

    # Alias methods for route compatibility
    async def get_risk(self, risk_id: str) -> Optional[Risk]:
        """Alias for get_by_id for route compatibility."""
        from uuid import UUID
        try:
            uuid_id = UUID(risk_id)
            return await self.get_by_id(uuid_id)
        except ValueError:
            return None
    
    async def recalculate_risk(self, risk_id: str) -> Optional[Risk]:
        """
        Recalculate BWVS score for a risk.
        
        Args:
            risk_id: Risk UUID string
            
        Returns:
            Updated Risk or None
        """
        risk = await self.get_risk(risk_id)
        if not risk:
            return None
        
        await self.calculate_bwvs(risk)
        await self.db.flush()
        return risk
    
    async def update_risk_status(
        self,
        risk_id: str,
        new_status: RiskStatus,
        notes: str = None
    ) -> Optional[Risk]:
        """
        Update risk status.
        
        Args:
            risk_id: Risk UUID string
            new_status: New status value
            notes: Optional notes
            
        Returns:
            Updated Risk or None
        """
        risk = await self.get_risk(risk_id)
        if not risk:
            return None
        
        risk.status = new_status
        if notes:
            risk.remediation_notes = notes
        
        await self.db.flush()
        logger.info("Risk status updated", risk_id=risk_id, status=new_status.value)
        return risk
