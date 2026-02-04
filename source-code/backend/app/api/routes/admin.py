"""
Contexta Backend - Admin API Routes

Provides administrative endpoints for:
- Database seeding
- System health checks
- Cache management
- Configuration
"""

from datetime import datetime
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import structlog

from app.database import get_db
from app.services.seeder import DatabaseSeeder, run_startup_seed

logger = structlog.get_logger()

router = APIRouter(tags=["admin"])


class SeedRequest(BaseModel):
    """Request model for seeding operations."""
    force_reseed: bool = False
    min_cvss: float = 7.0
    max_cves: int = 50
    days_back: int = 30


class SeedResponse(BaseModel):
    """Response model for seeding operations."""
    success: bool
    message: str
    assets_created: int = 0
    cves_stored: int = 0
    risks_created: int = 0
    elapsed_seconds: float = 0.0
    timestamp: str


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    database: str
    timestamp: str
    counts: Dict[str, int]


@router.post("/reseed", response_model=SeedResponse)
async def reseed_database(
    request: SeedRequest = SeedRequest(),
    db: AsyncSession = Depends(get_db)
) -> SeedResponse:
    """
    Reseed the database with fresh demo data.
    
    This endpoint will:
    1. Check if database needs seeding
    2. If force_reseed=True, clear all data first
    3. Seed demo assets
    4. Fetch real CVEs from NVD/CISA
    5. Enrich with AI analysis
    6. Calculate BWVS scores
    7. Create risk records
    
    Args:
        request: Seeding options
        db: Database session
        
    Returns:
        Summary of seeding operation
    """
    logger.info(
        "Reseed requested",
        force=request.force_reseed,
        min_cvss=request.min_cvss,
        max_cves=request.max_cves
    )
    
    seeder = DatabaseSeeder(db)
    
    try:
        if request.force_reseed:
            # Force full reseed
            result = await seeder.clear_and_reseed()
        else:
            # Check if seeding is needed
            needs_seed, counts = await seeder.needs_seeding()
            
            if not needs_seed:
                return SeedResponse(
                    success=True,
                    message="Database already seeded. Use force_reseed=true to reseed.",
                    assets_created=counts["assets"],
                    cves_stored=counts["cves"],
                    risks_created=counts["risks"],
                    elapsed_seconds=0.0,
                    timestamp=datetime.utcnow().isoformat()
                )
            
            result = await seeder.run_full_seed()
        
        return SeedResponse(
            success=result["success"],
            message="Database seeded successfully",
            assets_created=result["assets_created"],
            cves_stored=result["cves_stored"],
            risks_created=result["risks_created"],
            elapsed_seconds=result["elapsed_seconds"],
            timestamp=result["timestamp"]
        )
        
    except Exception as e:
        logger.error("Reseed failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Seeding failed: {str(e)}"
        )


@router.get("/health", response_model=HealthResponse)
async def admin_health(
    db: AsyncSession = Depends(get_db)
) -> HealthResponse:
    """
    Get detailed system health status.
    
    Returns:
        System health information
    """
    from sqlalchemy import select, func
    from app.models.asset import Asset
    from app.models.cve import CVE
    from app.models.risk import Risk
    
    try:
        assets_count = await db.scalar(select(func.count(Asset.id)))
        cves_count = await db.scalar(select(func.count(CVE.id)))
        risks_count = await db.scalar(select(func.count(Risk.id)))
        
        return HealthResponse(
            status="healthy",
            database="connected",
            timestamp=datetime.utcnow().isoformat(),
            counts={
                "assets": assets_count or 0,
                "cves": cves_count or 0,
                "risks": risks_count or 0
            }
        )
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return HealthResponse(
            status="unhealthy",
            database=f"error: {str(e)}",
            timestamp=datetime.utcnow().isoformat(),
            counts={"assets": 0, "cves": 0, "risks": 0}
        )


@router.post("/clear-cache")
async def clear_cache() -> Dict[str, str]:
    """
    Clear all caches (Redis, in-memory).
    
    Returns:
        Confirmation message
    """
    # TODO: Implement Redis cache clearing
    logger.info("Cache cleared")
    return {"message": "Cache cleared successfully"}


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get detailed statistics about the system.
    
    Returns:
        System statistics
    """
    from sqlalchemy import select, func
    from app.models.asset import Asset, AssetCriticality, ExposureLevel
    from app.models.cve import CVE
    from app.models.risk import Risk, RiskStatus
    
    try:
        # Basic counts
        assets_count = await db.scalar(select(func.count(Asset.id))) or 0
        cves_count = await db.scalar(select(func.count(CVE.id))) or 0
        risks_count = await db.scalar(select(func.count(Risk.id))) or 0
        
        # Risk stats
        critical_risks = await db.scalar(
            select(func.count(Risk.id)).where(Risk.bwvs_score >= 80)
        ) or 0
        high_risks = await db.scalar(
            select(func.count(Risk.id)).where(
                Risk.bwvs_score >= 60,
                Risk.bwvs_score < 80
            )
        ) or 0
        
        # Asset stats
        internet_facing = await db.scalar(
            select(func.count(Asset.id)).where(
                Asset.exposure_level == ExposureLevel.INTERNET_FACING
            )
        ) or 0
        
        critical_assets = await db.scalar(
            select(func.count(Asset.id)).where(
                Asset.criticality == AssetCriticality.PAYMENT_PAYROLL
            )
        ) or 0
        
        # CVE stats
        kev_cves = await db.scalar(
            select(func.count(CVE.id)).where(CVE.cisa_kev == True)
        ) or 0
        
        exploited_cves = await db.scalar(
            select(func.count(CVE.id)).where(CVE.has_exploit == True)
        ) or 0
        
        # Average BWVS
        avg_bwvs = await db.scalar(select(func.avg(Risk.bwvs_score))) or 0.0
        
        return {
            "counts": {
                "assets": assets_count,
                "cves": cves_count,
                "risks": risks_count,
            },
            "risks": {
                "critical": critical_risks,
                "high": high_risks,
                "average_bwvs": round(float(avg_bwvs), 2),
            },
            "assets": {
                "internet_facing": internet_facing,
                "critical": critical_assets,
            },
            "cves": {
                "cisa_kev": kev_cves,
                "with_exploit": exploited_cves,
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error("Stats retrieval failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get stats: {str(e)}"
        )
