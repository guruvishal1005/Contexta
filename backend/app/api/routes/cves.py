"""
Contexta Backend - CVE Management Routes

Provides endpoints for CVE collection and management.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.schemas.cve import CVEResponse
from app.services.cve_service import CVEService
from app.ingestion.cve_collector import CVECollector
from app.auth.jwt import get_current_active_user, TokenData

logger = structlog.get_logger()
router = APIRouter()


# === Public endpoints (no auth required, for frontend dashboard) ===

@router.get("/public/recent")
async def get_recent_cves_public(
    limit: int = Query(20, ge=1, le=100),
    min_cvss: Optional[float] = Query(None, ge=0, le=10),
    db: AsyncSession = Depends(get_db)
):
    """
    Get recent CVEs without authentication (for dashboard display).
    """
    cve_service = CVEService(db)
    cves, total = await cve_service.list_cves(
        page=1,
        page_size=limit,
        min_cvss=min_cvss
    )
    return {
        "cves": [
            {
                "cve_id": c.cve_id,
                "description": c.description[:200] if c.description else "",
                "cvss_score": c.cvss_score,
                "severity": c.severity,
                "has_exploit": c.has_exploit,
                "cisa_kev": c.cisa_kev,
                "affected_software": c.affected_software or [],
                "published_date": c.published_date.isoformat() if c.published_date else None,
                "attack_vector": c.attack_vector,
            }
            for c in cves
        ],
        "total": total
    }


@router.get("/public/stats")
async def get_cve_stats_public(
    db: AsyncSession = Depends(get_db)
):
    """
    Get CVE statistics without authentication.
    """
    cve_service = CVEService(db)
    return await cve_service.get_statistics()


@router.post("/public/collect")
async def trigger_collection_public(
    days_back: int = Query(7, ge=1, le=30),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger CVE collection from NVD + CISA KEV (no auth, for demo).
    """
    collector = CVECollector()
    all_cves = await collector.collect_all(days_back=days_back)
    await collector.close()
    
    cve_service = CVEService(db)
    stored = 0
    for cve_data in all_cves:
        try:
            await cve_service.upsert_cve(cve_data)
            stored += 1
        except Exception as e:
            logger.warning("Failed to upsert CVE", cve_id=cve_data.get("cve_id"), error=str(e))
    await db.commit()
    
    return {"fetched": len(all_cves), "stored": stored, "days_back": days_back}


# === Authenticated endpoints ===


@router.get("/", response_model=List[CVEResponse])
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    min_cvss: Optional[float] = Query(None, ge=0, le=10),
    has_exploit: Optional[bool] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all CVEs with filtering and pagination.
    
    - **page**: Page number (1-indexed)
    - **page_size**: Maximum records to return
    - **severity**: Filter by severity (critical, high, medium, low)
    - **min_cvss**: Minimum CVSS score
    - **has_exploit**: Filter for CVEs with known exploits
    """
    cve_service = CVEService(db)
    
    cves, total = await cve_service.list_cves(
        page=page,
        page_size=page_size,
        severity=severity,
        min_cvss=min_cvss,
        has_exploit=has_exploit
    )
    
    return cves


@router.get("/trending")
async def get_trending_cves(
    limit: int = Query(10, ge=1, le=50),
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get trending CVEs based on recent activity and severity.
    """
    cve_service = CVEService(db)
    
    trending = await cve_service.get_trending_cves(limit=limit)
    
    return {
        "trending_cves": trending,
        "count": len(trending)
    }


@router.get("/stats/summary")
async def get_cve_stats(
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get CVE statistics summary.
    """
    cve_service = CVEService(db)
    
    stats = await cve_service.get_statistics()
    
    return stats


@router.get("/search/by-product")
async def search_cves_by_product(
    product: str,
    vendor: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Search CVEs by affected product.
    """
    cve_service = CVEService(db)
    
    cves = await cve_service.search_by_product(
        product=product,
        vendor=vendor
    )
    
    return {
        "product": product,
        "vendor": vendor,
        "results": cves,
        "count": len(cves)
    }


@router.post("/collect/kev")
async def collect_cisa_kev(
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger collection from CISA Known Exploited Vulnerabilities catalog.
    """
    collector = CVECollector()
    
    cves = await collector.fetch_cisa_kev()
    await collector.close()
    
    # Persist to database
    cve_service = CVEService(db)
    stored = 0
    for cve_data in cves:
        try:
            await cve_service.upsert_cve(cve_data)
            stored += 1
        except Exception as e:
            logger.warning("Failed to upsert CVE", cve_id=cve_data.get("cve_id"), error=str(e))
    await db.commit()
    
    logger.info(
        "CISA KEV collection triggered",
        user_id=current_user.user_id,
        fetched=len(cves),
        stored=stored
    )
    
    return {"fetched": len(cves), "stored": stored}


@router.post("/collect/nvd")
async def collect_nvd_cves(
    days_back: int = Query(7, ge=1, le=30),
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger collection from NVD (National Vulnerability Database).
    
    Note: NVD API is rate-limited. Use sparingly.
    """
    collector = CVECollector()
    
    cves = await collector.fetch_nvd_cves(days_back=days_back)
    await collector.close()
    
    # Persist to database
    cve_service = CVEService(db)
    stored = 0
    for cve_data in cves:
        try:
            await cve_service.upsert_cve(cve_data)
            stored += 1
        except Exception as e:
            logger.warning("Failed to upsert CVE", cve_id=cve_data.get("cve_id"), error=str(e))
    await db.commit()

    logger.info(
        "NVD collection triggered",
        user_id=current_user.user_id,
        days_back=days_back,
        fetched=len(cves),
        stored=stored
    )
    
    return {"fetched": len(cves), "stored": stored, "days_back": days_back}


@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific CVE.
    """
    cve_service = CVEService(db)
    
    cve = await cve_service.get_cve_by_id(cve_id)
    
    if not cve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CVE not found"
        )
    
    return cve
