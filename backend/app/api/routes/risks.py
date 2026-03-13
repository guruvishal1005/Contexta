"""
Contexta Backend - Risk Management Routes

Provides endpoints for risk scores and the Top-10 risk list.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.schemas.risk import RiskResponse, TopRisksResponse
from app.services.risk_service import RiskService
from app.auth.jwt import get_current_active_user, TokenData

logger = structlog.get_logger()
router = APIRouter()


@router.get("/top10/public", response_model=TopRisksResponse)
async def get_top_10_risks_public(
    db: AsyncSession = Depends(get_db)
):
    """
    Get the Top 10 prioritized risks (PUBLIC - no auth required).
    
    This endpoint is for demo purposes and provides public access
    to the Top 10 risks dashboard.
    
    Returns the highest priority risks based on:
    - BWVS (Business-Weighted Vulnerability Score)
    - Freshness (how recent the threat is)
    - Trend Factor (velocity of spread)
    
    Priority Formula: BWVS × Freshness × TrendFactor
    """
    risk_service = RiskService(db)
    
    top_risks = await risk_service.get_top_risks(limit=10)
    
    logger.info(
        "Top 10 risks retrieved (public)",
        risks_count=len(top_risks)
    )
    
    from datetime import datetime
    return TopRisksResponse(
        risks=top_risks,
        last_calculated=datetime.utcnow(),
        calculation_interval_minutes=5
    )


@router.get("/top10", response_model=TopRisksResponse)
async def get_top_10_risks(
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the Top 10 prioritized risks.
    
    Returns the highest priority risks based on:
    - BWVS (Business-Weighted Vulnerability Score)
    - Freshness (how recent the threat is)
    - Trend Factor (velocity of spread)
    
    Priority Formula: BWVS × Freshness × TrendFactor
    """
    risk_service = RiskService(db)
    
    top_risks = await risk_service.get_top_risks(limit=10)
    
    logger.info(
        "Top 10 risks retrieved",
        user_id=current_user.user_id,
        risks_count=len(top_risks)
    )
    
    from datetime import datetime
    return TopRisksResponse(
        risks=top_risks,
        last_calculated=datetime.utcnow(),
        calculation_interval_minutes=5
    )


@router.get("/stats/summary")
async def get_risk_stats(
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get summary statistics of all risks.
    """
    risk_service = RiskService(db)
    
    stats = await risk_service.get_risk_statistics()
    
    return stats


@router.get("/", response_model=List[RiskResponse])
async def list_risks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status: Optional[str] = None,
    min_bwvs: Optional[float] = Query(None, ge=0, le=100),
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all risks with filtering and pagination.
    
    - **page**: Page number (1-indexed)
    - **page_size**: Maximum records to return (max 100)
    - **status**: Filter by risk status (open, mitigated, accepted, transferred)
    - **min_bwvs**: Minimum BWVS score
    """
    from app.models.risk import RiskStatus
    
    risk_service = RiskService(db)
    
    # Convert string to enum if provided
    status_enum = None
    if status:
        try:
            status_enum = RiskStatus(status)
        except ValueError:
            pass
    
    risks, total = await risk_service.list_risks(
        page=page,
        page_size=page_size,
        status=status_enum,
        min_bwvs=min_bwvs
    )
    
    return risks


@router.get("/{risk_id}", response_model=RiskResponse)
async def get_risk(
    risk_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific risk.
    """
    risk_service = RiskService(db)
    
    risk = await risk_service.get_risk(risk_id)
    
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk not found"
        )
    
    return risk


@router.post("/{risk_id}/recalculate", response_model=RiskResponse)
async def recalculate_risk(
    risk_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Manually trigger recalculation of a risk's BWVS score.
    """
    risk_service = RiskService(db)
    
    risk = await risk_service.recalculate_risk(risk_id)
    
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk not found"
        )
    
    logger.info(
        "Risk recalculated",
        risk_id=risk_id,
        user_id=current_user.user_id,
        new_bwvs=risk.bwvs_score
    )
    
    return risk


@router.put("/{risk_id}/status")
async def update_risk_status(
    risk_id: str,
    new_status: str,
    notes: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update the status of a risk.
    
    Valid statuses: open, mitigated, accepted, transferred
    """
    valid_statuses = ["open", "mitigated", "accepted", "transferred"]
    
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    
    risk_service = RiskService(db)
    
    risk = await risk_service.update_risk_status(
        risk_id=risk_id,
        new_status=new_status,
        notes=notes,
        updated_by=current_user.user_id
    )
    
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk not found"
        )
    
    logger.info(
        "Risk status updated",
        risk_id=risk_id,
        new_status=new_status,
        user_id=current_user.user_id
    )
    
    return {"message": "Risk status updated", "risk_id": risk_id, "status": new_status}
