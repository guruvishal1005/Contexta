"""
Contexta Backend - Asset Management Routes

Provides endpoints for asset inventory management.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from app.services.asset_service import AssetService
from app.auth.jwt import get_current_active_user, TokenData

logger = structlog.get_logger()
router = APIRouter()


@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_data: AssetCreate,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new asset in the inventory.
    
    - **name**: Asset name
    - **asset_type**: Type (server, workstation, network_device, etc.)
    - **criticality**: Business criticality (critical, high, medium, low)
    - **ip_address**: Optional IP address
    - **hostname**: Optional hostname
    """
    asset_service = AssetService(db)
    
    asset = await asset_service.create_asset(asset_data.model_dump())
    
    logger.info(
        "Asset created",
        asset_id=str(asset.id),
        user_id=current_user.user_id
    )
    
    return asset


@router.get("/", response_model=List[AssetResponse])
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    asset_type: Optional[str] = None,
    criticality: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all assets with filtering and pagination.
    """
    from app.models.asset import AssetType, AssetCriticality
    
    asset_service = AssetService(db)
    
    # Convert string to enum if provided
    asset_type_enum = None
    criticality_enum = None
    if asset_type:
        try:
            asset_type_enum = AssetType(asset_type)
        except ValueError:
            pass
    if criticality:
        try:
            criticality_enum = AssetCriticality(criticality)
        except ValueError:
            pass
    
    assets, total = await asset_service.list_assets(
        page=page,
        page_size=page_size,
        asset_type=asset_type_enum,
        criticality=criticality_enum
    )
    
    return assets


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific asset.
    """
    asset_service = AssetService(db)
    
    asset = await asset_service.get_asset(asset_id)
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: str,
    update_data: AssetUpdate,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update an existing asset.
    """
    asset_service = AssetService(db)
    
    asset = await asset_service.update_asset(asset_id, update_data)
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    logger.info(
        "Asset updated",
        asset_id=asset_id,
        user_id=current_user.user_id
    )
    
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete an asset from the inventory.
    """
    asset_service = AssetService(db)
    
    deleted = await asset_service.delete_asset(asset_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    logger.info(
        "Asset deleted",
        asset_id=asset_id,
        user_id=current_user.user_id
    )


@router.get("/{asset_id}/vulnerabilities")
async def get_asset_vulnerabilities(
    asset_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all vulnerabilities associated with an asset.
    """
    asset_service = AssetService(db)
    
    vulns = await asset_service.get_asset_vulnerabilities(asset_id)
    
    if vulns is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    return vulns


@router.get("/{asset_id}/risks")
async def get_asset_risks(
    asset_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all risks associated with an asset.
    """
    asset_service = AssetService(db)
    
    risks = await asset_service.get_asset_risks(asset_id)
    
    if risks is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    return risks
