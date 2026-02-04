"""
Contexta Backend - Incident Management Routes

Provides endpoints for incident lifecycle management.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.schemas.incident import IncidentCreate, IncidentResponse, IncidentUpdate
from app.services.incident_service import IncidentService
from app.auth.jwt import get_current_active_user, TokenData
from app.ledger.chain import get_ledger, LedgerEventTypes

logger = structlog.get_logger()
router = APIRouter()


@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: IncidentCreate,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new security incident.
    
    - **title**: Incident title
    - **description**: Detailed description
    - **severity**: Severity level (critical, high, medium, low)
    - **affected_asset_ids**: List of affected asset IDs
    """
    incident_service = IncidentService(db)
    
    incident = await incident_service.create_incident(
        title=incident_data.title,
        description=incident_data.description,
        risk_id=incident_data.risk_id,
        severity=incident_data.severity,
        created_by=current_user.user_id,
        assigned_to=incident_data.assigned_to,
        affected_assets=incident_data.affected_assets,
        iocs=incident_data.iocs
    )
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.INCIDENT_CREATED,
        data={
            "incident_id": str(incident.id),
            "title": incident.title,
            "severity": incident.severity
        },
        actor=current_user.user_id
    )
    
    logger.info(
        "Incident created",
        incident_id=str(incident.id),
        user_id=current_user.user_id
    )
    
    return incident


@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all incidents with filtering and pagination.
    """
    from app.models.incident import IncidentStatus, IncidentSeverity
    
    incident_service = IncidentService(db)
    
    # Convert string filters to enums if provided
    status = None
    severity = None
    if status_filter:
        try:
            status = IncidentStatus(status_filter)
        except ValueError:
            pass
    if severity_filter:
        try:
            severity = IncidentSeverity(severity_filter)
        except ValueError:
            pass
    
    incidents, total = await incident_service.list_incidents(
        page=page,
        page_size=page_size,
        status=status,
        severity=severity
    )
    
    return incidents


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific incident.
    """
    incident_service = IncidentService(db)
    
    incident = await incident_service.get_incident(incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return incident


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    update_data: IncidentUpdate,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update an existing incident.
    """
    incident_service = IncidentService(db)
    
    incident = await incident_service.update_incident(
        incident_id,
        update_data,
        updated_by=current_user.user_id
    )
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.INCIDENT_UPDATED,
        data={
            "incident_id": incident_id,
            "updates": update_data.model_dump(exclude_unset=True)
        },
        actor=current_user.user_id
    )
    
    return incident


@router.post("/{incident_id}/start")
async def start_incident_response(
    incident_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start incident response workflow.
    
    This triggers:
    1. Multi-agent analysis
    2. Playbook recommendations
    3. Status update to 'investigating'
    """
    incident_service = IncidentService(db)
    
    result = await incident_service.start_response(
        incident_id,
        initiated_by=current_user.user_id
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.INCIDENT_STATUS_CHANGED,
        data={
            "incident_id": incident_id,
            "new_status": "investigating",
            "action": "response_started"
        },
        actor=current_user.user_id
    )
    
    logger.info(
        "Incident response started",
        incident_id=incident_id,
        user_id=current_user.user_id
    )
    
    return result


@router.post("/{incident_id}/close")
async def close_incident(
    incident_id: str,
    resolution_notes: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Close an incident with resolution notes.
    """
    incident_service = IncidentService(db)
    
    incident = await incident_service.close_incident(
        incident_id,
        resolution_notes=resolution_notes,
        closed_by=current_user.user_id
    )
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.INCIDENT_CLOSED,
        data={
            "incident_id": incident_id,
            "resolution": resolution_notes[:500]  # Truncate for ledger
        },
        actor=current_user.user_id
    )
    
    logger.info(
        "Incident closed",
        incident_id=incident_id,
        user_id=current_user.user_id
    )
    
    return {"message": "Incident closed", "incident_id": incident_id}


@router.get("/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the timeline of events for an incident.
    """
    incident_service = IncidentService(db)
    
    timeline = await incident_service.get_timeline(incident_id)
    
    if timeline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return timeline
