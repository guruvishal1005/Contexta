"""
Contexta Backend - Playbook Routes

Provides endpoints for playbook management and execution.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.database import get_db
from app.schemas.playbook import PlaybookCreate, PlaybookResponse, PlaybookExecutionResponse
from app.services.playbook_service import PlaybookService
from app.auth.jwt import get_current_active_user, TokenData
from app.ledger.chain import get_ledger, LedgerEventTypes

logger = structlog.get_logger()
router = APIRouter()


@router.get("/", response_model=List[PlaybookResponse])
async def list_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    category: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all available playbooks.
    """
    playbook_service = PlaybookService(db)
    
    playbooks, total = await playbook_service.list_playbooks(
        page=page,
        page_size=page_size,
        category=category
    )
    
    return playbooks


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific playbook.
    """
    playbook_service = PlaybookService(db)
    
    playbook = await playbook_service.get_playbook(playbook_id)
    
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    return playbook


@router.post("/", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    playbook_data: PlaybookCreate,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new playbook.
    """
    playbook_service = PlaybookService(db)
    
    data = playbook_data.model_dump()
    data["created_by"] = current_user.user_id
    
    playbook = await playbook_service.create_playbook(data)
    
    logger.info(
        "Playbook created",
        playbook_id=str(playbook.id),
        user_id=current_user.user_id
    )
    
    return playbook


@router.post("/{playbook_id}/execute", response_model=PlaybookExecutionResponse)
async def execute_playbook(
    playbook_id: str,
    incident_id: str,
    parameters: Optional[dict] = None,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Execute a playbook for a specific incident.
    
    - **playbook_id**: ID of the playbook to execute
    - **incident_id**: ID of the incident to run the playbook against
    - **parameters**: Optional parameters for the playbook
    """
    playbook_service = PlaybookService(db)
    
    # Verify playbook exists
    playbook = await playbook_service.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    # Execute playbook
    execution = await playbook_service.execute_playbook(
        playbook_id=playbook_id,
        incident_id=incident_id,
        parameters=parameters or {},
        executed_by=current_user.user_id
    )
    
    # Log to ledger
    ledger = get_ledger()
    ledger.add_block(
        event_type=LedgerEventTypes.PLAYBOOK_TRIGGERED,
        data={
            "playbook_id": playbook_id,
            "playbook_name": playbook.name,
            "incident_id": incident_id,
            "execution_id": str(execution.id)
        },
        actor=current_user.user_id
    )
    
    logger.info(
        "Playbook execution started",
        playbook_id=playbook_id,
        incident_id=incident_id,
        user_id=current_user.user_id
    )
    
    return execution


@router.get("/{playbook_id}/executions")
async def get_playbook_executions(
    playbook_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get execution history for a playbook.
    """
    playbook_service = PlaybookService(db)
    
    executions = await playbook_service.get_playbook_executions(
        playbook_id=playbook_id,
        skip=skip,
        limit=limit
    )
    
    return executions


@router.get("/executions/{execution_id}")
async def get_execution_status(
    execution_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get status of a specific playbook execution.
    """
    playbook_service = PlaybookService(db)
    
    execution = await playbook_service.get_execution(execution_id)
    
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    return execution


@router.post("/executions/{execution_id}/cancel")
async def cancel_execution(
    execution_id: str,
    current_user: TokenData = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Cancel a running playbook execution.
    """
    playbook_service = PlaybookService(db)
    
    result = await playbook_service.cancel_execution(
        execution_id,
        cancelled_by=current_user.user_id
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found or already completed"
        )
    
    logger.info(
        "Playbook execution cancelled",
        execution_id=execution_id,
        user_id=current_user.user_id
    )
    
    return {"message": "Execution cancelled", "execution_id": execution_id}
