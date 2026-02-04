"""
Contexta Backend - Ledger Routes

Provides endpoints for blockchain audit ledger access.
"""

from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
import structlog

from app.ledger.chain import get_ledger
from app.auth.jwt import get_current_active_user, TokenData, require_role
from app.models.user import UserRole

logger = structlog.get_logger()
router = APIRouter()


@router.get("/")
async def get_ledger_info(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get ledger information and statistics.
    """
    ledger = get_ledger()
    
    return ledger.get_chain_stats()


@router.post("/log")
async def log_event(
    incident_id: str,
    actor: str,
    action: str,
    event_type: str = "action_taken",
    details: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Log an immutable SOC event into the blockchain ledger.
    
    - **incident_id**: Incident identifier (e.g., INC101)
    - **actor**: Who performed the action (e.g., ResponseAgent, SOC_Analyst)
    - **action**: Description of the action taken
    - **event_type**: Type of event (default: action_taken)
    - **details**: Optional additional details
    """
    ledger = get_ledger()
    
    data = {
        "incident_id": incident_id,
        "action": action,
    }
    if details:
        data["details"] = details
    
    block = ledger.add_block(
        event_type=event_type,
        data=data,
        actor=actor
    )
    
    logger.info(
        "SOC event logged to ledger",
        user_id=current_user.user_id,
        incident_id=incident_id,
        actor=actor,
        block_index=block.index
    )
    
    return block.to_dict()


@router.get("/timeline/{incident_id}")
async def get_incident_timeline(
    incident_id: str,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get the complete blockchain timeline for a specific incident.
    
    Returns all ledger entries related to the given incident ID.
    """
    ledger = get_ledger()
    
    # Search for blocks with this incident_id in their data
    timeline = [
        block.to_dict()
        for block in ledger.chain
        if block.data.get("incident_id") == incident_id
    ]
    
    return {
        "incident_id": incident_id,
        "total_events": len(timeline),
        "timeline": timeline
    }


@router.get("/blocks")
async def get_blocks(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get blocks from the ledger with filtering and pagination.
    
    - **skip**: Number of blocks to skip
    - **limit**: Maximum blocks to return
    - **event_type**: Filter by event type
    - **actor**: Filter by actor
    """
    ledger = get_ledger()
    
    # Get filtered blocks
    if event_type:
        blocks = ledger.get_blocks_by_event_type(event_type)
    elif actor:
        blocks = ledger.get_blocks_by_actor(actor)
    else:
        blocks = ledger.chain
    
    # Apply pagination
    paginated = blocks[skip:skip + limit]
    
    return {
        "blocks": [b.to_dict() for b in paginated],
        "total": len(blocks),
        "skip": skip,
        "limit": limit
    }


@router.get("/blocks/{block_index}")
async def get_block(
    block_index: int,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Get a specific block by index.
    """
    ledger = get_ledger()
    
    block = ledger.get_block(block_index)
    
    if not block:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Block not found"
        )
    
    return block.to_dict()


@router.get("/verify")
async def verify_chain(
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Verify the integrity of the blockchain.
    
    Checks that all hashes are valid and chain links are intact.
    """
    ledger = get_ledger()
    
    result = ledger.verify_chain()
    
    logger.info(
        "Chain verification requested",
        user_id=current_user.user_id,
        valid=result["valid"]
    )
    
    return result


@router.get("/verify/{block_index}")
async def verify_block(
    block_index: int,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Verify a specific block's integrity.
    """
    ledger = get_ledger()
    
    result = ledger.verify_block(block_index)
    
    return result


@router.get("/search")
async def search_blocks(
    query: str,
    field: Optional[str] = Query(None, description="Field to search in (event_type, actor, data)"),
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Search blocks by content.
    """
    ledger = get_ledger()
    
    results = ledger.search_blocks(query, field)
    
    return {
        "query": query,
        "field": field,
        "results": [b.to_dict() for b in results],
        "count": len(results)
    }


@router.get("/audit-trail")
async def get_audit_trail(
    incident_id: Optional[str] = None,
    current_user: TokenData = Depends(get_current_active_user)
):
    """
    Export audit trail for compliance.
    
    Optionally filter by incident ID to get trail for a specific incident.
    """
    ledger = get_ledger()
    
    trail = ledger.export_audit_trail(incident_id=incident_id)
    
    logger.info(
        "Audit trail exported",
        user_id=current_user.user_id,
        incident_id=incident_id,
        entries=trail["total_entries"]
    )
    
    return trail


@router.get("/export")
async def export_ledger(
    current_user: TokenData = Depends(require_role([UserRole.ADMIN]))
):
    """
    Export the entire ledger (admin only).
    """
    ledger = get_ledger()
    
    logger.info(
        "Full ledger export requested",
        user_id=current_user.user_id
    )
    
    return {
        "exported_at": datetime.utcnow().isoformat(),
        "chain": ledger.export_chain(),
        "stats": ledger.get_chain_stats()
    }
