"""
Contexta Backend - Ledger Schemas

Pydantic schemas for blockchain ledger requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field


class LedgerBlockResponse(BaseModel):
    """Schema for ledger block response."""
    id: UUID
    block_number: int
    previous_hash: str
    data: str
    data_hash: str
    block_hash: str
    action_type: str
    actor: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    timestamp: datetime
    verified: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class LedgerListResponse(BaseModel):
    """Schema for paginated ledger list response."""
    items: List[LedgerBlockResponse]
    total: int
    page: int
    page_size: int
    pages: int


class LedgerVerifyRequest(BaseModel):
    """Schema for verifying a range of blocks."""
    start_block: int = Field(default=0, ge=0)
    end_block: Optional[int] = None


class LedgerVerifyResponse(BaseModel):
    """Schema for ledger verification response."""
    is_valid: bool
    blocks_verified: int
    invalid_blocks: List[int] = Field(default_factory=list)
    verification_time: float
    message: str


class LedgerRecordRequest(BaseModel):
    """Schema for recording an action to the ledger."""
    action_type: str = Field(..., min_length=1, max_length=100)
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
