"""
Contexta Backend - Playbook Schemas

Pydantic schemas for playbook requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field

from app.models.playbook import PlaybookStatus


class PlaybookStep(BaseModel):
    """Schema for a playbook step."""
    order: int
    name: str
    action: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    on_failure: str = "stop"  # "stop", "continue", "retry"
    timeout_seconds: int = 300


class PlaybookCreate(BaseModel):
    """Schema for creating a playbook."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: str = Field(default="general")
    steps: List[PlaybookStep]
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    is_automated: bool = False
    required_permissions: List[str] = Field(default_factory=list)
    estimated_duration: int = Field(default=30, ge=1)


class PlaybookUpdate(BaseModel):
    """Schema for updating a playbook."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = None
    steps: Optional[List[PlaybookStep]] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    is_automated: Optional[bool] = None
    required_permissions: Optional[List[str]] = None
    estimated_duration: Optional[int] = Field(None, ge=1)


class PlaybookResponse(BaseModel):
    """Schema for playbook response."""
    id: UUID
    name: str
    description: Optional[str]
    category: str
    steps: List[Dict[str, Any]]
    trigger_conditions: Dict[str, Any]
    is_active: bool
    is_automated: bool
    required_permissions: List[str]
    estimated_duration: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PlaybookExecutionRequest(BaseModel):
    """Schema for executing a playbook."""
    playbook_id: UUID
    incident_id: Optional[UUID] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class StepResult(BaseModel):
    """Schema for step execution result."""
    step_order: int
    step_name: str
    status: str
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_seconds: float


class PlaybookExecutionResponse(BaseModel):
    """Schema for playbook execution response."""
    id: UUID
    playbook_id: UUID
    incident_id: Optional[UUID]
    status: PlaybookStatus
    executed_by: Optional[UUID]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    step_results: List[StepResult]
    error_message: Optional[str]
    output: Dict[str, Any]
    created_at: datetime
    
    class Config:
        from_attributes = True
