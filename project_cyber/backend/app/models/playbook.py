"""
Contexta Backend - Playbook Model

This module defines the Playbook and PlaybookExecution models.
"""

from sqlalchemy import Column, String, Text, Integer, Boolean, JSON, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy import Uuid as UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.models.base import BaseModel


class PlaybookStatus(str, enum.Enum):
    """Playbook execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Playbook(BaseModel):
    """
    Playbook model for automated response procedures.
    
    Attributes:
        name: Playbook name
        description: Playbook description
        category: Playbook category (incident_response, remediation, etc.)
        steps: Ordered list of steps (JSON array)
        trigger_conditions: Conditions that trigger playbook (JSON)
        is_active: Whether playbook is enabled
        is_automated: Whether playbook runs automatically
        required_permissions: Required user permissions (JSON array)
        estimated_duration: Estimated execution time in minutes
    """
    
    __tablename__ = "playbooks"
    
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    category = Column(String(100), index=True)
    steps = Column(JSON, nullable=False, default=list)
    trigger_conditions = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    is_automated = Column(Boolean, default=False)
    required_permissions = Column(JSON, default=list)
    estimated_duration = Column(Integer, default=30)
    
    # Relationships
    executions = relationship("PlaybookExecution", back_populates="playbook", lazy="dynamic")
    
    def __repr__(self) -> str:
        return f"<Playbook(name={self.name}, category={self.category})>"


class PlaybookExecution(BaseModel):
    """
    Playbook execution record.
    
    Attributes:
        playbook_id: Executed playbook
        incident_id: Related incident (optional)
        status: Execution status
        executed_by: User who triggered execution
        started_at: Execution start time
        completed_at: Execution completion time
        step_results: Results of each step (JSON array)
        error_message: Error message if failed
        output: Final execution output (JSON)
    """
    
    __tablename__ = "playbook_executions"
    
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("playbooks.id"), nullable=False, index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    status = Column(SQLEnum(PlaybookStatus), default=PlaybookStatus.PENDING, index=True)
    executed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    step_results = Column(JSON, default=list)
    error_message = Column(Text)
    output = Column(JSON, default=dict)
    
    # Relationships
    playbook = relationship("Playbook", back_populates="executions")
    
    def start(self) -> None:
        """Mark execution as started."""
        self.status = PlaybookStatus.RUNNING
        self.started_at = datetime.utcnow()
    
    def complete(self, output: dict = None) -> None:
        """Mark execution as completed."""
        self.status = PlaybookStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if output:
            self.output = output
    
    def fail(self, error: str) -> None:
        """Mark execution as failed."""
        self.status = PlaybookStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = error
    
    def __repr__(self) -> str:
        return f"<PlaybookExecution(playbook_id={self.playbook_id}, status={self.status})>"
