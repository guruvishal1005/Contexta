"""
Contexta Backend - Ledger Model

This module defines the LedgerBlock model for blockchain audit trail.
"""

from sqlalchemy import Column, String, Text, Integer, DateTime
from datetime import datetime
import hashlib
import json

from app.models.base import BaseModel


class LedgerBlock(BaseModel):
    """
    Blockchain ledger block for immutable audit trail.
    
    Implements a private hash chain: hash = SHA256(prev_hash + data)
    
    Attributes:
        block_number: Sequential block number
        previous_hash: Hash of previous block
        data: Block data (JSON string)
        data_hash: SHA256 hash of data
        block_hash: SHA256(previous_hash + data_hash)
        action_type: Type of action recorded
        actor: User/system that performed action
        resource_type: Type of resource affected
        resource_id: ID of affected resource
        timestamp: When action occurred
        verified: Whether block has been verified
    """
    
    __tablename__ = "ledger_blocks"
    
    block_number = Column(Integer, unique=True, index=True, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    data = Column(Text, nullable=False)
    data_hash = Column(String(64), nullable=False)
    block_hash = Column(String(64), unique=True, nullable=False, index=True)
    action_type = Column(String(100), nullable=False, index=True)
    actor = Column(String(255), nullable=False)
    resource_type = Column(String(100), index=True)
    resource_id = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    verified = Column(String(10), default="true")
    
    @staticmethod
    def calculate_hash(previous_hash: str, data: str) -> tuple[str, str]:
        """
        Calculate block hashes.
        
        Args:
            previous_hash: Hash of previous block
            data: Block data as JSON string
            
        Returns:
            Tuple of (data_hash, block_hash)
        """
        data_hash = hashlib.sha256(data.encode()).hexdigest()
        block_hash = hashlib.sha256(f"{previous_hash}{data_hash}".encode()).hexdigest()
        return data_hash, block_hash
    
    @classmethod
    def create_genesis_block(cls) -> "LedgerBlock":
        """Create the genesis (first) block."""
        data = json.dumps({
            "action": "genesis",
            "message": "Contexta Ledger Genesis Block",
            "timestamp": datetime.utcnow().isoformat()
        })
        genesis_hash = "0" * 64
        data_hash, block_hash = cls.calculate_hash(genesis_hash, data)
        
        return cls(
            block_number=0,
            previous_hash=genesis_hash,
            data=data,
            data_hash=data_hash,
            block_hash=block_hash,
            action_type="genesis",
            actor="system",
            resource_type="ledger",
            resource_id="genesis"
        )
    
    def verify(self, previous_block: "LedgerBlock" = None) -> bool:
        """
        Verify block integrity.
        
        Args:
            previous_block: Previous block for chain verification
            
        Returns:
            True if block is valid, False otherwise
        """
        # Verify data hash
        expected_data_hash = hashlib.sha256(self.data.encode()).hexdigest()
        if self.data_hash != expected_data_hash:
            return False
        
        # Verify block hash
        expected_block_hash = hashlib.sha256(
            f"{self.previous_hash}{self.data_hash}".encode()
        ).hexdigest()
        if self.block_hash != expected_block_hash:
            return False
        
        # Verify chain linkage if previous block provided
        if previous_block and self.previous_hash != previous_block.block_hash:
            return False
        
        return True
    
    def __repr__(self) -> str:
        return f"<LedgerBlock(number={self.block_number}, action={self.action_type}, hash={self.block_hash[:16]}...)>"
