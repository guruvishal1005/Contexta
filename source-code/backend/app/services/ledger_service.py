"""
Contexta Backend - Ledger Service

This module provides blockchain-style audit ledger capabilities.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
import json
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.ledger import LedgerBlock

logger = structlog.get_logger()


class LedgerService:
    """
    Service for managing the blockchain audit ledger.
    
    Implements a private hash chain: hash = SHA256(prev_hash + data)
    
    Provides methods for:
    - Recording actions to ledger
    - Verifying chain integrity
    - Querying ledger history
    """
    
    def __init__(self, db: AsyncSession):
        """Initialize service with database session."""
        self.db = db
    
    async def get_latest_block(self) -> Optional[LedgerBlock]:
        """
        Get the latest block in the chain.
        
        Returns:
            Latest LedgerBlock or None if chain is empty
        """
        result = await self.db.execute(
            select(LedgerBlock)
            .order_by(LedgerBlock.block_number.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()
    
    async def get_block_by_number(self, block_number: int) -> Optional[LedgerBlock]:
        """
        Get a specific block by number.
        
        Args:
            block_number: Block number to retrieve
            
        Returns:
            LedgerBlock or None
        """
        result = await self.db.execute(
            select(LedgerBlock).where(LedgerBlock.block_number == block_number)
        )
        return result.scalar_one_or_none()
    
    async def initialize_ledger(self) -> LedgerBlock:
        """
        Initialize the ledger with genesis block if not exists.
        
        Returns:
            Genesis block
        """
        genesis = await self.get_block_by_number(0)
        if genesis:
            return genesis
        
        genesis = LedgerBlock.create_genesis_block()
        self.db.add(genesis)
        await self.db.flush()
        logger.info("Created genesis block", hash=genesis.block_hash[:16])
        return genesis
    
    async def record_action(
        self,
        action_type: str,
        actor: str,
        resource_type: str = None,
        resource_id: str = None,
        data: Dict[str, Any] = None
    ) -> LedgerBlock:
        """
        Record an action to the ledger.
        
        Args:
            action_type: Type of action (e.g., 'incident_created', 'risk_updated')
            actor: User/system that performed the action
            resource_type: Type of affected resource
            resource_id: ID of affected resource
            data: Additional action data
            
        Returns:
            Created LedgerBlock
        """
        # Ensure genesis block exists
        await self.initialize_ledger()
        
        # Get latest block
        latest = await self.get_latest_block()
        
        # Prepare block data
        block_data = {
            "action_type": action_type,
            "actor": actor,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data or {}
        }
        data_json = json.dumps(block_data, sort_keys=True)
        
        # Calculate hashes
        data_hash, block_hash = LedgerBlock.calculate_hash(
            latest.block_hash,
            data_json
        )
        
        # Create new block
        block = LedgerBlock(
            block_number=latest.block_number + 1,
            previous_hash=latest.block_hash,
            data=data_json,
            data_hash=data_hash,
            block_hash=block_hash,
            action_type=action_type,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=datetime.utcnow()
        )
        
        self.db.add(block)
        await self.db.flush()
        
        logger.info(
            "Recorded to ledger",
            block_number=block.block_number,
            action=action_type,
            hash=block_hash[:16]
        )
        
        return block
    
    async def verify_chain(
        self,
        start_block: int = 0,
        end_block: int = None
    ) -> Dict[str, Any]:
        """
        Verify the integrity of the blockchain.
        
        Args:
            start_block: Starting block number
            end_block: Ending block number (None for latest)
            
        Returns:
            Verification result with details
        """
        import time
        start_time = time.time()
        
        # Get the block range
        query = select(LedgerBlock).where(LedgerBlock.block_number >= start_block)
        if end_block is not None:
            query = query.where(LedgerBlock.block_number <= end_block)
        query = query.order_by(LedgerBlock.block_number)
        
        result = await self.db.execute(query)
        blocks = list(result.scalars().all())
        
        if not blocks:
            return {
                "is_valid": True,
                "blocks_verified": 0,
                "invalid_blocks": [],
                "verification_time": time.time() - start_time,
                "message": "No blocks to verify"
            }
        
        invalid_blocks = []
        previous_block = None
        
        for block in blocks:
            # For genesis block, verify without previous
            if block.block_number == 0:
                if not block.verify():
                    invalid_blocks.append(block.block_number)
            else:
                # Get previous block if not already have it
                if previous_block is None or previous_block.block_number != block.block_number - 1:
                    prev_result = await self.db.execute(
                        select(LedgerBlock).where(
                            LedgerBlock.block_number == block.block_number - 1
                        )
                    )
                    previous_block = prev_result.scalar_one_or_none()
                
                if not block.verify(previous_block):
                    invalid_blocks.append(block.block_number)
            
            previous_block = block
        
        verification_time = time.time() - start_time
        is_valid = len(invalid_blocks) == 0
        
        # Update verification status
        for block in blocks:
            block.verified = "true" if block.block_number not in invalid_blocks else "false"
        await self.db.flush()
        
        logger.info(
            "Chain verification complete",
            blocks_verified=len(blocks),
            is_valid=is_valid,
            invalid_count=len(invalid_blocks)
        )
        
        return {
            "is_valid": is_valid,
            "blocks_verified": len(blocks),
            "invalid_blocks": invalid_blocks,
            "verification_time": verification_time,
            "message": "Chain is valid" if is_valid else f"Found {len(invalid_blocks)} invalid blocks"
        }
    
    async def list_blocks(
        self,
        page: int = 1,
        page_size: int = 50,
        action_type: str = None,
        actor: str = None,
        resource_type: str = None
    ) -> tuple[List[LedgerBlock], int]:
        """
        List ledger blocks with pagination and filters.
        
        Args:
            page: Page number
            page_size: Items per page
            action_type: Filter by action type
            actor: Filter by actor
            resource_type: Filter by resource type
            
        Returns:
            Tuple of (block list, total count)
        """
        query = select(LedgerBlock)
        count_query = select(func.count(LedgerBlock.id))
        
        if action_type:
            query = query.where(LedgerBlock.action_type == action_type)
            count_query = count_query.where(LedgerBlock.action_type == action_type)
        
        if actor:
            query = query.where(LedgerBlock.actor == actor)
            count_query = count_query.where(LedgerBlock.actor == actor)
        
        if resource_type:
            query = query.where(LedgerBlock.resource_type == resource_type)
            count_query = count_query.where(LedgerBlock.resource_type == resource_type)
        
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        offset = (page - 1) * page_size
        query = query.order_by(LedgerBlock.block_number.desc()).offset(offset).limit(page_size)
        
        result = await self.db.execute(query)
        blocks = result.scalars().all()
        
        return list(blocks), total
    
    async def get_actions_for_resource(
        self,
        resource_type: str,
        resource_id: str
    ) -> List[LedgerBlock]:
        """
        Get all ledger entries for a specific resource.
        
        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            
        Returns:
            List of related blocks
        """
        result = await self.db.execute(
            select(LedgerBlock)
            .where(LedgerBlock.resource_type == resource_type)
            .where(LedgerBlock.resource_id == resource_id)
            .order_by(LedgerBlock.block_number)
        )
        return list(result.scalars().all())
