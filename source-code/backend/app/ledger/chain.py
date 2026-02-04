"""
Contexta Backend - Private Blockchain Ledger

Implementation of a private blockchain for immutable audit logging
of all security events, decisions, and actions.

Hash chain: hash = SHA256(prev_hash + data)
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
import hashlib
import json
import structlog

logger = structlog.get_logger()


@dataclass
class Block:
    """
    A block in the blockchain ledger.
    
    Each block contains:
    - index: Block number in the chain
    - timestamp: When the block was created
    - event_type: Type of event being recorded
    - data: Event data payload
    - actor: Who/what initiated the action
    - prev_hash: Hash of the previous block
    - hash: Hash of this block
    - signature: Optional digital signature for actor verification
    - public_key_pem: Optional PEM-encoded public key of the signer
    """
    index: int
    timestamp: str
    event_type: str
    data: Dict[str, Any]
    actor: str
    prev_hash: str
    hash: str = field(default="")
    nonce: int = field(default=0)
    signature: Optional[str] = field(default=None)
    public_key_pem: Optional[str] = field(default=None)
    
    def calculate_hash(self) -> str:
        """
        Calculate SHA256 hash of the block.
        
        Formula: hash = SHA256(prev_hash + data)
        """
        block_content = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "data": self.data,
            "actor": self.actor,
            "prev_hash": self.prev_hash,
            "nonce": self.nonce
        }, sort_keys=True, default=str)
        
        return hashlib.sha256(block_content.encode()).hexdigest()
    
    def signing_payload(self) -> str:
        """
        Generate the payload string used for digital signature.
        
        This is the canonical representation of block data that gets signed.
        """
        return json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "data": self.data,
            "actor": self.actor,
            "prev_hash": self.prev_hash
        }, sort_keys=True, default=str)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary."""
        return asdict(self)


class BlockchainLedger:
    """
    Private blockchain ledger for immutable audit logging.
    
    Provides:
    - Immutable event recording
    - Chain integrity verification
    - Tamper detection
    - Query capabilities
    """
    
    def __init__(self):
        """Initialize the blockchain with a genesis block."""
        self.chain: List[Block] = []
        self._create_genesis_block()
        
        logger.info("Blockchain ledger initialized")
    
    def _create_genesis_block(self) -> Block:
        """Create the first block in the chain."""
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="genesis",
            data={"message": "Contexta Ledger Genesis Block"},
            actor="system",
            prev_hash="0" * 64
        )
        genesis.hash = genesis.calculate_hash()
        self.chain.append(genesis)
        
        logger.info("Genesis block created", hash=genesis.hash[:16])
        
        return genesis
    
    def add_block(
        self,
        event_type: str,
        data: Dict[str, Any],
        actor: str
    ) -> Block:
        """
        Add a new block to the chain.
        
        Args:
            event_type: Type of event (incident_created, analysis_complete, etc.)
            data: Event data payload
            actor: Who initiated the action (user_id, agent_name, system)
            
        Returns:
            The newly created block
        """
        prev_block = self.chain[-1]
        
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            data=data,
            actor=actor,
            prev_hash=prev_block.hash
        )
        new_block.hash = new_block.calculate_hash()
        
        self.chain.append(new_block)
        
        logger.info(
            "Block added to ledger",
            index=new_block.index,
            event_type=event_type,
            hash=new_block.hash[:16]
        )
        
        return new_block
    
    def add_signed_block(
        self,
        event_type: str,
        data: Dict[str, Any],
        actor: str,
        private_key,
        public_key
    ) -> Block:
        """
        Add a new digitally signed block to the chain.
        
        Args:
            event_type: Type of event (incident_created, analysis_complete, etc.)
            data: Event data payload
            actor: Who initiated the action (user_id, agent_name, system)
            private_key: RSA private key for signing
            public_key: RSA public key for verification
            
        Returns:
            The newly created and signed block
        """
        from app.ledger.signature import sign_data, serialize_public_key
        
        prev_block = self.chain[-1]
        
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            data=data,
            actor=actor,
            prev_hash=prev_block.hash
        )
        
        # Sign the block
        payload = new_block.signing_payload()
        new_block.signature = sign_data(private_key, payload)
        new_block.public_key_pem = serialize_public_key(public_key)
        
        # Calculate hash after signature is set
        new_block.hash = new_block.calculate_hash()
        
        self.chain.append(new_block)
        
        logger.info(
            "Signed block added to ledger",
            index=new_block.index,
            event_type=event_type,
            actor=actor,
            hash=new_block.hash[:16],
            signed=True
        )
        
        return new_block
    
    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the entire blockchain.
        
        Checks:
        1. Genesis block is valid
        2. Each block's hash is correctly calculated
        3. Each block's prev_hash matches the previous block's hash
        
        Returns:
            Verification result with any issues found
        """
        issues = []
        
        # Check genesis block
        if not self.chain:
            return {
                "valid": False,
                "issues": ["Chain is empty - no genesis block"]
            }
        
        genesis = self.chain[0]
        if genesis.prev_hash != "0" * 64:
            issues.append("Genesis block has invalid prev_hash")
        
        if genesis.hash != genesis.calculate_hash():
            issues.append("Genesis block hash is corrupted")
        
        # Check remaining blocks
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            
            # Verify hash
            if current.hash != current.calculate_hash():
                issues.append(f"Block {i} hash is corrupted")
            
            # Verify chain link
            if current.prev_hash != previous.hash:
                issues.append(f"Block {i} has broken chain link")
            
            # Verify signature if present
            if current.signature and current.public_key_pem:
                from app.ledger.signature import verify_signature, deserialize_public_key
                try:
                    public_key = deserialize_public_key(current.public_key_pem)
                    payload = current.signing_payload()
                    if not verify_signature(public_key, payload, current.signature):
                        issues.append(f"Block {i} has invalid signature")
                except Exception as e:
                    issues.append(f"Block {i} signature verification error: {str(e)}")
        
        is_valid = len(issues) == 0
        
        logger.info(
            "Chain verification complete",
            valid=is_valid,
            blocks_checked=len(self.chain),
            issues_found=len(issues)
        )
        
        return {
            "valid": is_valid,
            "blocks_verified": len(self.chain),
            "issues": issues if issues else None
        }
    
    def verify_block(self, index: int) -> Dict[str, Any]:
        """
        Verify a specific block.
        
        Args:
            index: Block index to verify
            
        Returns:
            Verification result
        """
        if index < 0 or index >= len(self.chain):
            return {"valid": False, "error": "Block index out of range"}
        
        block = self.chain[index]
        
        # Verify hash
        hash_valid = block.hash == block.calculate_hash()
        
        # Verify chain link (except genesis)
        link_valid = True
        if index > 0:
            previous = self.chain[index - 1]
            link_valid = block.prev_hash == previous.hash
        
        return {
            "valid": hash_valid and link_valid,
            "hash_valid": hash_valid,
            "chain_link_valid": link_valid,
            "block_index": index
        }
    
    def get_block(self, index: int) -> Optional[Block]:
        """Get a block by index."""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_latest_block(self) -> Block:
        """Get the most recent block."""
        return self.chain[-1]
    
    def get_blocks_by_event_type(self, event_type: str) -> List[Block]:
        """
        Query blocks by event type.
        
        Args:
            event_type: Event type to filter by
            
        Returns:
            List of matching blocks
        """
        return [
            block for block in self.chain
            if block.event_type == event_type
        ]
    
    def get_blocks_by_actor(self, actor: str) -> List[Block]:
        """
        Query blocks by actor.
        
        Args:
            actor: Actor to filter by
            
        Returns:
            List of matching blocks
        """
        return [
            block for block in self.chain
            if block.actor == actor
        ]
    
    def get_blocks_in_timerange(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Block]:
        """
        Query blocks within a time range.
        
        Args:
            start_time: Start of range
            end_time: End of range
            
        Returns:
            List of matching blocks
        """
        results = []
        
        for block in self.chain:
            block_time = datetime.fromisoformat(block.timestamp.replace('Z', '+00:00'))
            if start_time <= block_time <= end_time:
                results.append(block)
        
        return results
    
    def search_blocks(
        self,
        query: str,
        field: str = None
    ) -> List[Block]:
        """
        Search blocks for matching content.
        
        Args:
            query: Search query string
            field: Optional specific field to search in
            
        Returns:
            List of matching blocks
        """
        results = []
        query_lower = query.lower()
        
        for block in self.chain:
            if field:
                # Search specific field
                if field == "event_type":
                    if query_lower in block.event_type.lower():
                        results.append(block)
                elif field == "actor":
                    if query_lower in block.actor.lower():
                        results.append(block)
                elif field == "data":
                    if query_lower in json.dumps(block.data).lower():
                        results.append(block)
            else:
                # Search all fields
                searchable = f"{block.event_type} {block.actor} {json.dumps(block.data)}"
                if query_lower in searchable.lower():
                    results.append(block)
        
        return results
    
    def get_chain_stats(self) -> Dict[str, Any]:
        """Get statistics about the blockchain."""
        if not self.chain:
            return {"error": "Chain is empty"}
        
        # Count events by type
        event_counts: Dict[str, int] = {}
        actor_counts: Dict[str, int] = {}
        
        for block in self.chain:
            event_counts[block.event_type] = event_counts.get(block.event_type, 0) + 1
            actor_counts[block.actor] = actor_counts.get(block.actor, 0) + 1
        
        return {
            "total_blocks": len(self.chain),
            "genesis_timestamp": self.chain[0].timestamp,
            "latest_timestamp": self.chain[-1].timestamp,
            "events_by_type": event_counts,
            "events_by_actor": actor_counts,
            "chain_integrity": self.verify_chain()["valid"]
        }
    
    def export_chain(self) -> List[Dict[str, Any]]:
        """Export the entire chain to a list of dictionaries."""
        return [block.to_dict() for block in self.chain]
    
    def export_audit_trail(
        self,
        incident_id: str = None
    ) -> Dict[str, Any]:
        """
        Export an audit trail for compliance purposes.
        
        Args:
            incident_id: Optional incident ID to filter by
            
        Returns:
            Formatted audit trail
        """
        blocks = self.chain
        
        if incident_id:
            blocks = [
                b for b in self.chain
                if b.data.get("incident_id") == incident_id
            ]
        
        return {
            "audit_trail_generated": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(blocks),
            "chain_integrity_verified": self.verify_chain()["valid"],
            "entries": [
                {
                    "sequence": block.index,
                    "timestamp": block.timestamp,
                    "event": block.event_type,
                    "actor": block.actor,
                    "details": block.data,
                    "hash": block.hash,
                    "prev_hash": block.prev_hash
                }
                for block in blocks
            ]
        }


# Event type constants
class LedgerEventTypes:
    """Standard event types for the ledger."""
    GENESIS = "genesis"
    
    # Incident events
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_STATUS_CHANGED = "incident_status_changed"
    INCIDENT_CLOSED = "incident_closed"
    
    # Analysis events
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETE = "analysis_complete"
    AGENT_INVOKED = "agent_invoked"
    CONSENSUS_GENERATED = "consensus_generated"
    
    # Risk events
    RISK_CALCULATED = "risk_calculated"
    RISK_ESCALATED = "risk_escalated"
    RISK_MITIGATED = "risk_mitigated"
    
    # Response events
    PLAYBOOK_TRIGGERED = "playbook_triggered"
    PLAYBOOK_COMPLETED = "playbook_completed"
    ACTION_TAKEN = "action_taken"
    
    # Asset events
    ASSET_COMPROMISED = "asset_compromised"
    ASSET_CONTAINED = "asset_contained"
    ASSET_RECOVERED = "asset_recovered"
    
    # User events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    
    # System events
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    DATA_EXPORTED = "data_exported"
    MANUAL_OVERRIDE = "manual_override"


# Singleton instance
_ledger: Optional[BlockchainLedger] = None


def get_ledger() -> BlockchainLedger:
    """Get or create the blockchain ledger singleton."""
    global _ledger
    if _ledger is None:
        _ledger = BlockchainLedger()
    return _ledger
