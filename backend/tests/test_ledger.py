"""
Tests for the Blockchain Ledger.
"""

import pytest
from datetime import datetime, timezone, timedelta
from app.ledger.chain import BlockchainLedger, Block, LedgerEventTypes


class TestBlock:
    """Test suite for Block class."""
    
    def test_block_creation(self):
        """Test basic block creation."""
        block = Block(
            index=1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="test_event",
            data={"key": "value"},
            actor="test_user",
            prev_hash="0" * 64
        )
        
        assert block.index == 1
        assert block.event_type == "test_event"
        assert block.data == {"key": "value"}
        assert block.actor == "test_user"
    
    def test_block_hash_calculation(self):
        """Test that block hash is calculated correctly."""
        block = Block(
            index=1,
            timestamp="2024-01-01T00:00:00+00:00",
            event_type="test_event",
            data={"key": "value"},
            actor="test_user",
            prev_hash="0" * 64
        )
        
        hash1 = block.calculate_hash()
        hash2 = block.calculate_hash()
        
        # Hash should be deterministic
        assert hash1 == hash2
        
        # Hash should be 64 characters (SHA256 hex)
        assert len(hash1) == 64
    
    def test_different_blocks_have_different_hashes(self):
        """Test that different blocks produce different hashes."""
        block1 = Block(
            index=1,
            timestamp="2024-01-01T00:00:00+00:00",
            event_type="event1",
            data={"key": "value1"},
            actor="user1",
            prev_hash="0" * 64
        )
        
        block2 = Block(
            index=2,
            timestamp="2024-01-01T00:00:01+00:00",
            event_type="event2",
            data={"key": "value2"},
            actor="user2",
            prev_hash="0" * 64
        )
        
        assert block1.calculate_hash() != block2.calculate_hash()
    
    def test_block_to_dict(self):
        """Test block serialization."""
        block = Block(
            index=1,
            timestamp="2024-01-01T00:00:00+00:00",
            event_type="test_event",
            data={"key": "value"},
            actor="test_user",
            prev_hash="0" * 64,
            hash="abc123"
        )
        
        block_dict = block.to_dict()
        
        assert block_dict["index"] == 1
        assert block_dict["event_type"] == "test_event"
        assert block_dict["hash"] == "abc123"


class TestBlockchainLedger:
    """Test suite for BlockchainLedger class."""
    
    def setup_method(self):
        """Set up fresh ledger for each test."""
        self.ledger = BlockchainLedger()
    
    def test_genesis_block_created(self):
        """Test that genesis block is created on initialization."""
        assert len(self.ledger.chain) == 1
        
        genesis = self.ledger.chain[0]
        assert genesis.index == 0
        assert genesis.event_type == "genesis"
        assert genesis.prev_hash == "0" * 64
    
    def test_add_block(self):
        """Test adding a new block."""
        block = self.ledger.add_block(
            event_type="test_event",
            data={"test": "data"},
            actor="test_user"
        )
        
        assert len(self.ledger.chain) == 2
        assert block.index == 1
        assert block.event_type == "test_event"
        assert block.actor == "test_user"
        assert block.prev_hash == self.ledger.chain[0].hash
    
    def test_chain_integrity(self):
        """Test that chain maintains integrity."""
        # Add several blocks
        for i in range(5):
            self.ledger.add_block(
                event_type=f"event_{i}",
                data={"index": i},
                actor=f"user_{i}"
            )
        
        # Verify chain
        result = self.ledger.verify_chain()
        
        assert result["valid"] is True
        assert result["blocks_verified"] == 6  # Genesis + 5
        assert result["issues"] is None
    
    def test_tamper_detection(self):
        """Test that tampering is detected."""
        # Add a block
        self.ledger.add_block(
            event_type="original_event",
            data={"original": True},
            actor="user"
        )
        
        # Tamper with the block
        self.ledger.chain[1].data = {"tampered": True}
        
        # Verification should fail
        result = self.ledger.verify_chain()
        
        assert result["valid"] is False
        assert len(result["issues"]) > 0
    
    def test_get_blocks_by_event_type(self):
        """Test filtering blocks by event type."""
        self.ledger.add_block("type_a", {"data": 1}, "user")
        self.ledger.add_block("type_b", {"data": 2}, "user")
        self.ledger.add_block("type_a", {"data": 3}, "user")
        
        type_a_blocks = self.ledger.get_blocks_by_event_type("type_a")
        
        assert len(type_a_blocks) == 2
        assert all(b.event_type == "type_a" for b in type_a_blocks)
    
    def test_get_blocks_by_actor(self):
        """Test filtering blocks by actor."""
        self.ledger.add_block("event", {"data": 1}, "alice")
        self.ledger.add_block("event", {"data": 2}, "bob")
        self.ledger.add_block("event", {"data": 3}, "alice")
        
        alice_blocks = self.ledger.get_blocks_by_actor("alice")
        
        assert len(alice_blocks) == 2
        assert all(b.actor == "alice" for b in alice_blocks)
    
    def test_search_blocks(self):
        """Test searching blocks."""
        self.ledger.add_block("event", {"message": "hello world"}, "user")
        self.ledger.add_block("event", {"message": "goodbye"}, "user")
        
        results = self.ledger.search_blocks("hello")
        
        assert len(results) == 1
        assert "hello" in str(results[0].data)
    
    def test_export_chain(self):
        """Test chain export."""
        self.ledger.add_block("event", {"data": 1}, "user")
        
        exported = self.ledger.export_chain()
        
        assert isinstance(exported, list)
        assert len(exported) == 2
        assert exported[0]["event_type"] == "genesis"
    
    def test_audit_trail_export(self):
        """Test audit trail export."""
        self.ledger.add_block(
            "incident_created",
            {"incident_id": "inc-123"},
            "user"
        )
        
        trail = self.ledger.export_audit_trail()
        
        assert "audit_trail_generated" in trail
        assert "total_entries" in trail
        assert trail["chain_integrity_verified"] is True
    
    def test_chain_stats(self):
        """Test chain statistics."""
        self.ledger.add_block("type_a", {}, "user1")
        self.ledger.add_block("type_b", {}, "user2")
        self.ledger.add_block("type_a", {}, "user1")
        
        stats = self.ledger.get_chain_stats()
        
        assert stats["total_blocks"] == 4
        assert stats["events_by_type"]["type_a"] == 2
        assert stats["events_by_actor"]["user1"] == 2


class TestSignatureModule:
    """Test suite for digital signature functionality."""
    
    def test_key_generation(self):
        """Test RSA keypair generation."""
        from app.ledger.signature import generate_keys
        
        private_key, public_key = generate_keys()
        
        assert private_key is not None
        assert public_key is not None
    
    def test_sign_and_verify(self):
        """Test signing and verifying data."""
        from app.ledger.signature import generate_keys, sign_data, verify_signature
        
        private_key, public_key = generate_keys()
        message = "Test message for signing"
        
        signature = sign_data(private_key, message)
        
        assert signature is not None
        assert len(signature) > 0
        assert verify_signature(public_key, message, signature) is True
    
    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected."""
        from app.ledger.signature import generate_keys, sign_data, verify_signature
        
        private_key, public_key = generate_keys()
        message = "Original message"
        
        signature = sign_data(private_key, message)
        
        # Tamper with the message
        tampered_message = "Tampered message"
        
        assert verify_signature(public_key, tampered_message, signature) is False
    
    def test_key_serialization(self):
        """Test key serialization and deserialization."""
        from app.ledger.signature import (
            generate_keys, serialize_public_key, deserialize_public_key,
            sign_data, verify_signature
        )
        
        private_key, public_key = generate_keys()
        
        # Serialize and deserialize
        pem_string = serialize_public_key(public_key)
        restored_key = deserialize_public_key(pem_string)
        
        # Verify signature still works with restored key
        message = "Test message"
        signature = sign_data(private_key, message)
        
        assert verify_signature(restored_key, message, signature) is True


class TestSignedBlocks:
    """Test suite for signed blockchain blocks."""
    
    def setup_method(self):
        """Set up fresh ledger for each test."""
        self.ledger = BlockchainLedger()
    
    def test_add_signed_block(self):
        """Test adding a signed block."""
        from app.ledger.signature import generate_keys
        
        private_key, public_key = generate_keys()
        
        block = self.ledger.add_signed_block(
            event_type="test_signed",
            data={"test": "data"},
            actor="test_actor",
            private_key=private_key,
            public_key=public_key
        )
        
        assert block.signature is not None
        assert block.public_key_pem is not None
        assert len(self.ledger.chain) == 2
    
    def test_signed_block_verification(self):
        """Test that signed blocks pass verification."""
        from app.ledger.signature import generate_keys
        
        private_key, public_key = generate_keys()
        
        self.ledger.add_signed_block(
            event_type="signed_event",
            data={"action": "test"},
            actor="soc_analyst",
            private_key=private_key,
            public_key=public_key
        )
        
        result = self.ledger.verify_chain()
        
        assert result["valid"] is True
    
    def test_tampered_signature_detected(self):
        """Test that tampering with signed block is detected."""
        from app.ledger.signature import generate_keys
        
        private_key, public_key = generate_keys()
        
        block = self.ledger.add_signed_block(
            event_type="signed_event",
            data={"original": True},
            actor="test_actor",
            private_key=private_key,
            public_key=public_key
        )
        
        # Tamper with the block data (but keep signature)
        self.ledger.chain[-1].data = {"tampered": True}
        
        # Verification should fail
        result = self.ledger.verify_chain()
        
        assert result["valid"] is False
