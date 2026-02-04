# Private Blockchain Ledger

## Overview

Contexta uses a private blockchain for immutable audit logging of all security events, decisions, and actions. This ensures complete traceability and tamper detection for compliance and forensic purposes.

## Design

### Hash Chain
Each block's hash is calculated as:
```
hash = SHA256(prev_hash + data)
```

This creates an immutable chain where any modification to historical data will be detected.

### Block Structure

```json
{
  "index": 1,
  "timestamp": "2024-01-15T10:30:00+00:00",
  "event_type": "incident_created",
  "data": {
    "incident_id": "inc-123",
    "title": "Malware Detection",
    "severity": "high"
  },
  "actor": "user-456",
  "prev_hash": "a4b3c2d1...",
  "hash": "e5f6g7h8...",
  "nonce": 0
}
```

## Event Types

### Incident Events
| Event Type | Description |
|------------|-------------|
| `incident_created` | New incident created |
| `incident_updated` | Incident details modified |
| `incident_status_changed` | Status transition |
| `incident_closed` | Incident closed |

### Analysis Events
| Event Type | Description |
|------------|-------------|
| `analysis_started` | Agent analysis initiated |
| `analysis_complete` | Analysis finished |
| `agent_invoked` | Specific agent called |
| `consensus_generated` | Orchestrator consensus |

### Risk Events
| Event Type | Description |
|------------|-------------|
| `risk_calculated` | BWVS score computed |
| `risk_escalated` | Risk escalated |
| `risk_mitigated` | Risk marked mitigated |

### Response Events
| Event Type | Description |
|------------|-------------|
| `playbook_triggered` | Playbook execution started |
| `playbook_completed` | Playbook finished |
| `action_taken` | Response action executed |

### Asset Events
| Event Type | Description |
|------------|-------------|
| `asset_compromised` | Asset marked compromised |
| `asset_contained` | Asset isolated |
| `asset_recovered` | Asset restored |

### User Events
| Event Type | Description |
|------------|-------------|
| `user_login` | User authentication |
| `user_logout` | User logout |
| `access_granted` | Access approval |
| `access_denied` | Access rejection |

### System Events
| Event Type | Description |
|------------|-------------|
| `system_config_changed` | Configuration modified |
| `data_exported` | Data export |
| `manual_override` | Manual override action |

## Features

### Chain Verification
Verify entire chain integrity:
```python
result = ledger.verify_chain()
# Returns: {"valid": True, "blocks_verified": 100}
```

### Block Verification
Verify specific block:
```python
result = ledger.verify_block(index=50)
# Returns: {"valid": True, "hash_valid": True, "chain_link_valid": True}
```

### Querying

**By Event Type**:
```python
blocks = ledger.get_blocks_by_event_type("incident_created")
```

**By Actor**:
```python
blocks = ledger.get_blocks_by_actor("user-123")
```

**By Time Range**:
```python
blocks = ledger.get_blocks_in_timerange(start_time, end_time)
```

**Search**:
```python
blocks = ledger.search_blocks("malware", field="data")
```

### Audit Trail Export
Export audit trail for compliance:
```python
trail = ledger.export_audit_trail(incident_id="inc-123")
```

Output:
```json
{
  "audit_trail_generated": "2024-01-15T15:00:00Z",
  "total_entries": 25,
  "chain_integrity_verified": true,
  "entries": [
    {
      "sequence": 10,
      "timestamp": "2024-01-15T10:00:00Z",
      "event": "incident_created",
      "actor": "user-123",
      "details": {...},
      "hash": "abc123...",
      "prev_hash": "def456..."
    },
    ...
  ]
}
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/ledger` | Ledger statistics |
| `GET /api/ledger/blocks` | List blocks |
| `GET /api/ledger/blocks/{index}` | Get specific block |
| `GET /api/ledger/verify` | Verify chain |
| `GET /api/ledger/search` | Search blocks |
| `GET /api/ledger/audit-trail` | Export audit trail |

## Usage

### Adding Events
```python
from app.ledger.chain import get_ledger, LedgerEventTypes

ledger = get_ledger()

# Add incident creation event
ledger.add_block(
    event_type=LedgerEventTypes.INCIDENT_CREATED,
    data={
        "incident_id": "inc-123",
        "title": "Ransomware Attack",
        "severity": "critical"
    },
    actor="user-456"
)
```

### Verification
```python
# Verify entire chain
result = ledger.verify_chain()
if not result["valid"]:
    print(f"Chain compromised! Issues: {result['issues']}")

# Verify specific block
block_result = ledger.verify_block(50)
```

### Statistics
```python
stats = ledger.get_chain_stats()
print(f"Total blocks: {stats['total_blocks']}")
print(f"Events by type: {stats['events_by_type']}")
```

## Tamper Detection

If any block is modified:

1. Its hash will no longer match the stored hash
2. The next block's `prev_hash` will not match
3. `verify_chain()` will return `valid: False` with issues

Example tamper scenario:
```python
# Original chain is valid
assert ledger.verify_chain()["valid"] == True

# Attacker modifies historical data
ledger.chain[5].data["severity"] = "low"  # Changed from "critical"

# Chain verification detects tampering
result = ledger.verify_chain()
assert result["valid"] == False
assert "Block 5 hash is corrupted" in result["issues"]
```

## Compliance Benefits

1. **Non-repudiation**: Actions cannot be denied
2. **Traceability**: Complete history of all events
3. **Tamper-evident**: Any modification is detectable
4. **Audit-ready**: Export trails for regulators
5. **Chain of custody**: Evidence integrity

## Regulatory Alignment

- **CERT-In**: Incident timeline documentation
- **ISO 27001**: Audit logging requirements
- **SOC 2**: Change management evidence
- **GDPR**: Data processing records
- **SEBI**: Cyber incident reporting

## Best Practices

1. **Regular verification**: Run daily chain verification
2. **Off-site backup**: Export and store chain periodically
3. **Monitor integrity**: Alert on verification failures
4. **Minimal data**: Store references, not full data
5. **Actor tracking**: Always include actor ID
