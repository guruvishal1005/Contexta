# Digital Twin Engine

## Overview

The Digital Twin Engine uses NetworkX to create a virtual representation of your organization's network infrastructure. This enables attack path analysis, lateral movement simulation, and blast radius calculations.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Digital Twin Engine                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    NetworkX DiGraph                       │  │
│  │                                                           │  │
│  │    [DMZ Server]──────┬─────[Web Server]                  │  │
│  │          │           │           │                        │  │
│  │    [Firewall]────[App Server]────┤                       │  │
│  │          │           │           │                        │  │
│  │    [DB Server]───────┴─────[File Server]                 │  │
│  │          │                       │                        │  │
│  │    [Backup]──────────────[Domain Controller]             │  │
│  │                                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │
│  │Attack Path │ │  Lateral   │ │   Blast    │ │  Critical  │  │
│  │  Analysis  │ │  Movement  │ │   Radius   │ │   Paths    │  │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Graph Structure

### Nodes (Assets)
Each node represents an asset with metadata:
```python
{
    "id": "asset-001",
    "type": "server",
    "name": "Web Server 1",
    "criticality": "high",
    "zone": "dmz",
    "compromised": False,
    "metadata": {...}
}
```

### Edges (Connections)
Edges represent network connectivity:
```python
{
    "type": "network",
    "protocols": ["tcp", "https"],
    "weight": 1.0
}
```

## Features

### 1. Attack Path Discovery

#### BFS (Breadth-First Search)
Finds shortest paths first. Optimal for:
- Finding quickest attack routes
- Identifying minimum hop attacks
- Emergency triage scenarios

```python
paths = twin.find_attack_paths_bfs(
    start_id="compromised-host",
    target_id="critical-database",
    max_depth=10
)
```

#### DFS (Depth-First Search)
Explores all possible paths. Optimal for:
- Comprehensive attack surface analysis
- Finding all possible routes
- Security assessments

```python
paths = twin.find_attack_paths_dfs(
    start_id="compromised-host",
    target_id="critical-database",
    max_depth=10
)
```

### 2. Lateral Movement Simulation

Simulates attacker spread through the network:

```python
result = twin.simulate_lateral_movement(
    initial_compromise="infected-workstation",
    time_steps=10,
    propagation_probability=0.3
)
```

**Output**:
```json
{
  "initial_compromise": "infected-workstation",
  "total_compromised": 7,
  "compromised_assets": ["..."],
  "critical_assets_compromised": ["dc-001"],
  "timeline": [
    {"time_step": 0, "newly_compromised": ["infected-workstation"]},
    {"time_step": 1, "newly_compromised": ["server-001", "server-002"]},
    ...
  ],
  "propagation_rate": 0.7
}
```

**Factors affecting propagation**:
- Base probability (configurable)
- Vulnerability presence
- Network exploitable CVEs
- CVSS scores

### 3. Blast Radius Calculation

Calculates impact if an asset is compromised:

```python
result = twin.calculate_blast_radius(
    asset_id="critical-server",
    max_hops=3
)
```

**Output**:
```json
{
  "source_asset": "critical-server",
  "total_affected_assets": 12,
  "affected_by_hop": {
    "1": 4,
    "2": 5,
    "3": 3
  },
  "affected_by_criticality": {
    "critical": 2,
    "high": 4,
    "medium": 4,
    "low": 2
  },
  "risk_score": 45.7,
  "critical_assets_at_risk": ["dc-001", "db-001"]
}
```

### 4. Critical Path Identification

Finds paths from entry points to critical assets:

```python
paths = twin.find_critical_paths()
```

**Logic**:
1. Identify entry points (DMZ, external-facing)
2. Identify critical targets (criticality = critical)
3. Find all paths between them
4. Score by risk factors
5. Return top 20 paths

## Vulnerability Integration

Associate vulnerabilities with assets:

```python
twin.add_vulnerability(
    asset_id="server-001",
    cve_id="CVE-2024-1234",
    cvss_score=9.8,
    exploitable=True,
    network_exploitable=True
)
```

Vulnerabilities affect:
- Lateral movement probability
- Path risk scoring
- Blast radius calculations

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/twin/stats` | Network statistics |
| `GET /api/twin/attack-paths/bfs` | BFS path finding |
| `GET /api/twin/attack-paths/dfs` | DFS path finding |
| `POST /api/twin/simulate/lateral-movement` | Movement simulation |
| `GET /api/twin/blast-radius/{id}` | Blast radius |
| `GET /api/twin/critical-paths` | Critical paths |

## Usage Example

```python
from app.twin.engine import get_twin_engine

# Get engine instance
twin = get_twin_engine()

# Add assets
twin.add_asset("web-01", "server", "Web Server", "high", "dmz")
twin.add_asset("app-01", "server", "App Server", "critical", "internal")
twin.add_asset("db-01", "database", "Database", "critical", "internal")

# Add connections
twin.add_connection("web-01", "app-01", bidirectional=True)
twin.add_connection("app-01", "db-01", protocols=["tcp-3306"])

# Add vulnerabilities
twin.add_vulnerability("web-01", "CVE-2024-1234", 9.8, True, True)

# Find attack paths
paths = twin.find_attack_paths_bfs("web-01", "db-01")

# Simulate compromise
sim = twin.simulate_lateral_movement("web-01", time_steps=5)

# Get blast radius
blast = twin.calculate_blast_radius("app-01", max_hops=2)
```

## Best Practices

1. **Keep twin synchronized** with asset inventory
2. **Regular updates** when network changes
3. **Run simulations** before major changes
4. **Use for incident response** to predict spread
5. **Integrate with risk scoring** for BWVS context
