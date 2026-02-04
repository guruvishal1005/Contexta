# Contexta Backend API Documentation

## Overview

All API endpoints are prefixed with `/api` and run on `http://localhost:8000`

**Base URL:** `http://localhost:8000/api`

---

## 1. Authentication Routes (`/auth`)

### POST `/auth/register`

**Purpose:** Register a new user account
**Authentication:** None
**Parameters:**

- `email` - User's email (must be unique)
- `password` - Password (min 8 characters)
- `username` - Username (must be unique)
- `full_name` - User's full name
  **Response:** User object with ID and details
  **Tasks:** Creates user in database, logs to blockchain ledger

### POST `/auth/login`

**Purpose:** Authenticate user and receive tokens
**Authentication:** None
**Parameters:**

- `username` - Email address
- `password` - User password
  **Response:** JWT access token + refresh token
  **Tasks:** Validates credentials, generates JWT tokens, logs login event

### POST `/auth/refresh`

**Purpose:** Refresh expired access token using refresh token
**Authentication:** Refresh token required
**Response:** New JWT access token
**Tasks:** Validates refresh token, generates new access token

### GET `/auth/me`

**Purpose:** Get current authenticated user's profile
**Authentication:** JWT token required
**Response:** Current user object with role and details
**Tasks:** Returns authenticated user information

### POST `/auth/logout`

**Purpose:** Logout current user
**Authentication:** JWT token required
**Response:** Success message
**Tasks:** Invalidates session, logs logout event

---

## 2. Risk Management Routes (`/risks`)

### GET `/risks/top10`

**Purpose:** Get the top 10 prioritized risks
**Authentication:** JWT token required
**Formula Used:** Priority = BWVS × Freshness × TrendFactor
**Response:** List of top 10 risks with BWVS scores
**Tasks:** Calculates BWVS scores, applies freshness weighting, ranks by trend factor

### GET `/risks/stats/summary`

**Purpose:** Get risk statistics summary
**Authentication:** JWT token required
**Response:** Risk counts by severity, status distribution
**Tasks:** Aggregates risk data, calculates statistics

### GET `/risks/`

**Purpose:** List all risks with filtering and pagination
**Authentication:** JWT token required
**Query Parameters:**

- `page` - Page number (default 1)
- `page_size` - Records per page (default 50, max 100)
- `status` - Filter by status (open, mitigated, accepted, transferred)
- `min_bwvs` - Minimum BWVS score
  **Response:** Paginated list of risk objects
  **Tasks:** Filters risks, applies pagination, returns matching risks

### GET `/risks/{risk_id}`

**Purpose:** Get details of a specific risk
**Authentication:** JWT token required
**Response:** Single risk object with all details
**Tasks:** Retrieves risk from database, includes related vulnerabilities

### POST `/risks/{risk_id}/recalculate`

**Purpose:** Manually recalculate a risk's BWVS score
**Authentication:** JWT token required
**Response:** Updated risk object
**Tasks:** Triggers BWVS recalculation, updates risk score

### PUT `/risks/{risk_id}/status`

**Purpose:** Update risk status
**Authentication:** JWT token required
**Parameters:**

- `status` - New status (open, mitigated, accepted, transferred)
  **Response:** Updated risk object
  **Tasks:** Changes risk status, logs status change

---

## 3. Incident Management Routes (`/incidents`)

### POST `/incidents/`

**Purpose:** Create a new incident
**Authentication:** JWT token required
**Parameters:**

- `title` - Incident title
- `description` - Incident description
- `severity` - Severity level (critical, high, medium, low)
- `source` - How incident was detected
  **Response:** Newly created incident object
  **Tasks:** Creates incident, initializes timeline, assigns ID

### GET `/incidents/`

**Purpose:** List all incidents with filtering and pagination
**Authentication:** JWT token required
**Query Parameters:**

- `page` - Page number
- `page_size` - Records per page
- `status` - Filter by status (open, investigating, resolved, closed)
  **Response:** Paginated list of incidents
  **Tasks:** Filters incidents, applies pagination

### GET `/incidents/{incident_id}`

**Purpose:** Get specific incident details
**Authentication:** JWT token required
**Response:** Single incident object with timeline
**Tasks:** Retrieves incident, includes related analyses

### PUT `/incidents/{incident_id}`

**Purpose:** Update incident details
**Authentication:** JWT token required
**Parameters:** Any updatable incident field
**Response:** Updated incident object
**Tasks:** Updates incident record

### POST `/incidents/{incident_id}/start`

**Purpose:** Start investigating an incident
**Authentication:** JWT token required
**Response:** Updated incident with investigation status
**Tasks:** Changes status to investigating, logs start time

### POST `/incidents/{incident_id}/close`

**Purpose:** Close a completed incident
**Authentication:** JWT token required
**Parameters:**

- `resolution` - How incident was resolved
- `lessons_learned` - Post-incident lessons
  **Response:** Closed incident object
  **Tasks:** Changes status to closed, logs closure, generates report

### GET `/incidents/{incident_id}/timeline`

**Purpose:** Get detailed timeline of incident events
**Authentication:** JWT token required
**Response:** Chronological list of all incident events
**Tasks:** Retrieves timeline entries, sorts by timestamp

---

## 4. Asset Management Routes (`/assets`)

### POST `/assets/`

**Purpose:** Create a new asset in inventory
**Authentication:** JWT token required
**Parameters:**

- `name` - Asset name
- `asset_type` - Type (server, workstation, network_device, firewall, database, web_server)
- `criticality` - Business criticality (critical, high, medium, low)
- `ip_address` - Optional IP address
- `hostname` - Optional hostname
  **Response:** Newly created asset object
  **Tasks:** Creates asset record, initializes in digital twin

### GET `/assets/`

**Purpose:** List all assets with filtering and pagination
**Authentication:** JWT token required
**Query Parameters:**

- `page` - Page number
- `page_size` - Records per page
- `asset_type` - Filter by type
- `criticality` - Filter by criticality level
  **Response:** Paginated list of assets
  **Tasks:** Filters assets, applies pagination

### GET `/assets/{asset_id}`

**Purpose:** Get details of specific asset
**Authentication:** JWT token required
**Response:** Single asset object with all properties
**Tasks:** Retrieves asset details

### PUT `/assets/{asset_id}`

**Purpose:** Update asset information
**Authentication:** JWT token required
**Parameters:** Any updatable asset field
**Response:** Updated asset object
**Tasks:** Updates asset record, may trigger digital twin refresh

### DELETE `/assets/{asset_id}`

**Purpose:** Remove asset from inventory
**Authentication:** JWT token required
**Response:** 204 No Content
**Tasks:** Deletes asset, removes from digital twin

### GET `/assets/{asset_id}/vulnerabilities`

**Purpose:** Get vulnerabilities affecting this asset
**Authentication:** JWT token required
**Response:** List of CVE objects
**Tasks:** Retrieves related vulnerabilities from database

### GET `/assets/{asset_id}/risks`

**Purpose:** Get risks associated with this asset
**Authentication:** JWT token required
**Response:** List of risk objects
**Tasks:** Retrieves risks from database

---

## 5. CVE Management Routes (`/cves`)

### GET `/cves/`

**Purpose:** List all CVEs with filtering and pagination
**Authentication:** JWT token required
**Query Parameters:**

- `page` - Page number
- `page_size` - Records per page
- `severity` - Filter by severity (critical, high, medium, low)
- `min_cvss` - Minimum CVSS score
- `has_exploit` - Filter for CVEs with known exploits
  **Response:** Paginated list of CVE objects
  **Tasks:** Retrieves CVEs from database, applies filters

### GET `/cves/trending`

**Purpose:** Get trending CVEs based on recent activity
**Authentication:** JWT token required
**Query Parameters:**

- `limit` - Number of results (default 10, max 50)
  **Response:** List of trending CVEs
  **Tasks:** Analyzes CVE activity, returns most active

### GET `/cves/stats/summary`

**Purpose:** Get CVE statistics summary
**Authentication:** JWT token required
**Response:** Statistics about CVEs in system
**Tasks:** Calculates CVE statistics

### GET `/cves/search/by-product`

**Purpose:** Search CVEs by affected product
**Authentication:** JWT token required
**Query Parameters:**

- `product` - Product name
- `vendor` - Optional vendor name
  **Response:** List of matching CVEs
  **Tasks:** Searches CVE database, returns matches

### POST `/cves/collect/kev`

**Purpose:** Collect CVEs from CISA Known Exploited Vulnerabilities catalog
**Authentication:** JWT token required
**Response:** Collection result with count
**Tasks:** Fetches from CISA API, imports into database

### POST `/cves/collect/nvd`

**Purpose:** Collect recent CVEs from NVD
**Authentication:** JWT token required
**Query Parameters:**

- `days_back` - Look back days (default 7, max 30)
  **Response:** Collection result with count
  **Tasks:** Fetches from NVD API, imports into database

### GET `/cves/{cve_id}`

**Purpose:** Get specific CVE details
**Authentication:** JWT token required
**Response:** Single CVE object with metadata
**Tasks:** Retrieves CVE from database

---

## 6. AI Agents Routes (`/agents`)

### POST `/agents/analyze/{incident_id}`

**Purpose:** Run multi-agent analysis on an incident
**Authentication:** JWT token required
**Response:** Analysis results from all agents (Analyst, Intel, Forensics, Business, Response)
**Tasks:**

- Analyst Agent: Evaluates indicators and threat level
- Intel Agent: Gathers threat intelligence
- Forensics Agent: Analyzes attack artifacts
- Business Agent: Calculates business impact
- Response Agent: Recommends response actions

### GET `/agents/status`

**Purpose:** Get status of all agent processes
**Authentication:** JWT token required
**Response:** Status of each agent (running, idle, busy)
**Tasks:** Monitors agent health and availability

### POST `/agents/query`

**Purpose:** Query specific agent with custom question
**Authentication:** JWT token required
**Parameters:**

- `agent_type` - Which agent to query
- `query` - Question/prompt for agent
  **Response:** Agent's response to query
  **Tasks:** Sends query to agent, returns response

### GET `/agents/capabilities`

**Purpose:** Get capabilities of each agent
**Authentication:** JWT token required
**Response:** List of what each agent can do
**Tasks:** Returns agent capabilities

---

## 7. Playbook Automation Routes (`/playbooks`)

### GET `/playbooks/`

**Purpose:** List all security playbooks
**Authentication:** JWT token required
**Response:** List of all available playbooks
**Tasks:** Retrieves playbook library

### GET `/playbooks/{playbook_id}`

**Purpose:** Get specific playbook details
**Authentication:** JWT token required
**Response:** Playbook definition with steps
**Tasks:** Retrieves playbook details

### POST `/playbooks/`

**Purpose:** Create a new automated playbook
**Authentication:** JWT token required
**Parameters:**

- `name` - Playbook name
- `description` - What it does
- `steps` - Array of execution steps
- `trigger_conditions` - When to execute
  **Response:** Created playbook object
  **Tasks:** Creates playbook, validates steps

### POST `/playbooks/{playbook_id}/execute`

**Purpose:** Execute a playbook
**Authentication:** JWT token required
**Parameters:**

- `incident_id` - Incident to run playbook on
  **Response:** Execution ID and status
  **Tasks:** Starts playbook execution, monitors progress

### GET `/playbooks/{playbook_id}/executions`

**Purpose:** Get execution history of a playbook
**Authentication:** JWT token required
**Response:** List of past executions
**Tasks:** Retrieves execution records

### GET `/playbooks/executions/{execution_id}`

**Purpose:** Get details of specific playbook execution
**Authentication:** JWT token required
**Response:** Execution details with results
**Tasks:** Retrieves execution status and output

### POST `/playbooks/executions/{execution_id}/cancel`

**Purpose:** Cancel an in-progress playbook execution
**Authentication:** JWT token required
**Response:** Cancellation confirmation
**Tasks:** Stops playbook, cleans up resources

---

## 8. Blockchain Ledger Routes (`/ledger`)

### GET `/ledger/`

**Purpose:** Get ledger status and info
**Authentication:** JWT token required
**Response:** Ledger statistics and integrity status
**Tasks:** Returns blockchain status

### GET `/ledger/blocks`

**Purpose:** List all blockchain blocks
**Authentication:** JWT token required
**Response:** List of all blocks
**Tasks:** Retrieves blocks from ledger

### GET `/ledger/blocks/{block_index}`

**Purpose:** Get specific block details
**Authentication:** JWT token required
**Response:** Single block with hash and data
**Tasks:** Retrieves block from chain

### GET `/ledger/verify`

**Purpose:** Verify entire blockchain integrity
**Authentication:** JWT token required
**Response:** Verification result (valid/invalid)
**Tasks:** Validates all hashes, checks chain continuity

### GET `/ledger/verify/{block_index}`

**Purpose:** Verify specific block
**Authentication:** JWT token required
**Response:** Block verification result
**Tasks:** Validates specific block hash

### GET `/ledger/search`

**Purpose:** Search ledger for events
**Authentication:** JWT token required
**Query Parameters:**

- `event_type` - Type of event to search
- `actor` - User who performed action
- `start_date` - Filter by date range
  **Response:** Matching ledger entries
  **Tasks:** Searches ledger blocks

### GET `/ledger/audit-trail`

**Purpose:** Get audit trail for specific asset/user
**Authentication:** JWT token required
**Query Parameters:**

- `subject` - Asset ID or user ID
  **Response:** Complete audit history
  **Tasks:** Retrieves all related events

### GET `/ledger/export`

**Purpose:** Export ledger to file
**Authentication:** JWT token required
**Query Parameters:**

- `format` - Export format (json, csv)
  **Response:** Ledger data in requested format
  **Tasks:** Exports blocks to file

---

## 9. Digital Twin Routes (`/twin`)

### GET `/twin/stats`

**Purpose:** Get network topology statistics
**Authentication:** Optional JWT token
**Response:** Node count, connection count, complexity metrics
**Tasks:** Analyzes network graph, returns statistics

### GET `/twin/export`

**Purpose:** Export digital twin graph
**Authentication:** Optional JWT token
**Response:** Graph data (nodes and edges)
**Tasks:** Exports network model

### POST `/twin/import`

**Purpose:** Import digital twin graph data
**Authentication:** Optional JWT token
**Parameters:** Graph data structure
**Response:** Import confirmation with stats
**Tasks:** Loads network model from data

### POST `/twin/assets`

**Purpose:** Add asset to digital twin network
**Authentication:** Optional JWT token
**Parameters:**

- `asset_id` - Asset identifier
- `asset_type` - Type of asset
- `name` - Display name
- `criticality` - Business criticality
- `zone` - Network zone (internal/external)
- `metadata` - Optional extra data
  **Response:** Confirmation with asset details
  **Tasks:** Adds node to graph

### POST `/twin/connections`

**Purpose:** Add network connection between assets
**Authentication:** Optional JWT token
**Parameters:**

- `source_id` - Source asset
- `target_id` - Target asset
- `connection_type` - Type (network, service, dependency)
- `protocols` - Network protocols used
- `bidirectional` - Is connection bidirectional
  **Response:** Confirmation with connection details
  **Tasks:** Adds edge to graph

### POST `/twin/vulnerabilities`

**Purpose:** Add vulnerability to asset
**Authentication:** Optional JWT token
**Parameters:**

- `asset_id` - Affected asset
- `cve_id` - CVE identifier
- `cvss_score` - CVSS severity
- `exploitable` - Is it exploitable
- `network_exploitable` - Exploitable remotely
  **Response:** Confirmation
  **Tasks:** Adds vulnerability metadata

### GET `/twin/attack-paths/bfs`

**Purpose:** Find shortest attack paths (Breadth-First Search)
**Authentication:** Optional JWT token
**Query Parameters:**

- `start_id` - Starting asset
- `target_id` - Target asset
- `max_depth` - Maximum hops (default 10, max 20)
  **Response:** List of attack paths (up to 50)
  **Tasks:** BFS traversal, finds shortest paths

### GET `/twin/attack-paths/dfs`

**Purpose:** Find all attack paths (Depth-First Search)
**Authentication:** Optional JWT token
**Query Parameters:**

- `start_id` - Starting asset
- `target_id` - Target asset
- `max_depth` - Maximum hops (default 10, max 20)
  **Response:** List of attack paths (up to 50)
  **Tasks:** DFS traversal, explores all routes

### POST `/twin/simulate/lateral-movement`

**Purpose:** Simulate lateral movement from initial compromise
**Authentication:** Optional JWT token
**Parameters:**

- `initial_compromise` - Starting asset
- `time_steps` - Number of simulation steps (default 10, max 100)
- `propagation_probability` - Spread probability (default 0.3)
  **Response:** Simulation results showing compromised assets
  **Tasks:** Probabilistic simulation, tracks spread over time

### GET `/twin/blast-radius/{asset_id}`

**Purpose:** Calculate blast radius of compromised asset
**Authentication:** Optional JWT token
**Query Parameters:**

- `max_hops` - Maximum network hops (default 3, max 10)
  **Response:** List of all reachable assets within hops
  **Tasks:** BFS from asset, returns reachable nodes

### GET `/twin/critical-paths`

**Purpose:** Find paths to critical assets
**Authentication:** Optional JWT token
**Response:** Attack paths leading to critical systems
**Tasks:** Analyzes graph for critical asset routes

### POST `/twin/simulate`

**Purpose:** Run comprehensive attack simulation
**Authentication:** Optional JWT token
**Query Parameters:**

- `attack_type` - Type (ransomware, apt, insider, ddos) **REQUIRED**
- `entry_point` - Initial entry asset **REQUIRED**
- `target` - Target asset (optional)
  **Response:**

```json
{
  "attack_type": "ransomware",
  "entry_point": "web-server-1",
  "risk_score": 9.2,
  "paths": [
    ["web-server-1", "app-server-2", "database-1"]
  ],
  "affected_assets": 17,
  "blast_radius": [...],
  "impact_estimate": {
    "financial_loss": "$2.4M",
    "recovery_time": "72 hours",
    "data_at_risk": "500GB"
  },
  "mitigations": [...],
  "recommendations": [...]
}
```

**Tasks:**

1. **Ransomware**: 3-hop max, SMB-focused propagation, impacts data & backup systems
2. **APT**: 6-hop max, lateral movement, persistent, impacts long-term
3. **Insider**: 2-hop max, direct access exploitation, immediate impact
4. **DDoS**: 1-hop max, external targeting, bandwidth attack

---

## Common Query Parameters

| Parameter   | Type    | Description                            |
| ----------- | ------- | -------------------------------------- |
| `page`      | integer | Page number (1-indexed)                |
| `page_size` | integer | Records per page (default 50, max 100) |
| `limit`     | integer | Number of results to return            |
| `sort_by`   | string  | Sort field                             |
| `order`     | string  | Sort order (asc/desc)                  |

## Authentication

All endpoints require JWT Bearer token in Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

**Optional endpoints** (marked in documentation) work without authentication using demo mode.

## Response Codes

| Code | Meaning      |
| ---- | ------------ |
| 200  | Success      |
| 201  | Created      |
| 204  | No Content   |
| 400  | Bad Request  |
| 401  | Unauthorized |
| 403  | Forbidden    |
| 404  | Not Found    |
| 500  | Server Error |

## Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

---

## Testing Endpoints

### Quick Test (No Auth Required)

```bash
curl http://localhost:8000/api/twin/stats
curl http://localhost:8000/api/twin/export
```

### With Demo Login

```bash
# Login to get token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo-user@contexta.io&password=demo123"

# Use token in requests
curl http://localhost:8000/api/risks/top10 \
  -H "Authorization: Bearer <token>"
```

---

## Notes

- All timestamps are in UTC (ISO 8601 format)
- Database operations are async using SQLAlchemy with aiosqlite
- Digital Twin uses NetworkX for graph analysis
- BWVS scoring combines vulnerability, exposure, and business factors
- Blockchain ledger provides immutable audit trail
- All user actions are logged to ledger for compliance
