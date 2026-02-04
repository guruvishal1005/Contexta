# Contexta

**Autonomous Context-Aware Threat Intelligence & Business Risk Platform**

Contexta is a comprehensive security operations platform that combines AI-powered analysis, risk scoring, network simulation, and immutable audit logging to provide context-aware threat intelligence and business risk assessment.

## Features

### 1. CVE Feed Collector
- Ingests vulnerabilities from **CISA Known Exploited Vulnerabilities (KEV)**
- Fetches from **NVD (National Vulnerability Database)**
- Automatic enrichment with exploit availability data

### 2. SIEM Log Generator
- Generates realistic security event logs for testing
- Supports multiple log types: login failures, port scans, malware alerts, privilege escalation
- Configurable severity and frequency

### 3. BWVS Scoring (Business-Weighted Vulnerability Score)
Custom risk scoring formula that considers business context:

```
BWVS = (CVSS×0.20 + Exploit×0.20 + Exposure×0.15 + Asset_Crit×0.20 + Business_Impact×0.15 + AI_Relevance×0.10) × 10
```

| Factor | Weight | Description |
|--------|--------|-------------|
| CVSS | 20% | Standard vulnerability severity |
| Exploit Availability | 20% | Is there a known exploit? |
| Exposure Level | 15% | How exposed is the asset? |
| Asset Criticality | 20% | Business importance of the asset |
| Business Impact | 15% | Potential business damage |
| AI Relevance | 10% | AI-assessed contextual relevance |

### 4. Top-10 Real-Time Risk Dashboard
Prioritized risk ranking using:

```
Priority = BWVS × Freshness × TrendFactor
```

Where:
- **Freshness** = Exponential decay based on discovery time
- **TrendFactor** = Velocity of spread/exploitation

### 5. Multi-Agent SOC System
AI-powered agents using Google Gemini:

| Agent | Role |
|-------|------|
| **Analyst** | Security analysis and initial triage |
| **Intel** | Threat intelligence and attribution |
| **Forensics** | Digital forensics and evidence analysis |
| **Business** | Business impact assessment |
| **Response** | Response planning and coordination |

The **Orchestrator** coordinates all agents and generates consensus reports.

### 6. Digital Twin Network Simulation
NetworkX-based network topology simulation:
- **BFS/DFS Attack Path Discovery**
- **Lateral Movement Simulation**
- **Blast Radius Calculation**
- **Critical Path Identification**

### 7. Private Blockchain Ledger
Immutable audit logging with hash chain:

```
hash = SHA256(prev_hash + data)
```

Features:
- Tamper detection
- Full audit trail export
- Chain integrity verification

### 8. Playbook Engine
Automated response workflows with:
- Step-by-step execution
- Timeout handling
- Escalation rules
- Notification hooks

## 🛠️ Tech Stack

- **Python 3.11+**
- **FastAPI** - Modern async web framework
- **PostgreSQL** - Primary database with asyncpg
- **Redis** - Caching and rate limiting
- **SQLAlchemy 2.0** - Async ORM
- **Google Gemini** - AI/LLM provider
- **NetworkX** - Graph-based digital twin
- **APScheduler** - Background task scheduling
- **Docker** - Containerization

## 🚀 Getting Started

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL 15+
- Redis 7+
- Google Gemini API key

### Quick Start with Docker

1. **Navigate to the backend directory**
   ```bash
   cd contexta-backend
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start services**
   ```bash
   docker-compose up -d
   ```

4. **Access the API**
   - API Docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc
   - Health: http://localhost:8000/health

### Local Development

1. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or: venv\Scripts\activate  # Windows
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up database**
   ```bash
   # Start PostgreSQL and Redis
   docker-compose up -d postgres redis
   
   # Run migrations
   alembic upgrade head
   ```

4. **Run the application**
   ```bash
   uvicorn app.main:app --reload
   ```

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login and get tokens |
| POST | `/api/auth/refresh` | Refresh access token |
| GET | `/api/auth/me` | Get current user |

### Risk Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/risks/top10` | Get top 10 prioritized risks |
| GET | `/api/risks` | List all risks |
| GET | `/api/risks/{id}` | Get specific risk |
| POST | `/api/risks/{id}/recalculate` | Recalculate BWVS |

### Incidents
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/incidents` | Create incident |
| GET | `/api/incidents` | List incidents |
| POST | `/api/incidents/{id}/start` | Start response |
| POST | `/api/incidents/{id}/close` | Close incident |

### AI Agents
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agents/analyze/{incident_id}` | Run multi-agent analysis |
| GET | `/api/agents/status` | Get agent status |
| POST | `/api/agents/query` | Query specific agent |

### Digital Twin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/twin/attack-paths/bfs` | Find paths using BFS |
| GET | `/api/twin/attack-paths/dfs` | Find paths using DFS |
| POST | `/api/twin/simulate/lateral-movement` | Simulate attack spread |
| GET | `/api/twin/blast-radius/{asset_id}` | Calculate blast radius |

### Audit Ledger
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ledger` | Get ledger stats |
| GET | `/api/ledger/blocks` | List blocks |
| GET | `/api/ledger/verify` | Verify chain integrity |
| GET | `/api/ledger/audit-trail` | Export audit trail |

## 📁 Project Structure

```
contexta-backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── database.py          # Database setup
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business logic
│   ├── api/                 # API routes
│   │   └── routes/
│   ├── agents/              # Multi-agent SOC system
│   ├── risk_engine/         # BWVS calculation
│   ├── ingestion/           # CVE collector, log generator
│   ├── twin/                # Digital twin engine
│   ├── ledger/              # Blockchain ledger
│   ├── auth/                # Authentication
│   ├── workers/             # Background tasks
│   └── utils/               # Utilities
├── playbooks/               # Response playbooks
├── scripts/                 # Database scripts
├── tests/                   # Test suite
├── docs/                    # Documentation
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## 🔐 Security Considerations

- All passwords hashed with bcrypt
- JWT tokens with configurable expiration
- Role-based access control (RBAC)
- Immutable audit logging
- Input validation with Pydantic
- Rate limiting on API endpoints

## 📊 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `JWT_SECRET_KEY` | Secret for JWT signing | Required |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration | `30` |
| `LOG_LEVEL` | Logging level | `INFO` |

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_risk_engine.py
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📧 Support

For questions and support, please contact the development team.

---

Built with ❤️ for the security community
