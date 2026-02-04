# Multi-Agent SOC System

## Overview

Contexta uses a multi-agent system powered by Google Gemini to provide comprehensive, autonomous security analysis. Each agent specializes in a specific domain, and the orchestrator coordinates their outputs to generate consensus reports.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Agent Orchestrator                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐│
│  │ Analyst  │ │  Intel   │ │Forensics │ │ Business │ │Response││
│  │  Agent   │ │  Agent   │ │  Agent   │ │  Agent   │ │ Agent  ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘│
│       │            │            │            │           │      │
│       └────────────┴─────┬──────┴────────────┴───────────┘      │
│                          │                                       │
│                    ┌─────▼─────┐                                │
│                    │ Consensus │                                │
│                    │  Engine   │                                │
│                    └───────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Descriptions

### 1. Security Analyst Agent
**Role**: Initial analysis and triage

**Capabilities**:
- Log analysis and correlation
- Attack pattern recognition
- Initial classification
- Severity assessment

**Prompt Focus**:
- What type of attack is this?
- What is the attack vector?
- What systems are affected?
- What is the initial severity?

### 2. Threat Intelligence Agent
**Role**: CTI and attribution

**Capabilities**:
- Threat actor attribution
- TTP mapping (MITRE ATT&CK)
- IOC extraction and correlation
- Threat landscape assessment

**Prompt Focus**:
- Who might be behind this?
- What TTPs are being used?
- Are there similar attacks in threat feeds?
- What is the threat actor's capability level?

### 3. Digital Forensics Agent
**Role**: Evidence analysis

**Capabilities**:
- Timeline reconstruction
- Artifact examination
- Evidence preservation guidance
- Chain of custody documentation

**Prompt Focus**:
- What happened and when?
- What evidence should be collected?
- How should evidence be preserved?
- What is the forensic timeline?

### 4. Business Impact Agent
**Role**: Business risk assessment

**Capabilities**:
- Financial impact estimation
- Operational impact analysis
- Regulatory compliance checking
- Stakeholder communication planning

**Prompt Focus**:
- What is the business impact?
- What regulations apply?
- Who needs to be notified?
- What is the reputational risk?

### 5. Response Coordinator Agent
**Role**: Response planning

**Capabilities**:
- Incident response planning
- Playbook recommendations
- Resource coordination
- Recovery planning

**Prompt Focus**:
- What actions should be taken?
- Which playbooks apply?
- What resources are needed?
- What is the recovery plan?

## Orchestrator

The orchestrator coordinates all agents and generates unified outputs:

### Parallel Execution
All agents run concurrently for efficiency:
```python
tasks = [
    analyst.analyze(incident),
    intel.analyze(incident),
    forensics.analyze(incident),
    business.analyze(incident),
    response.analyze(incident)
]
results = await asyncio.gather(*tasks)
```

### Consensus Generation
The orchestrator combines agent outputs:

1. **Severity Consensus**: Uses conservative approach (highest severity wins)
2. **Confidence Scoring**: Weighted average of agent confidence
3. **Key Findings**: Top findings from each agent
4. **Recommendations**: Prioritized based on urgency and agent

### Output Format
```json
{
  "incident_id": "inc-123",
  "analysis_timestamp": "2024-01-15T10:30:00Z",
  "analysis_duration_seconds": 12.5,
  "agent_results": {
    "analyst": { ... },
    "intel": { ... },
    "forensics": { ... },
    "business": { ... },
    "response": { ... }
  },
  "consensus_report": {
    "consensus_severity": "high",
    "threat_level": "elevated",
    "confidence_score": 0.85,
    "executive_summary": "...",
    "key_findings": [...],
    "prioritized_recommendations": [...],
    "agent_agreement": {
      "level": "high",
      "score": 0.92
    },
    "escalation_required": true,
    "immediate_actions": [...]
  }
}
```

## Usage

### Full Analysis
```python
from app.agents.orchestrator import get_orchestrator

orchestrator = get_orchestrator()
result = await orchestrator.full_analysis(incident_data)
```

### Targeted Analysis
```python
result = await orchestrator.targeted_analysis(
    incident_data,
    agent_types=["analyst", "intel"]  # Only specific agents
)
```

### Direct Agent Query
```python
from app.agents.analyst import AnalystAgent

agent = AnalystAgent()
result = await agent.analyze(incident_data, context)
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/agents/analyze/{incident_id}` | Run multi-agent analysis |
| `GET /api/agents/status` | Get agent status |
| `POST /api/agents/query` | Query specific agent |
| `GET /api/agents/capabilities` | List agent capabilities |

## Configuration

Agents use Google Gemini for AI capabilities:

```python
# Environment variables
GEMINI_API_KEY=your-api-key
GEMINI_MODEL=gemini-pro
```

## Error Handling

Each agent has fallback mechanisms:
1. Retry with exponential backoff
2. Rate limit handling
3. Graceful degradation if API unavailable
4. Cached responses for similar queries

## Best Practices

1. **Always verify critical findings manually**
2. **Use targeted analysis for focused investigations**
3. **Review consensus report for conflicts**
4. **Log all agent invocations to ledger**
5. **Monitor agent performance metrics**
