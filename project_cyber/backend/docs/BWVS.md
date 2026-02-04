# BWVS - Business-Weighted Vulnerability Scoring

## Overview

BWVS (Business-Weighted Vulnerability Score) is a custom risk scoring methodology that enhances traditional CVSS scores by incorporating business context and operational factors.

## Formula

```
BWVS = (CVSS×0.20 + Exploit×0.20 + Exposure×0.15 + Asset_Crit×0.20 + Business_Impact×0.15 + AI_Relevance×0.10) × 10
```

## Factors

### 1. CVSS Score (20%)
The standard Common Vulnerability Scoring System score, normalized to 0-10.

### 2. Exploit Availability (20%)
Whether a working exploit exists:
- **Available (10)**: Public exploit exists
- **Proof-of-Concept (7)**: PoC available
- **Theoretical (3)**: Exploitation theoretically possible
- **None (0)**: No known exploit

### 3. Exposure Level (15%)
How exposed the affected asset is:
- **Internet Facing (10)**: Directly accessible from internet
- **DMZ (8)**: In demilitarized zone
- **Internal Broad (5)**: Accessible from general internal network
- **Internal Segmented (2)**: In segmented internal network

### 4. Asset Criticality (20%)
Business importance of the affected asset:
- **Critical (10)**: Core business systems, customer data
- **High (7)**: Important business functions
- **Medium (4)**: Supporting systems
- **Low (1)**: Non-essential systems

### 5. Business Impact (15%)
Potential damage if exploited:
- **Catastrophic (10)**: Existential threat, massive data breach
- **Major (7)**: Significant financial/reputational damage
- **Moderate (4)**: Noticeable business disruption
- **Minor (2)**: Limited impact
- **Minimal (1)**: Negligible impact

### 6. AI Relevance (10%)
Context-aware scoring from AI analysis:
- Score from 0-1 based on current threat landscape
- Considers trending attacks, threat actor activity
- Updated dynamically based on threat intelligence

## Risk Levels

| BWVS Range | Risk Level |
|------------|------------|
| 80-100 | Critical |
| 60-79 | High |
| 40-59 | Medium |
| 0-39 | Low |

## Priority Calculation

For ranking in the Top-10 list:

```
Priority = BWVS × Freshness × TrendFactor
```

### Freshness
Exponential decay based on discovery time:
```
Freshness = 0.5 ^ (age_days / 7)
```
- A 7-day-old vulnerability has freshness of 0.5
- A 14-day-old vulnerability has freshness of 0.25

### Trend Factor
Velocity of spread (1.0-2.0):
- **2.0**: Rapidly spreading, active exploitation
- **1.5**: Increasing activity
- **1.0**: Stable/declining activity

## Example Calculation

**Scenario**: Critical server with Log4j vulnerability

| Factor | Value | Normalized | Weight | Weighted |
|--------|-------|------------|--------|----------|
| CVSS | 10.0 | 10.0 | 0.20 | 2.0 |
| Exploit | Available | 10.0 | 0.20 | 2.0 |
| Exposure | Internet | 10.0 | 0.15 | 1.5 |
| Asset Crit | Critical | 10.0 | 0.20 | 2.0 |
| Business | Major | 7.0 | 0.15 | 1.05 |
| AI Relevance | 0.9 | 9.0 | 0.10 | 0.9 |

**BWVS** = (2.0 + 2.0 + 1.5 + 2.0 + 1.05 + 0.9) × 10 = **94.5** (Critical)

## Implementation

See `app/risk_engine/bwvs.py` for the implementation.
