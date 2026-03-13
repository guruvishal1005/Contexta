"""
Contexta Backend - Business-Weighted Vulnerability Score (BWVS) Calculator

This module implements the BWVS scoring algorithm that weighs vulnerabilities
based on both technical severity and business context.

BWVS Formula:
=============
BWVS = (
    CVSS_Score           × 0.20 +
    Exploit_Activity     × 0.20 +
    Exposure_Level       × 0.15 +
    Asset_Criticality    × 0.20 +
    Business_Impact      × 0.15 +
    AI_Relevance_Score   × 0.10
) × 10

Final score range: 0-100

Factor Definitions:
==================

CVSS_Score (0-10):
    Direct from CVE feed CVSS v3 base score.

Exploit_Activity (0-10):
    | Condition            | Score |
    |---------------------|-------|
    | Public exploit      | 10    |
    | GitHub PoC          | 8     |
    | Threat reports      | 6     |
    | No evidence         | 2     |

Exposure_Level (0-10):
    | Asset Type          | Score |
    |---------------------|-------|
    | Internet-facing     | 10    |
    | VPN                 | 7     |
    | Internal            | 4     |
    | Isolated            | 1     |

Asset_Criticality (0-10):
    | Role                | Score |
    |---------------------|-------|
    | Payment/Payroll     | 10    |
    | Core backend        | 8     |
    | CRM/HR              | 6     |
    | Dev/Test            | 3     |

Business_Impact (0-10):
    | Loss / Day (₹)      | Score |
    |---------------------|-------|
    | > ₹10L              | 10    |
    | ₹5-10L              | 8     |
    | ₹1-5L               | 6     |
    | < ₹1L               | 3     |

AI_Relevance_Score (0-10):
    Converted from Gemini relevance percentage:
    | %                   | Score |
    |---------------------|-------|
    | 90-100              | 10    |
    | 75-89               | 8     |
    | 50-74               | 6     |
    | 25-49               | 4     |
    | <25                 | 2     |
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()


@dataclass
class BWVSWeights:
    """
    Configurable weights for BWVS calculation.
    
    Default weights sum to 1.0 for proper scaling.
    """
    cvss: float = 0.20
    exploit_activity: float = 0.20
    exposure_level: float = 0.15
    asset_criticality: float = 0.20
    business_impact: float = 0.15
    ai_relevance: float = 0.10
    
    def validate(self) -> bool:
        """Validate that weights sum to 1.0."""
        total = (
            self.cvss +
            self.exploit_activity +
            self.exposure_level +
            self.asset_criticality +
            self.business_impact +
            self.ai_relevance
        )
        return abs(total - 1.0) < 0.001


class BWVSCalculator:
    """
    Business-Weighted Vulnerability Score Calculator.
    
    Calculates risk scores by combining technical vulnerability data
    with business context and AI-derived relevance.
    
    Example:
        calculator = BWVSCalculator()
        score = calculator.calculate(
            cvss_score=8.5,
            exploit_activity_score=10,  # Public exploit exists
            exposure_score=10,          # Internet-facing
            criticality_score=10,       # Payment system
            business_impact_score=10,   # High revenue impact
            ai_relevance_percentage=95  # Highly relevant
        )
        print(score["final_bwvs"])  # Output: 95.0
    """
    
    # Scoring constants
    EXPLOIT_SCORES = {
        "public_exploit": 10,
        "github_poc": 8,
        "threat_reports": 6,
        "no_evidence": 2
    }
    
    EXPOSURE_SCORES = {
        "internet_facing": 10,
        "vpn": 7,
        "internal": 4,
        "isolated": 1
    }
    
    CRITICALITY_SCORES = {
        "payment_payroll": 10,
        "core_backend": 8,
        "crm_hr": 6,
        "dev_test": 3
    }
    
    BUSINESS_IMPACT_THRESHOLDS = [
        (10.0, 10),  # > 10 Lakhs = 10
        (5.0, 8),    # 5-10 Lakhs = 8
        (1.0, 6),    # 1-5 Lakhs = 6
        (0.0, 3)     # < 1 Lakh = 3
    ]
    
    AI_RELEVANCE_THRESHOLDS = [
        (90, 10),  # 90-100% = 10
        (75, 8),   # 75-89% = 8
        (50, 6),   # 50-74% = 6
        (25, 4),   # 25-49% = 4
        (0, 2)     # <25% = 2
    ]
    
    def __init__(self, weights: Optional[BWVSWeights] = None):
        """
        Initialize calculator with optional custom weights.
        
        Args:
            weights: Custom weights (defaults to standard weights)
        """
        self.weights = weights or BWVSWeights()
        if not self.weights.validate():
            logger.warning("BWVS weights do not sum to 1.0")
    
    def calculate(
        self,
        cvss_score: float,
        exploit_activity_score: int,
        exposure_score: int,
        criticality_score: int,
        business_impact_score: int,
        ai_relevance_percentage: float
    ) -> Dict[str, Any]:
        """
        Calculate the Business-Weighted Vulnerability Score.
        
        Args:
            cvss_score: CVSS v3 base score (0-10)
            exploit_activity_score: Exploit availability score (0-10)
            exposure_score: Asset exposure level score (0-10)
            criticality_score: Asset criticality score (0-10)
            business_impact_score: Business impact score (0-10)
            ai_relevance_percentage: AI relevance (0-100%)
            
        Returns:
            Dictionary containing all component scores and final BWVS
        """
        # Validate and clamp inputs to valid ranges
        cvss_score = self._clamp(cvss_score, 0, 10)
        exploit_activity_score = self._clamp(exploit_activity_score, 0, 10)
        exposure_score = self._clamp(exposure_score, 0, 10)
        criticality_score = self._clamp(criticality_score, 0, 10)
        business_impact_score = self._clamp(business_impact_score, 0, 10)
        
        # Convert AI relevance percentage to 0-10 score
        ai_relevance_score = self._convert_ai_relevance(ai_relevance_percentage)
        
        # Calculate weighted sum
        weighted_sum = (
            cvss_score * self.weights.cvss +
            exploit_activity_score * self.weights.exploit_activity +
            exposure_score * self.weights.exposure_level +
            criticality_score * self.weights.asset_criticality +
            business_impact_score * self.weights.business_impact +
            ai_relevance_score * self.weights.ai_relevance
        )
        
        # Scale to 0-100
        final_bwvs = weighted_sum * 10
        final_bwvs = round(final_bwvs, 2)
        
        result = {
            "cvss_score": cvss_score,
            "exploit_activity": exploit_activity_score,
            "exposure_level": exposure_score,
            "asset_criticality": criticality_score,
            "business_impact": business_impact_score,
            "ai_relevance": ai_relevance_score,
            "ai_relevance_percentage": ai_relevance_percentage,
            "final_bwvs": final_bwvs,
            "weights_used": {
                "cvss": self.weights.cvss,
                "exploit_activity": self.weights.exploit_activity,
                "exposure_level": self.weights.exposure_level,
                "asset_criticality": self.weights.asset_criticality,
                "business_impact": self.weights.business_impact,
                "ai_relevance": self.weights.ai_relevance
            }
        }
        
        logger.debug("Calculated BWVS", **result)
        return result
    
    def _clamp(self, value: float, min_val: float, max_val: float) -> float:
        """Clamp a value to a range."""
        return max(min_val, min(max_val, value))
    
    def _convert_ai_relevance(self, percentage: float) -> int:
        """
        Convert AI relevance percentage to 0-10 score.
        
        Args:
            percentage: AI relevance (0-100)
            
        Returns:
            Score (0-10)
        """
        percentage = self._clamp(percentage, 0, 100)
        
        for threshold, score in self.AI_RELEVANCE_THRESHOLDS:
            if percentage >= threshold:
                return score
        return 2  # Default minimum
    
    @classmethod
    def get_exploit_score(cls, exploit_info: Dict[str, Any]) -> int:
        """
        Determine exploit activity score from exploit information.
        
        Args:
            exploit_info: Dictionary with exploit details
            
        Returns:
            Exploit activity score (0-10)
        """
        sources = exploit_info.get("sources", [])
        cisa_kev = exploit_info.get("cisa_kev", False)
        has_exploit = exploit_info.get("has_exploit", False)
        
        # Check for CISA KEV or public exploit databases
        if cisa_kev or "exploit-db" in sources or "metasploit" in sources:
            return cls.EXPLOIT_SCORES["public_exploit"]
        
        # Check for GitHub PoC
        if "github" in sources:
            return cls.EXPLOIT_SCORES["github_poc"]
        
        # Check for any exploit evidence
        if has_exploit or len(sources) > 0:
            return cls.EXPLOIT_SCORES["threat_reports"]
        
        return cls.EXPLOIT_SCORES["no_evidence"]
    
    @classmethod
    def get_exposure_score(cls, exposure_level: str) -> int:
        """
        Get exposure score from exposure level string.
        
        Args:
            exposure_level: Exposure level enum value
            
        Returns:
            Exposure score (0-10)
        """
        level_map = {
            "internet_facing": cls.EXPOSURE_SCORES["internet_facing"],
            "vpn": cls.EXPOSURE_SCORES["vpn"],
            "internal": cls.EXPOSURE_SCORES["internal"],
            "isolated": cls.EXPOSURE_SCORES["isolated"],
        }
        return level_map.get(exposure_level.lower(), cls.EXPOSURE_SCORES["internal"])
    
    @classmethod
    def get_criticality_score(cls, criticality: str) -> int:
        """
        Get criticality score from criticality string.
        
        Args:
            criticality: Criticality enum value
            
        Returns:
            Criticality score (0-10)
        """
        crit_map = {
            "payment_payroll": cls.CRITICALITY_SCORES["payment_payroll"],
            "core_backend": cls.CRITICALITY_SCORES["core_backend"],
            "crm_hr": cls.CRITICALITY_SCORES["crm_hr"],
            "dev_test": cls.CRITICALITY_SCORES["dev_test"],
        }
        return crit_map.get(criticality.lower(), cls.CRITICALITY_SCORES["dev_test"])
    
    @classmethod
    def get_business_impact_score(cls, daily_revenue_lakhs: float) -> int:
        """
        Get business impact score from daily revenue impact.
        
        Args:
            daily_revenue_lakhs: Daily revenue impact in INR Lakhs
            
        Returns:
            Business impact score (0-10)
        """
        for threshold, score in cls.BUSINESS_IMPACT_THRESHOLDS:
            if daily_revenue_lakhs > threshold:
                return score
        return 3  # Default minimum
    
    def calculate_from_models(
        self,
        cve_data: Dict[str, Any],
        asset_data: Dict[str, Any],
        ai_relevance: float
    ) -> Dict[str, Any]:
        """
        Calculate BWVS from CVE and Asset model data.
        
        Args:
            cve_data: CVE model dictionary
            asset_data: Asset model dictionary
            ai_relevance: AI relevance percentage
            
        Returns:
            BWVS calculation result
        """
        # Extract CVSS score
        cvss_score = cve_data.get("cvss_score", 5.0)
        
        # Calculate exploit activity score
        exploit_score = self.get_exploit_score({
            "sources": cve_data.get("exploit_sources", []),
            "cisa_kev": cve_data.get("cisa_kev", False),
            "has_exploit": cve_data.get("has_exploit", False)
        })
        
        # Get asset scores
        exposure_score = self.get_exposure_score(
            asset_data.get("exposure_level", "internal")
        )
        criticality_score = self.get_criticality_score(
            asset_data.get("criticality", "dev_test")
        )
        business_impact_score = self.get_business_impact_score(
            asset_data.get("daily_revenue_impact", 0)
        )
        
        return self.calculate(
            cvss_score=cvss_score,
            exploit_activity_score=exploit_score,
            exposure_score=exposure_score,
            criticality_score=criticality_score,
            business_impact_score=business_impact_score,
            ai_relevance_percentage=ai_relevance
        )
    
    def get_severity_label(self, bwvs_score: float) -> str:
        """
        Get severity label from BWVS score.
        
        Args:
            bwvs_score: BWVS score (0-100)
            
        Returns:
            Severity label
        """
        if bwvs_score >= 80:
            return "CRITICAL"
        elif bwvs_score >= 60:
            return "HIGH"
        elif bwvs_score >= 40:
            return "MEDIUM"
        elif bwvs_score >= 20:
            return "LOW"
        else:
            return "INFO"
