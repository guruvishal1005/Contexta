"""
Contexta Backend - Risk Ranking Engine

This module implements dynamic risk ranking using:
    Priority = BWVS × Freshness × TrendFactor

The ranking is updated every 5 minutes to reflect changing conditions.
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import structlog

logger = structlog.get_logger()


@dataclass
class RankingConfig:
    """Configuration for risk ranking algorithm."""
    
    # Freshness decay parameters
    fresh_hours: float = 24.0        # Hours considered "fresh" (factor = 1.0)
    decay_rate: float = 0.0004       # Decay rate per hour after fresh period
    min_freshness: float = 0.5       # Minimum freshness factor
    max_freshness: float = 1.0       # Maximum freshness factor
    
    # Trend factor parameters
    default_trend: float = 1.0       # Default trend multiplier
    increasing_trend: float = 1.5    # Multiplier for increasing frequency
    decreasing_trend: float = 0.7    # Multiplier for decreasing frequency
    
    # Top N configuration
    top_n: int = 10                  # Number of top risks to track


class RiskRanker:
    """
    Dynamic risk ranking engine.
    
    Calculates priority scores and maintains Top 10 risk list.
    
    Priority Formula:
        Priority = BWVS × Freshness × TrendFactor
        
    Where:
        - BWVS: Business-Weighted Vulnerability Score (0-100)
        - Freshness: Time-based decay factor (0.5-1.0)
        - TrendFactor: Occurrence trend multiplier (0.7-1.5)
    """
    
    def __init__(self, config: RankingConfig = None):
        """
        Initialize ranker with configuration.
        
        Args:
            config: Ranking configuration (uses defaults if not provided)
        """
        self.config = config or RankingConfig()
    
    def calculate_freshness(self, first_seen: datetime, last_seen: datetime) -> float:
        """
        Calculate freshness factor based on risk age.
        
        Freshness decays over time:
        - 0-24 hours: 1.0 (fresh)
        - 24h-7d: Gradual decay to 0.7
        - 7d-30d: Gradual decay to 0.5
        - >30d: 0.5 (minimum)
        
        Args:
            first_seen: When risk was first detected
            last_seen: When risk was last observed
            
        Returns:
            Freshness factor (0.5-1.0)
        """
        now = datetime.utcnow()
        
        # Use last_seen for more accurate freshness if risk recurs
        age = now - first_seen
        recency = now - last_seen
        
        age_hours = age.total_seconds() / 3600
        recency_hours = recency.total_seconds() / 3600
        
        # If risk was recently seen, boost freshness
        if recency_hours < 1:
            return self.config.max_freshness
        
        # Calculate base freshness from age
        if age_hours <= self.config.fresh_hours:
            freshness = self.config.max_freshness
        else:
            # Decay after fresh period
            hours_past_fresh = age_hours - self.config.fresh_hours
            decay = hours_past_fresh * self.config.decay_rate
            freshness = self.config.max_freshness - decay
        
        # Clamp to valid range
        return max(self.config.min_freshness, min(self.config.max_freshness, freshness))
    
    def calculate_trend_factor(
        self,
        occurrence_count: int,
        time_window_hours: float = 168,  # 7 days
        previous_count: int = None
    ) -> float:
        """
        Calculate trend factor based on occurrence frequency.
        
        Args:
            occurrence_count: Number of occurrences in current window
            time_window_hours: Time window for counting occurrences
            previous_count: Occurrences in previous window for comparison
            
        Returns:
            Trend factor (0.7-1.5)
        """
        if previous_count is None:
            # No historical data, use default
            return self.config.default_trend
        
        if occurrence_count > previous_count * 1.5:
            # Significantly increasing
            return self.config.increasing_trend
        elif occurrence_count < previous_count * 0.5:
            # Significantly decreasing
            return self.config.decreasing_trend
        else:
            # Stable
            return self.config.default_trend
    
    def calculate_priority(
        self,
        bwvs_score: float,
        freshness: float,
        trend_factor: float
    ) -> float:
        """
        Calculate final priority score.
        
        Args:
            bwvs_score: BWVS score (0-100)
            freshness: Freshness factor (0.5-1.0)
            trend_factor: Trend multiplier (0.7-1.5)
            
        Returns:
            Priority score
        """
        priority = bwvs_score * freshness * trend_factor
        return round(priority, 2)
    
    def rank_risks(self, risks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Rank a list of risks by priority.
        
        Args:
            risks: List of risk dictionaries with required fields:
                - bwvs_score
                - first_seen
                - last_seen
                - trend_factor (optional)
                
        Returns:
            Sorted list of risks with priority scores
        """
        ranked = []
        
        for risk in risks:
            bwvs = risk.get("bwvs_score", 0)
            first_seen = risk.get("first_seen", datetime.utcnow())
            last_seen = risk.get("last_seen", datetime.utcnow())
            trend = risk.get("trend_factor", self.config.default_trend)
            
            # Ensure datetime objects
            if isinstance(first_seen, str):
                first_seen = datetime.fromisoformat(first_seen)
            if isinstance(last_seen, str):
                last_seen = datetime.fromisoformat(last_seen)
            
            freshness = self.calculate_freshness(first_seen, last_seen)
            priority = self.calculate_priority(bwvs, freshness, trend)
            
            ranked_risk = {
                **risk,
                "freshness_factor": freshness,
                "priority_score": priority
            }
            ranked.append(ranked_risk)
        
        # Sort by priority descending
        ranked.sort(key=lambda r: r["priority_score"], reverse=True)
        
        logger.debug("Ranked risks", count=len(ranked))
        return ranked
    
    def get_top_n(
        self,
        risks: List[Dict[str, Any]],
        n: int = None
    ) -> List[Dict[str, Any]]:
        """
        Get top N risks by priority.
        
        Args:
            risks: List of risks to rank
            n: Number of top risks (defaults to config.top_n)
            
        Returns:
            Top N risks sorted by priority
        """
        n = n or self.config.top_n
        ranked = self.rank_risks(risks)
        
        top = ranked[:n]
        
        # Mark as top 10
        for risk in top:
            risk["is_top_10"] = True
        
        logger.info("Generated top risks", count=len(top))
        return top
    
    def should_alert(self, risk: Dict[str, Any]) -> bool:
        """
        Determine if a risk should trigger an alert.
        
        Args:
            risk: Risk with priority score
            
        Returns:
            True if alert should be triggered
        """
        priority = risk.get("priority_score", 0)
        bwvs = risk.get("bwvs_score", 0)
        
        # Alert on critical priority or high BWVS
        if priority >= 80 or bwvs >= 85:
            return True
        
        # Alert on rapidly increasing trend
        if risk.get("trend_factor", 1.0) >= 1.4 and bwvs >= 60:
            return True
        
        return False
    
    def compare_rankings(
        self,
        previous: List[Dict[str, Any]],
        current: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compare two rankings to identify changes.
        
        Args:
            previous: Previous top N ranking
            current: Current top N ranking
            
        Returns:
            Comparison result with new, removed, and position changes
        """
        prev_ids = {r.get("id") for r in previous}
        curr_ids = {r.get("id") for r in current}
        
        new_risks = [r for r in current if r.get("id") not in prev_ids]
        removed_risks = [r for r in previous if r.get("id") not in curr_ids]
        
        # Track position changes for risks in both lists
        position_changes = []
        prev_positions = {r.get("id"): i for i, r in enumerate(previous)}
        curr_positions = {r.get("id"): i for i, r in enumerate(current)}
        
        for risk_id in prev_ids & curr_ids:
            prev_pos = prev_positions[risk_id]
            curr_pos = curr_positions[risk_id]
            if prev_pos != curr_pos:
                position_changes.append({
                    "id": risk_id,
                    "previous_position": prev_pos + 1,
                    "current_position": curr_pos + 1,
                    "change": prev_pos - curr_pos  # Positive = moved up
                })
        
        return {
            "new_entries": new_risks,
            "removed_entries": removed_risks,
            "position_changes": position_changes,
            "total_new": len(new_risks),
            "total_removed": len(removed_risks),
            "total_changes": len(position_changes)
        }
