"""
Tests for the BWVS Risk Engine.
"""

import pytest
from app.risk_engine.bwvs import BWVSCalculator, BWVSInput


class TestBWVSCalculator:
    """Test suite for BWVS calculation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.calculator = BWVSCalculator()
    
    def test_calculate_bwvs_critical_scenario(self):
        """Test BWVS calculation for a critical vulnerability."""
        input_data = BWVSInput(
            cvss_score=9.8,
            exploit_available=True,
            exposure_level="internet_facing",
            asset_criticality="critical",
            business_impact="catastrophic",
            ai_relevance_score=0.9
        )
        
        result = self.calculator.calculate(input_data)
        
        # Should be a high score given all critical factors
        assert result.bwvs_score > 80
        assert result.risk_level == "critical"
    
    def test_calculate_bwvs_low_scenario(self):
        """Test BWVS calculation for a low-risk vulnerability."""
        input_data = BWVSInput(
            cvss_score=2.0,
            exploit_available=False,
            exposure_level="internal_segmented",
            asset_criticality="low",
            business_impact="minimal",
            ai_relevance_score=0.1
        )
        
        result = self.calculator.calculate(input_data)
        
        # Should be a low score
        assert result.bwvs_score < 30
        assert result.risk_level == "low"
    
    def test_calculate_bwvs_medium_scenario(self):
        """Test BWVS calculation for a medium-risk vulnerability."""
        input_data = BWVSInput(
            cvss_score=5.5,
            exploit_available=True,
            exposure_level="internal_broad",
            asset_criticality="medium",
            business_impact="moderate",
            ai_relevance_score=0.5
        )
        
        result = self.calculator.calculate(input_data)
        
        # Should be in medium range
        assert 30 <= result.bwvs_score <= 70
        assert result.risk_level in ["medium", "high"]
    
    def test_weight_factors_sum_to_one(self):
        """Verify that weight factors sum to 1.0."""
        total_weight = (
            self.calculator.WEIGHT_CVSS +
            self.calculator.WEIGHT_EXPLOIT +
            self.calculator.WEIGHT_EXPOSURE +
            self.calculator.WEIGHT_ASSET_CRIT +
            self.calculator.WEIGHT_BUSINESS +
            self.calculator.WEIGHT_AI_RELEVANCE
        )
        
        assert abs(total_weight - 1.0) < 0.001
    
    def test_bwvs_score_bounds(self):
        """Test that BWVS scores are within valid bounds."""
        # Test minimum scenario
        min_input = BWVSInput(
            cvss_score=0.0,
            exploit_available=False,
            exposure_level="internal_segmented",
            asset_criticality="low",
            business_impact="minimal",
            ai_relevance_score=0.0
        )
        
        min_result = self.calculator.calculate(min_input)
        assert 0 <= min_result.bwvs_score <= 100
        
        # Test maximum scenario
        max_input = BWVSInput(
            cvss_score=10.0,
            exploit_available=True,
            exposure_level="internet_facing",
            asset_criticality="critical",
            business_impact="catastrophic",
            ai_relevance_score=1.0
        )
        
        max_result = self.calculator.calculate(max_input)
        assert 0 <= max_result.bwvs_score <= 100
    
    def test_exploit_availability_impact(self):
        """Test that exploit availability significantly impacts score."""
        base_input = BWVSInput(
            cvss_score=7.0,
            exploit_available=False,
            exposure_level="internal_broad",
            asset_criticality="medium",
            business_impact="moderate",
            ai_relevance_score=0.5
        )
        
        exploit_input = BWVSInput(
            cvss_score=7.0,
            exploit_available=True,
            exposure_level="internal_broad",
            asset_criticality="medium",
            business_impact="moderate",
            ai_relevance_score=0.5
        )
        
        base_result = self.calculator.calculate(base_input)
        exploit_result = self.calculator.calculate(exploit_input)
        
        # Exploit availability should increase score
        assert exploit_result.bwvs_score > base_result.bwvs_score


class TestBWVSInput:
    """Test suite for BWVS input validation."""
    
    def test_valid_input(self):
        """Test that valid input is accepted."""
        input_data = BWVSInput(
            cvss_score=7.5,
            exploit_available=True,
            exposure_level="dmz",
            asset_criticality="high",
            business_impact="major",
            ai_relevance_score=0.7
        )
        
        assert input_data.cvss_score == 7.5
        assert input_data.exploit_available is True
    
    def test_cvss_bounds(self):
        """Test CVSS score bounds."""
        # Valid CVSS
        valid = BWVSInput(
            cvss_score=5.0,
            exploit_available=False,
            exposure_level="internal_broad",
            asset_criticality="medium",
            business_impact="moderate",
            ai_relevance_score=0.5
        )
        assert valid.cvss_score == 5.0
        
        # CVSS should be between 0 and 10
        # Edge cases
        min_cvss = BWVSInput(
            cvss_score=0.0,
            exploit_available=False,
            exposure_level="internal_broad",
            asset_criticality="medium",
            business_impact="moderate",
            ai_relevance_score=0.5
        )
        assert min_cvss.cvss_score == 0.0
        
        max_cvss = BWVSInput(
            cvss_score=10.0,
            exploit_available=False,
            exposure_level="internal_broad",
            asset_criticality="medium",
            business_impact="moderate",
            ai_relevance_score=0.5
        )
        assert max_cvss.cvss_score == 10.0
