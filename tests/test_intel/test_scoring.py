"""
Threat Scoring Tests
====================
Tests for threat score calculation.

Security Fixes Tested:
  - #4: Configurable country and ASN lists
"""

import pytest

from netshield.config import NetShieldConfig
from netshield.intel.scoring import ThreatScorer
from netshield.models import IPProfile


@pytest.fixture
def scorer(test_config):
    """Default threat scorer."""
    return ThreatScorer(test_config)


@pytest.fixture
def custom_scorer():
    """Scorer with custom configuration."""
    config = NetShieldConfig(
        high_risk_countries=frozenset({"XX", "YY"}),
        suspicious_asn_keywords=frozenset({"evil", "bad"})
    )
    return ThreatScorer(config)


class TestScoreCalculation:
    """Tests for threat score calculation."""
    
    def test_score_clean_ip(self, scorer):
        """Normal IP with no risk factors should score 0."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="US",
            asn_description="Google LLC",
            max_speed_mbps=10.0,
            total_packets=100,
            throttled_packets=5
        )
        
        score, reasons = scorer.calculate(profile)
        assert score == 0
        assert len(reasons) == 0
    
    def test_score_high_risk_country(self, scorer):
        """High-risk country should add points."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP",  # Default high risk
        )
        
        score, reasons = scorer.calculate(profile)
        assert score >= 30
        assert any("country" in r.lower() for r in reasons)
    
    def test_score_extreme_speed(self, scorer):
        """Extreme speed (>100 MB/s) should add +40."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            max_speed_mbps=150.0
        )
        
        score, reasons = scorer.calculate(profile)
        assert score >= 40
        assert any("extreme" in r.lower() for r in reasons)
    
    def test_score_high_speed(self, scorer):
        """High speed (50-100 MB/s) should add +20."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            max_speed_mbps=75.0
        )
        
        score, reasons = scorer.calculate(profile)
        assert score >= 20
        assert any("speed" in r.lower() for r in reasons)
    
    def test_score_high_throttle_ratio(self, scorer):
        """High throttle ratio (>50%) should add +20."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            total_packets=100,
            throttled_packets=60  # 60% throttled
        )
        
        score, reasons = scorer.calculate(profile)
        assert score >= 20
        assert any("throttle" in r.lower() for r in reasons)
    
    def test_score_suspicious_asn(self, scorer):
        """Suspicious ASN keywords should add +15."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            asn_description="Bulletproof Hosting VPS Cloud"
        )
        
        score, reasons = scorer.calculate(profile)
        assert score >= 15
        assert any("asn" in r.lower() for r in reasons)
    
    def test_score_capped_at_100(self, scorer):
        """Score should never exceed 100."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP",  # +30
            max_speed_mbps=200.0,  # +40
            total_packets=100,
            throttled_packets=80,  # +20
            asn_description="Bulletproof hosting VPS"  # +15
        )
        
        score, reasons = scorer.calculate(profile)
        assert score <= 100
    
    def test_score_cumulative(self, scorer):
        """Multiple risk factors should accumulate."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP",  # +30
            max_speed_mbps=150.0,  # +40
        )
        
        score, reasons = scorer.calculate(profile)
        assert score >= 70  # 30 + 40
        assert len(reasons) >= 2


class TestCustomScorer:
    """Tests for custom scorer configuration (Fix #4)."""
    
    def test_custom_countries(self, custom_scorer):
        """Custom country list should be used."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="XX"  # Custom high-risk
        )
        
        score, reasons = custom_scorer.calculate(profile)
        assert score >= 30
    
    def test_default_country_not_in_custom(self, custom_scorer):
        """KP should not trigger in custom scorer without it."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP"  # Not in custom list
        )
        
        score, reasons = custom_scorer.calculate(profile)
        assert not any("country" in r.lower() for r in reasons)
    
    def test_custom_asn_keywords(self, custom_scorer):
        """Custom ASN keywords should be used."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            asn_description="Evil Corporation"
        )
        
        score, reasons = custom_scorer.calculate(profile)
        assert score >= 15
        assert any("evil" in r.lower() for r in reasons)


class TestScorerProfileUpdate:
    """Tests for update_profile_score method."""
    
    def test_update_profile_sets_score(self, scorer):
        """update_profile_score should set threat_score."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP"
        )
        
        scorer.update_profile_score(profile)
        assert profile.threat_score >= 30
    
    def test_update_profile_sets_reasons(self, scorer):
        """update_profile_score should set threat_reasons."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            max_speed_mbps=120.0
        )
        
        scorer.update_profile_score(profile)
        assert len(profile.threat_reasons) > 0
    
    def test_update_clears_old_reasons(self, scorer):
        """update_profile_score should replace old reasons."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01"
        )
        profile.threat_reasons = ["old_reason"]
        
        scorer.update_profile_score(profile)
        assert "old_reason" not in profile.threat_reasons
