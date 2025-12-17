"""
Threat Scoring Module
=====================
Calculates threat scores based on configurable rules.

Security Fixes:
  - #4: Uses externalized country list from config
"""

from typing import TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from ..models import IPProfile
    from ..config import NetShieldConfig

logger = logging.getLogger(__name__)


class ThreatScorer:
    """
    Thread-safe threat scoring engine.
    All thresholds and lists are configurable.
    """
    
    def __init__(self, config: "NetShieldConfig"):
        self.high_risk_countries = config.high_risk_countries
        self.suspicious_asn_keywords = config.suspicious_asn_keywords
        
        # Score weights (could also be in config)
        self.score_high_risk_country = 30
        self.score_extreme_speed = 40
        self.score_high_speed = 20
        self.score_high_throttle = 20
        self.score_suspicious_asn = 15
        
        # Thresholds
        self.extreme_speed_threshold = 100.0  # MB/s
        self.high_speed_threshold = 50.0  # MB/s
        self.high_throttle_ratio = 0.5
    
    def calculate(self, profile: "IPProfile") -> tuple[int, list[str]]:
        """
        Calculate threat score for an IP profile.
        
        Returns:
            (score, reasons) - threat score 0-100 and list of reasons
        """
        score = 0
        reasons = []
        
        # 1. Country risk check (Fix #4: from config, not hardcoded)
        if profile.country in self.high_risk_countries:
            score += self.score_high_risk_country
            reasons.append(f"High-risk country: {profile.country}")
        
        # 2. Speed anomalies
        if profile.max_speed_mbps > self.extreme_speed_threshold:
            score += self.score_extreme_speed
            reasons.append(f"Extreme speed: {profile.max_speed_mbps:.1f} MB/s")
        elif profile.max_speed_mbps > self.high_speed_threshold:
            score += self.score_high_speed
            reasons.append(f"High speed: {profile.max_speed_mbps:.1f} MB/s")
        
        # 3. Throttle ratio
        if profile.total_packets > 10:  # Need minimum sample
            throttle_ratio = profile.throttled_packets / profile.total_packets
            if throttle_ratio > self.high_throttle_ratio:
                score += self.score_high_throttle
                reasons.append(f"High throttle ratio: {throttle_ratio:.0%}")
        
        # 4. Suspicious ASN (Fix #4: from config)
        asn_lower = profile.asn_description.lower()
        for keyword in self.suspicious_asn_keywords:
            if keyword in asn_lower:
                score += self.score_suspicious_asn
                reasons.append(f"Suspicious ASN keyword: {keyword}")
                break  # Only count once
        
        # Cap at 100
        final_score = min(score, 100)
        
        return final_score, reasons
    
    def update_profile_score(self, profile: "IPProfile"):
        """Update profile with calculated score."""
        score, reasons = self.calculate(profile)
        profile.threat_score = score
        profile.threat_reasons = reasons
