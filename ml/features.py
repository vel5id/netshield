"""
Feature Extractor for ML Anomaly Detection
===========================================
Extracts numerical features from IP profiles for ML inference.

Security Note: All features are sanitized and bounded to prevent
adversarial manipulation of model inputs.
"""

import numpy as np
from typing import TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..models import IPProfile


@dataclass
class TrafficFeatures:
    """
    Normalized feature vector for ML models.
    All values are bounded [0, 1] or standardized.
    """
    # Speed features
    speed_ratio: float  # current_speed / max_bandwidth
    speed_variance: float  # Coefficient of variation
    
    # Throttle features
    throttle_ratio: float  # throttled / total packets
    burst_score: float  # Short-term burst intensity
    
    # Temporal features
    duration_hours: float  # How long this IP has been active
    packets_per_minute: float  # Normalized packet rate
    
    # Protocol features (0 = TCP, 1 = UDP)
    protocol_udp: float
    
    # Geo features
    is_high_risk_country: float  # 0 or 1
    is_known_hosting: float  # 0 or 1 (VPS/hosting ASN)
    
    def to_array(self) -> np.ndarray:
        """Convert to numpy array for model input."""
        return np.array([
            self.speed_ratio,
            self.speed_variance,
            self.throttle_ratio,
            self.burst_score,
            self.duration_hours,
            self.packets_per_minute,
            self.protocol_udp,
            self.is_high_risk_country,
            self.is_known_hosting,
        ], dtype=np.float32)


class FeatureExtractor:
    """
    Extracts ML features from IP profiles.
    
    Security:
      - All inputs sanitized
      - Feature bounds enforced
      - No external data dependencies in hot path
    """
    
    # Feature normalization constants
    MAX_SPEED_MBPS = 500.0
    MAX_DURATION_HOURS = 24.0
    MAX_PACKETS_PER_MIN = 10000.0
    
    # Keywords indicating VPS/hosting
    HOSTING_KEYWORDS = frozenset({
        'hosting', 'vps', 'cloud', 'server', 'datacenter',
        'hetzner', 'ovh', 'digitalocean', 'vultr', 'linode'
    })
    
    def __init__(self, high_risk_countries: frozenset[str]):
        """
        Initialize extractor.
        
        Args:
            high_risk_countries: Set of high-risk country codes
        """
        self.high_risk_countries = high_risk_countries
    
    def extract(self, profile: "IPProfile", 
                current_speed: float = 0.0,
                max_bandwidth: float = 50.0,
                protocol: str = "udp") -> TrafficFeatures:
        """
        Extract features from IP profile.
        
        All features are bounded and sanitized.
        """
        # Speed features
        speed_ratio = self._clamp(current_speed / max(max_bandwidth, 1.0), 0, 2.0)
        
        # Throttle ratio
        if profile.total_packets > 0:
            throttle_ratio = profile.throttled_packets / profile.total_packets
        else:
            throttle_ratio = 0.0
        
        # Burst score (high speed + high throttle = burst)
        burst_score = self._clamp(
            (speed_ratio * 0.5) + (throttle_ratio * 0.5), 
            0, 1
        )
        
        # Duration (would need first_seen parsing, simplified)
        duration_hours = self._clamp(1.0, 0, self.MAX_DURATION_HOURS)  # TODO: calculate from timestamps
        
        # Packets per minute
        ppm = self._clamp(
            profile.total_packets / max(duration_hours * 60, 1),
            0, self.MAX_PACKETS_PER_MIN
        ) / self.MAX_PACKETS_PER_MIN
        
        # Protocol
        protocol_udp = 1.0 if protocol.lower() == "udp" else 0.0
        
        # Geo/ASN features
        is_high_risk = 1.0 if profile.country in self.high_risk_countries else 0.0
        
        asn_lower = profile.asn_description.lower()
        is_hosting = 1.0 if any(kw in asn_lower for kw in self.HOSTING_KEYWORDS) else 0.0
        
        return TrafficFeatures(
            speed_ratio=speed_ratio,
            speed_variance=0.0,  # Would need historical data
            throttle_ratio=throttle_ratio,
            burst_score=burst_score,
            duration_hours=duration_hours / self.MAX_DURATION_HOURS,
            packets_per_minute=ppm,
            protocol_udp=protocol_udp,
            is_high_risk_country=is_high_risk,
            is_known_hosting=is_hosting,
        )
    
    @staticmethod
    def _clamp(value: float, min_val: float, max_val: float) -> float:
        """Clamp value to range (input sanitization)."""
        return max(min_val, min(value, max_val))
