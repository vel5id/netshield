"""
ML Module Tests
===============
Tests for feature extraction and anomaly detection.
"""

import pytest
from unittest.mock import MagicMock

from netshield.ml.features import FeatureExtractor, TrafficFeatures
from netshield.ml.anomaly import AnomalyDetector
from netshield.models import IPProfile


@pytest.fixture
def extractor():
    """Feature extractor with test config."""
    return FeatureExtractor(high_risk_countries=frozenset({"KP", "XX"}))


@pytest.fixture
def sample_profile():
    """Sample IP profile."""
    return IPProfile(
        ip="8.8.8.8",
        first_seen="2024-01-01",
        last_seen="2024-01-01",
        country="US",
        asn_description="Google LLC",
        total_packets=1000,
        throttled_packets=100,
    )


class TestFeatureExtractor:
    """Tests for feature extraction."""
    
    def test_extract_returns_features(self, extractor, sample_profile):
        """Should return TrafficFeatures object."""
        features = extractor.extract(sample_profile, current_speed=25.0)
        assert isinstance(features, TrafficFeatures)
    
    def test_speed_ratio_normalized(self, extractor, sample_profile):
        """Speed ratio should be normalized."""
        features = extractor.extract(
            sample_profile, 
            current_speed=100.0, 
            max_bandwidth=50.0
        )
        assert features.speed_ratio == 2.0  # Capped at 2.0
    
    def test_throttle_ratio_calculated(self, extractor, sample_profile):
        """Throttle ratio should be calculated correctly."""
        features = extractor.extract(sample_profile)
        assert features.throttle_ratio == 0.1  # 100/1000
    
    def test_protocol_udp_detection(self, extractor, sample_profile):
        """Protocol flag should be set correctly."""
        features_udp = extractor.extract(sample_profile, protocol="udp")
        features_tcp = extractor.extract(sample_profile, protocol="tcp")
        
        assert features_udp.protocol_udp == 1.0
        assert features_tcp.protocol_udp == 0.0
    
    def test_high_risk_country_detection(self, extractor):
        """High-risk country should be flagged."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP"  # High risk
        )
        features = extractor.extract(profile)
        assert features.is_high_risk_country == 1.0
    
    def test_hosting_detection(self, extractor):
        """Hosting keywords should be detected."""
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            asn_description="DigitalOcean Cloud Hosting"
        )
        features = extractor.extract(profile)
        assert features.is_known_hosting == 1.0
    
    def test_to_array(self, extractor, sample_profile):
        """to_array should return numpy array."""
        features = extractor.extract(sample_profile)
        arr = features.to_array()
        
        assert arr.shape == (9,)
        assert arr.dtype.name.startswith('float')


class TestAnomalyDetector:
    """Tests for anomaly detection."""
    
    def test_detector_initializes(self):
        """Detector should initialize without model."""
        detector = AnomalyDetector()
        assert detector is not None
    
    def test_predict_returns_score(self, extractor, sample_profile):
        """predict should return anomaly score."""
        detector = AnomalyDetector()
        features = extractor.extract(sample_profile)
        
        score = detector.predict(features)
        
        assert 0.0 <= score <= 1.0
    
    def test_rule_based_fallback(self, extractor):
        """Untrained model should use rule-based fallback."""
        detector = AnomalyDetector()
        
        # High-risk profile
        profile = IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="KP",
            asn_description="bulletproof hosting",
            total_packets=1000,
            throttled_packets=600,  # 60% throttled
        )
        
        features = extractor.extract(profile, current_speed=200.0, max_bandwidth=50.0)
        score = detector.predict(features)
        
        # Should detect as anomalous
        assert score > 0.5
    
    def test_normal_profile_low_score(self, extractor, sample_profile):
        """Normal profile should have low anomaly score."""
        detector = AnomalyDetector()
        features = extractor.extract(sample_profile, current_speed=10.0)
        
        score = detector.predict(features)
        assert score < 0.5
    
    def test_classification_labels(self):
        """get_classification should return correct labels."""
        detector = AnomalyDetector()
        
        assert detector.get_classification(0.95) == "CRITICAL"
        assert detector.get_classification(0.75) == "HIGH"
        assert detector.get_classification(0.5) == "MEDIUM"
        assert detector.get_classification(0.2) == "NORMAL"
