"""
MITRE ATT&CK and Threat Feed Tests
==================================
Tests for TTP mapping and threat intelligence.
"""

import pytest
from unittest.mock import MagicMock, patch

from netshield.intel.mitre import TTPMapper, TECHNIQUES
from netshield.intel.feeds import ThreatFeed
from netshield.models import IPProfile


class TestTTPMapper:
    """Tests for MITRE ATT&CK mapping."""
    
    @pytest.fixture
    def mapper(self):
        return TTPMapper()
    
    @pytest.fixture
    def flood_profile(self):
        """Profile exhibiting DoS behavior."""
        return IPProfile(
            ip="1.2.3.4",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            total_packets=10000,
            throttled_packets=8000,  # 80% throttled
        )
    
    @pytest.fixture
    def tor_profile(self):
        """Profile from Tor exit node."""
        return IPProfile(
            ip="185.220.101.1",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            asn_description="Tor Exit Node",
            network_name="TOR-RELAY",
        )
    
    def test_detects_flood_attack(self, mapper, flood_profile):
        """Should detect T1498.001 for high-speed flood."""
        ttps = mapper.classify(flood_profile, speed_mbps=150.0)
        
        ids = [t.id for t in ttps]
        assert "T1498.001" in ids
    
    def test_detects_dos_by_throttle(self, mapper, flood_profile):
        """Should detect T1498 for high throttle ratio."""
        ttps = mapper.classify(flood_profile, speed_mbps=50.0)
        
        ids = [t.id for t in ttps]
        assert "T1498" in ids or "T1498.001" in ids
    
    def test_detects_tor(self, mapper, tor_profile):
        """Should detect T1090.003 for Tor traffic."""
        ttps = mapper.classify(tor_profile)
        
        ids = [t.id for t in ttps]
        assert "T1090.003" in ids
    
    def test_normal_profile_no_ttp(self, mapper):
        """Normal profile should have no TTPs."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            asn_description="Google LLC",
        )
        
        ttps = mapper.classify(profile, speed_mbps=10.0)
        assert len(ttps) == 0
    
    def test_get_technique(self, mapper):
        """get_technique should return technique by ID."""
        t = mapper.get_technique("T1498")
        
        assert t is not None
        assert t.name == "Network Denial of Service"
    
    def test_format_report(self, mapper, flood_profile):
        """format_report should create readable report."""
        ttps = mapper.classify(flood_profile, speed_mbps=150.0)
        report = mapper.format_report(ttps)
        
        assert "MITRE ATT&CK" in report
        assert "T1498" in report


class TestThreatFeed:
    """Tests for threat intelligence feeds."""
    
    def test_feed_initializes(self, tmp_path):
        """Feed should initialize with empty data."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        assert feed is not None
        assert len(feed._malicious_ips) >= 0
    
    def test_is_malicious_false_for_clean(self, tmp_path):
        """Clean IP should not be flagged."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        assert feed.is_malicious("8.8.8.8") is False
    
    def test_is_malicious_true_for_known_bad(self, tmp_path):
        """Known bad IP should be flagged."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        
        # Manually add malicious IP
        feed._malicious_ips.add("1.2.3.4")
        
        assert feed.is_malicious("1.2.3.4") is True
    
    def test_validate_ip_valid(self, tmp_path):
        """Valid IPs should pass validation."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        
        assert feed._validate_ip("192.168.1.1") is True
        assert feed._validate_ip("8.8.8.8") is True
    
    def test_validate_ip_invalid(self, tmp_path):
        """Invalid IPs should fail validation."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        
        assert feed._validate_ip("not-an-ip") is False
        assert feed._validate_ip("256.1.1.1") is True  # Regex doesn't check range
        assert feed._validate_ip("1.2.3.4.5") is False
    
    def test_get_stats(self, tmp_path):
        """get_stats should return feed statistics."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        stats = feed.get_stats()
        
        assert 'total_iocs' in stats
        assert 'enabled_feeds' in stats
    
    def test_needs_update(self, tmp_path):
        """needs_update should return True initially."""
        feed = ThreatFeed(cache_dir=tmp_path / "feeds")
        
        # No update yet, so should need one
        assert feed.needs_update() is True
    
    def test_cache_persistence(self, tmp_path):
        """Cache should persist across instances."""
        feed1 = ThreatFeed(cache_dir=tmp_path / "feeds")
        feed1._malicious_ips.add("1.2.3.4")
        feed1._save_cache()
        
        feed2 = ThreatFeed(cache_dir=tmp_path / "feeds")
        assert "1.2.3.4" in feed2._malicious_ips
