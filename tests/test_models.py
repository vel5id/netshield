"""
Models Module Tests
===================
Tests for data models and sanitization.

Security Fixes Tested:
  - #3: Input sanitization to prevent log injection
"""

import pytest

from netshield.models import (
    IPProfile,
    ThreatEvent,
    sanitize_string,
    sanitize_ip,
    MAX_FIELD_LENGTH,
)


class TestSanitizeString:
    """Tests for string sanitization (Fix #3)."""
    
    def test_sanitize_removes_null_bytes(self):
        """Null bytes should be removed."""
        result = sanitize_string("test\x00string")
        assert "\x00" not in result
        assert result == "teststring"
    
    def test_sanitize_removes_control_chars(self):
        """Control characters (0x00-0x1f) should be removed."""
        # Test various control chars
        dirty = "hello\x01\x02\x03\x0a\x0dworld"
        result = sanitize_string(dirty)
        assert result == "helloworld"
    
    def test_sanitize_removes_high_control_chars(self):
        """High control characters (0x7f-0x9f) should be removed."""
        dirty = "test\x7f\x80\x9fdata"
        result = sanitize_string(dirty)
        for c in ['\x7f', '\x80', '\x9f']:
            assert c not in result
    
    def test_sanitize_truncates_long_strings(self):
        """Long strings should be truncated."""
        long_string = "x" * 1000
        result = sanitize_string(long_string)
        assert len(result) <= MAX_FIELD_LENGTH
        assert result.endswith("...")
    
    def test_sanitize_preserves_normal_text(self):
        """Normal text should be preserved."""
        normal = "Hello, World! 123"
        result = sanitize_string(normal)
        assert result == normal
    
    def test_sanitize_strips_whitespace(self):
        """Leading/trailing whitespace should be stripped."""
        result = sanitize_string("  test  ")
        assert result == "test"
    
    def test_sanitize_handles_unicode(self):
        """Unicode characters should be preserved."""
        unicode_str = "Привет мир 你好世界"
        result = sanitize_string(unicode_str)
        assert result == unicode_str
    
    def test_sanitize_custom_max_length(self):
        """Custom max length should work."""
        result = sanitize_string("abcdefghij", max_length=5)
        assert len(result) == 5


class TestSanitizeIP:
    """Tests for IP address sanitization."""
    
    def test_sanitize_valid_ipv4(self):
        """Valid IPv4 should pass through."""
        result = sanitize_ip("192.168.1.1")
        assert result == "192.168.1.1"
    
    def test_sanitize_valid_ipv6(self):
        """Valid IPv6 should pass through."""
        result = sanitize_ip("2001:db8::1")
        assert result == "2001:db8::1"
    
    def test_sanitize_invalid_ip_chars(self):
        """Invalid characters should result in 'invalid'."""
        result = sanitize_ip("192.168.1.1; DROP TABLE")
        assert result == "invalid"
    
    def test_sanitize_ip_max_length(self):
        """Very long IP strings should be truncated."""
        long_ip = "1" * 100
        result = sanitize_ip(long_ip)
        assert len(result) <= 45  # Max IPv6 length


class TestIPProfile:
    """Tests for IPProfile data class."""
    
    def test_profile_sanitizes_on_init(self):
        """Fields should be sanitized on initialization."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            network_name="Test\x00Network\x0d\x0a"
        )
        assert "\x00" not in profile.network_name
        assert "\x0d" not in profile.network_name
    
    def test_profile_sanitizes_country(self):
        """Country code should be sanitized and limited."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
            country="US\x00\x00EXTRA"
        )
        assert len(profile.country) <= 10
        assert "\x00" not in profile.country
    
    def test_profile_update_whois_sanitizes(self, sample_ip_profile):
        """update_whois should sanitize all fields."""
        sample_ip_profile.update_whois(
            country="XX\x00",
            asn="123\x0a456",
            asn_desc="Evil\x00Corp",
            network_name="Bad\rNetwork",
            network_cidr="1.2.3.0/24",
            abuse="abuse@\x00test.com"
        )
        
        assert "\x00" not in sample_ip_profile.country
        assert "\x0a" not in sample_ip_profile.asn
        assert "\x00" not in sample_ip_profile.asn_description
        assert "\r" not in sample_ip_profile.network_name
    
    def test_profile_to_dict(self, sample_ip_profile):
        """to_dict should return valid dictionary."""
        result = sample_ip_profile.to_dict()
        
        assert isinstance(result, dict)
        assert result['ip'] == sample_ip_profile.ip
        assert result['country'] == sample_ip_profile.country
        assert 'threat_score' in result
        assert 'threat_reasons' in result
    
    def test_profile_to_dict_sanitizes_reasons(self):
        """threat_reasons in to_dict should be sanitized."""
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01",
        )
        profile.threat_reasons = ["Reason\x00One", "Reason\nTwo"]
        
        result = profile.to_dict()
        for reason in result['threat_reasons']:
            assert "\x00" not in reason
            assert "\n" not in reason


class TestThreatEvent:
    """Tests for ThreatEvent data class."""
    
    def test_event_sanitizes_ip(self):
        """IP should be sanitized on init."""
        event = ThreatEvent(
            timestamp="2024-01-01",
            event_type="test",
            ip="8.8.8.8; DROP TABLE",
            speed_mbps=10.0,
            threat_score=50
        )
        assert event.ip == "invalid"
    
    def test_event_sanitizes_type(self):
        """Event type should be sanitized."""
        event = ThreatEvent(
            timestamp="2024-01-01",
            event_type="high_score\x00\x0d\x0a",
            ip="8.8.8.8",
            speed_mbps=10.0,
            threat_score=50
        )
        assert "\x00" not in event.event_type
        assert "\x0d" not in event.event_type
    
    def test_event_sanitizes_details(self):
        """Details dict values should be sanitized."""
        event = ThreatEvent(
            timestamp="2024-01-01",
            event_type="test",
            ip="8.8.8.8",
            speed_mbps=10.0,
            threat_score=50,
            details={"key\x00": "value\x00\x0a"}
        )
        
        for k, v in event.details.items():
            if isinstance(v, str):
                assert "\x00" not in v
    
    def test_event_to_dict(self, sample_event):
        """to_dict should return valid dictionary."""
        result = sample_event.to_dict()
        
        assert isinstance(result, dict)
        assert result['ip'] == sample_event.ip
        assert result['event_type'] == sample_event.event_type
        assert result['speed_mbps'] == round(sample_event.speed_mbps, 2)
    
    def test_event_speed_rounded(self):
        """Speed should be rounded to 2 decimals in to_dict."""
        event = ThreatEvent(
            timestamp="2024-01-01",
            event_type="test",
            ip="8.8.8.8",
            speed_mbps=10.123456789,
            threat_score=50
        )
        result = event.to_dict()
        assert result['speed_mbps'] == 10.12
