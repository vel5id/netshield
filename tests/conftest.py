"""
NetShield Test Fixtures
=======================
Shared pytest fixtures for all test modules.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from netshield.config import NetShieldConfig, MODE_VRCHAT, MODE_UNIVERSAL
from netshield.models import IPProfile, ThreatEvent


# ============================================================================
# CONFIG FIXTURES
# ============================================================================

@pytest.fixture
def default_config():
    """Default NetShield configuration."""
    return NetShieldConfig()


@pytest.fixture
def test_config():
    """Minimal test configuration with low limits."""
    return NetShieldConfig(
        mode=MODE_VRCHAT,
        max_bandwidth_mbps=10.0,
        burst_size_mb=5.0,
        cache_max_size=100,
        cache_ttl_hours=1,
        whois_rate_limit=2,
    )


@pytest.fixture
def universal_config():
    """Universal mode configuration."""
    return NetShieldConfig(
        mode=MODE_UNIVERSAL,
        max_bandwidth_mbps=100.0,
        burst_size_mb=20.0,
    )


# ============================================================================
# MODEL FIXTURES
# ============================================================================

@pytest.fixture
def sample_ip_profile():
    """Sample IP profile for testing."""
    return IPProfile(
        ip="8.8.8.8",
        first_seen="2024-01-01T00:00:00",
        last_seen="2024-01-01T01:00:00",
        country="US",
        asn="15169",
        asn_description="Google LLC",
        network_name="GOOGLE",
        total_bytes=1000000,
        total_packets=100,
    )


@pytest.fixture
def high_risk_profile():
    """High-risk IP profile for testing."""
    return IPProfile(
        ip="1.2.3.4",
        first_seen="2024-01-01T00:00:00",
        last_seen="2024-01-01T01:00:00",
        country="KP",  # North Korea (default high risk)
        asn="12345",
        asn_description="Bulletproof Hosting VPS",
        network_name="SUS-NET",
        max_speed_mbps=150.0,
        total_packets=100,
        throttled_packets=60,
    )


@pytest.fixture
def sample_event():
    """Sample threat event for testing."""
    return ThreatEvent(
        timestamp="2024-01-01T00:00:00",
        event_type="high_score",
        ip="1.2.3.4",
        speed_mbps=75.5,
        threat_score=85,
        details={"country": "KP", "asn": "12345"}
    )


# ============================================================================
# DIRECTORY FIXTURES
# ============================================================================

@pytest.fixture
def temp_log_dir(tmp_path):
    """Temporary directory for log files."""
    log_dir = tmp_path / "netshield_logs"
    log_dir.mkdir()
    return log_dir


@pytest.fixture
def temp_config_file(tmp_path):
    """Temporary YAML config file."""
    config_content = """
mode: vrchat
limits:
  max_bandwidth_mbps: 25.0
  burst_size_mb: 8.0
watchlist:
  threshold: 70
threat_intel:
  high_risk_countries:
    - KP
    - TEST
  suspicious_asn_keywords:
    - bulletproof
    - test
"""
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(config_content)
    return config_file


# ============================================================================
# MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_whois():
    """Mock IPWhois for testing without network."""
    with patch('netshield.intel.threat_intel.IPWhois') as mock:
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = {
            'asn_country_code': 'US',
            'asn': '15169',
            'asn_description': 'GOOGLE',
            'network': {
                'name': 'GOOGLE-NET',
                'cidr': '8.8.8.0/24'
            },
            'entities': ['abuse@google.com']
        }
        mock.return_value = mock_instance
        yield mock


@pytest.fixture
def mock_pydivert():
    """Mock pydivert for testing without admin rights."""
    with patch('netshield.shield.engine.pydivert') as mock:
        mock_handle = MagicMock()
        mock_handle.__enter__ = MagicMock(return_value=mock_handle)
        mock_handle.__exit__ = MagicMock(return_value=False)
        mock.WinDivert.return_value = mock_handle
        yield mock


# ============================================================================
# HELPER FIXTURES
# ============================================================================

@pytest.fixture
def integrity_secret(monkeypatch):
    """Set log integrity secret for testing."""
    monkeypatch.setenv('NETSHIELD_LOG_SECRET', 'test_secret_key_12345')
    return b'test_secret_key_12345'


@pytest.fixture
def no_whois(monkeypatch):
    """Disable WHOIS for faster tests."""
    monkeypatch.setattr(
        'netshield.intel.threat_intel.IPWHOIS_AVAILABLE', 
        False
    )
