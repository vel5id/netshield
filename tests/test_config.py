"""
Config Module Tests
===================
Tests for configuration validation and loading.

Security Fixes Tested:
  - #4: Externalized country lists
  - #5: CLI argument bounds validation
"""

import pytest
from pathlib import Path

from netshield.config import (
    NetShieldConfig,
    MODE_VRCHAT,
    MODE_UNIVERSAL,
    MODE_CUSTOM,
    MIN_BANDWIDTH_MBPS,
    MAX_BANDWIDTH_MBPS,
    load_config,
)


class TestConfigDefaults:
    """Tests for default configuration values."""
    
    def test_default_config_valid(self, default_config):
        """Default configuration should pass validation."""
        errors = default_config.validate()
        assert errors == [], f"Default config has errors: {errors}"
    
    def test_default_mode_is_vrchat(self, default_config):
        """Default mode should be VRChat."""
        assert default_config.mode == MODE_VRCHAT
    
    def test_default_bandwidth_reasonable(self, default_config):
        """Default bandwidth should be 50 MB/s."""
        assert default_config.max_bandwidth_mbps == 50.0
    
    def test_default_countries_minimal(self, default_config):
        """Default high-risk countries should be minimal (only KP)."""
        # Fix #4: We use minimal conservative list by default
        assert len(default_config.high_risk_countries) <= 2


class TestConfigValidation:
    """Tests for configuration validation (Fix #5)."""
    
    def test_bandwidth_bounds_min_rejected(self):
        """Bandwidth below minimum should fail validation."""
        config = NetShieldConfig(max_bandwidth_mbps=0.5)
        errors = config.validate()
        assert any('max_bandwidth_mbps' in e for e in errors)
    
    def test_bandwidth_bounds_max_rejected(self):
        """Bandwidth above maximum should fail validation."""
        config = NetShieldConfig(max_bandwidth_mbps=2000.0)
        errors = config.validate()
        assert any('max_bandwidth_mbps' in e for e in errors)
    
    def test_bandwidth_at_min_valid(self):
        """Bandwidth at minimum should pass."""
        config = NetShieldConfig(max_bandwidth_mbps=MIN_BANDWIDTH_MBPS)
        errors = config.validate()
        assert not any('max_bandwidth_mbps' in e for e in errors)
    
    def test_bandwidth_at_max_valid(self):
        """Bandwidth at maximum should pass."""
        config = NetShieldConfig(max_bandwidth_mbps=MAX_BANDWIDTH_MBPS)
        errors = config.validate()
        assert not any('max_bandwidth_mbps' in e for e in errors)
    
    def test_burst_bounds_min_rejected(self):
        """Burst below minimum should fail."""
        config = NetShieldConfig(burst_size_mb=0.1)
        errors = config.validate()
        assert any('burst_size_mb' in e for e in errors)
    
    def test_burst_bounds_max_rejected(self):
        """Burst above maximum should fail."""
        config = NetShieldConfig(burst_size_mb=500.0)
        errors = config.validate()
        assert any('burst_size_mb' in e for e in errors)
    
    def test_invalid_mode_rejected(self):
        """Invalid mode string should fail."""
        config = NetShieldConfig(mode="invalid_mode")
        errors = config.validate()
        assert any('mode' in e.lower() for e in errors)
    
    def test_valid_modes_accepted(self):
        """All valid modes should pass."""
        for mode in [MODE_VRCHAT, MODE_UNIVERSAL, MODE_CUSTOM]:
            config = NetShieldConfig(mode=mode)
            errors = config.validate()
            assert not any('mode' in e.lower() for e in errors)
    
    def test_watchlist_threshold_bounds(self):
        """Watchlist threshold must be 0-100."""
        config = NetShieldConfig(watchlist_threshold=150)
        errors = config.validate()
        assert any('watchlist_threshold' in e for e in errors)
    
    def test_negative_cache_size_rejected(self):
        """Negative cache size should fail."""
        config = NetShieldConfig(cache_max_size=-1)
        errors = config.validate()
        assert any('cache_max_size' in e for e in errors)


class TestConfigLoading:
    """Tests for configuration file loading (Fix #4)."""
    
    def test_yaml_loading(self, temp_config_file):
        """Config should load from YAML file."""
        try:
            import yaml
            config = NetShieldConfig.from_yaml(temp_config_file)
            assert config.max_bandwidth_mbps == 25.0
            assert config.burst_size_mb == 8.0
        except ImportError:
            pytest.skip("PyYAML not installed")
    
    def test_countries_externalized(self, temp_config_file):
        """Countries should be loaded from config file (Fix #4)."""
        try:
            import yaml
            config = NetShieldConfig.from_yaml(temp_config_file)
            assert "KP" in config.high_risk_countries
            assert "TEST" in config.high_risk_countries
        except ImportError:
            pytest.skip("PyYAML not installed")
    
    def test_asn_keywords_externalized(self, temp_config_file):
        """ASN keywords should be loaded from config (Fix #4)."""
        try:
            import yaml
            config = NetShieldConfig.from_yaml(temp_config_file)
            assert "bulletproof" in config.suspicious_asn_keywords
            assert "test" in config.suspicious_asn_keywords
        except ImportError:
            pytest.skip("PyYAML not installed")
    
    def test_load_config_fallback(self):
        """load_config() should return default when no file exists."""
        config = load_config(Path("/nonexistent/path.yaml"))
        assert config is not None
        assert config.mode == MODE_VRCHAT
    
    def test_json_config_loading(self, tmp_path):
        """Config should load from JSON file."""
        import json
        config_data = {
            "mode": "universal",
            "limits": {"max_bandwidth_mbps": 75.0}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        config = NetShieldConfig.from_json(config_file)
        assert config.mode == "universal"
        assert config.max_bandwidth_mbps == 75.0


class TestConfigFrozenSets:
    """Tests for immutable configuration sets."""
    
    def test_countries_is_frozenset(self, default_config):
        """Countries should be frozenset (immutable)."""
        assert isinstance(default_config.high_risk_countries, frozenset)
    
    def test_asn_keywords_is_frozenset(self, default_config):
        """ASN keywords should be frozenset (immutable)."""
        assert isinstance(default_config.suspicious_asn_keywords, frozenset)
    
    def test_cannot_modify_countries(self, default_config):
        """Should not be able to modify countries set."""
        with pytest.raises((TypeError, AttributeError)):
            default_config.high_risk_countries.add("XX")
