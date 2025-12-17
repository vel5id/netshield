"""
NetShield Configuration Module
==============================
Централизованная конфигурация с валидацией и YAML-загрузкой.

Security Fixes:
  - #4: Externalized risk countries (configurable)
  - #5: CLI argument validation with bounds
"""

import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import json

# Optional YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ============================================================================
# CONFIG PATHS
# ============================================================================

CONFIG_DIR = Path(__file__).parent
DEFAULT_CONFIG_FILE = CONFIG_DIR / "config.yaml"
USER_CONFIG_FILE = Path.home() / ".netshield" / "config.yaml"


# ============================================================================
# VALIDATION CONSTANTS
# ============================================================================

# CLI argument bounds (Fix #5)
MIN_BANDWIDTH_MBPS = 1.0
MAX_BANDWIDTH_MBPS = 1000.0
MIN_BURST_SIZE_MB = 1.0
MAX_BURST_SIZE_MB = 100.0

# Memory protection (Fix #2)
MAX_CACHE_SIZE = 50000
CACHE_TTL_HOURS = 24

# WHOIS rate limiting (Fix #7)
WHOIS_RATE_LIMIT_PER_SEC = 5


# ============================================================================
# MODE CONSTANTS
# ============================================================================

MODE_VRCHAT = "vrchat"
MODE_UNIVERSAL = "universal"
MODE_CUSTOM = "custom"

VALID_MODES = {MODE_VRCHAT, MODE_UNIVERSAL, MODE_CUSTOM}
DEFAULT_MODE = MODE_VRCHAT


# ============================================================================
# PORT DEFINITIONS
# ============================================================================

VRCHAT_PORTS = [5055, 5056, 5058] + list(range(27000, 27101))


# ============================================================================
# THREAT INTEL DEFAULTS (Fix #4 - Externalized)
# ============================================================================

# DISCLAIMER: This list is for demonstration purposes only.
# Configure according to your organization's threat model and compliance requirements.
# We only include countries with UN sanctions by default.
DEFAULT_HIGH_RISK_COUNTRIES = frozenset({"KP"})  # North Korea only by default

DEFAULT_SUSPICIOUS_ASN_KEYWORDS = frozenset({
    "hosting", "vps", "cloud", "proxy", "vpn", "bulletproof"
})


# ============================================================================
# LOGGING DEFAULTS
# ============================================================================

DEFAULT_LOG_DIR = Path("netshield_logs")
EVENTS_LOG_FILENAME = "events.jsonl"
WATCHLIST_LOG_FILENAME = "watchlist.json"
TRAFFIC_LOG_FILENAME = "traffic.csv"

# Log rotation (Fix #10)
MAX_LOG_SIZE_MB = 100

# Log integrity (Fix #9)
ENABLE_LOG_INTEGRITY = False
INTEGRITY_SECRET_ENV = "NETSHIELD_LOG_SECRET"


# ============================================================================
# WATCHLIST
# ============================================================================

WATCHLIST_THRESHOLD = 80
MAX_WATCHLIST_ENTRIES = 10000


# ============================================================================
# TIMING (Fix #6)
# ============================================================================

# Add jitter to prevent timing side-channel attacks
THROTTLE_JITTER_MS = 10  # Max random jitter in milliseconds


# ============================================================================
# CONFIG DATACLASS
# ============================================================================

@dataclass
class NetShieldConfig:
    """Main configuration container with validation."""
    
    # Mode
    mode: str = MODE_VRCHAT
    
    # Rate limiting
    max_bandwidth_mbps: float = 50.0
    burst_size_mb: float = 10.0
    
    # Watchlist
    watchlist_threshold: int = 80
    
    # Threat Intel
    high_risk_countries: frozenset = field(default_factory=lambda: DEFAULT_HIGH_RISK_COUNTRIES)
    suspicious_asn_keywords: frozenset = field(default_factory=lambda: DEFAULT_SUSPICIOUS_ASN_KEYWORDS)
    
    # WHOIS
    whois_enabled: bool = True
    whois_rate_limit: int = WHOIS_RATE_LIMIT_PER_SEC
    
    # Cache limits (Fix #2)
    cache_max_size: int = MAX_CACHE_SIZE
    cache_ttl_hours: int = CACHE_TTL_HOURS
    
    # Logging
    log_dir: Path = field(default_factory=lambda: DEFAULT_LOG_DIR)
    log_integrity: bool = False
    
    # Timing (Fix #6)
    throttle_jitter_ms: int = THROTTLE_JITTER_MS
    
    def validate(self) -> list[str]:
        """
        Validates configuration. Returns list of errors.
        
        Security Fix #5: CLI argument validation with bounds
        """
        errors = []
        
        # Mode validation
        if self.mode not in VALID_MODES:
            errors.append(f"Invalid mode: {self.mode}. Valid: {VALID_MODES}")
        
        # Bandwidth bounds
        if not (MIN_BANDWIDTH_MBPS <= self.max_bandwidth_mbps <= MAX_BANDWIDTH_MBPS):
            errors.append(
                f"max_bandwidth_mbps must be between {MIN_BANDWIDTH_MBPS} and {MAX_BANDWIDTH_MBPS}, "
                f"got {self.max_bandwidth_mbps}"
            )
        
        # Burst bounds
        if not (MIN_BURST_SIZE_MB <= self.burst_size_mb <= MAX_BURST_SIZE_MB):
            errors.append(
                f"burst_size_mb must be between {MIN_BURST_SIZE_MB} and {MAX_BURST_SIZE_MB}, "
                f"got {self.burst_size_mb}"
            )
        
        # Watchlist threshold
        if not (0 <= self.watchlist_threshold <= 100):
            errors.append(f"watchlist_threshold must be 0-100, got {self.watchlist_threshold}")
        
        # Cache size
        if self.cache_max_size <= 0:
            errors.append(f"cache_max_size must be positive, got {self.cache_max_size}")
        
        return errors
    
    @classmethod
    def from_yaml(cls, path: Path) -> "NetShieldConfig":
        """Load config from YAML file."""
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML required: pip install pyyaml")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return cls._from_dict(data)
    
    @classmethod
    def from_json(cls, path: Path) -> "NetShieldConfig":
        """Load config from JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return cls._from_dict(data)
    
    @classmethod
    def _from_dict(cls, data: dict) -> "NetShieldConfig":
        """Create config from dictionary."""
        config = cls()
        
        if 'mode' in data:
            config.mode = data['mode']
        
        limits = data.get('limits', {})
        if 'max_bandwidth_mbps' in limits:
            config.max_bandwidth_mbps = float(limits['max_bandwidth_mbps'])
        if 'burst_size_mb' in limits:
            config.burst_size_mb = float(limits['burst_size_mb'])
        
        watchlist = data.get('watchlist', {})
        if 'threshold' in watchlist:
            config.watchlist_threshold = int(watchlist['threshold'])
        
        threat = data.get('threat_intel', {})
        if 'high_risk_countries' in threat:
            config.high_risk_countries = frozenset(threat['high_risk_countries'])
        if 'suspicious_asn_keywords' in threat:
            config.suspicious_asn_keywords = frozenset(threat['suspicious_asn_keywords'])
        
        whois = data.get('whois', {})
        if 'enabled' in whois:
            config.whois_enabled = bool(whois['enabled'])
        if 'rate_limit_per_sec' in whois:
            config.whois_rate_limit = int(whois['rate_limit_per_sec'])
        if 'cache_max_size' in whois:
            config.cache_max_size = int(whois['cache_max_size'])
        
        logging = data.get('logging', {})
        if 'directory' in logging:
            config.log_dir = Path(logging['directory'])
        if 'integrity_check' in logging:
            config.log_integrity = bool(logging['integrity_check'])
        
        return config


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def load_config(config_path: Optional[Path] = None) -> NetShieldConfig:
    """
    Load configuration with fallback chain:
    1. Explicit path
    2. User config (~/.netshield/config.yaml)
    3. Default config
    """
    paths_to_try = []
    
    if config_path:
        paths_to_try.append(config_path)
    
    paths_to_try.append(USER_CONFIG_FILE)
    paths_to_try.append(DEFAULT_CONFIG_FILE)
    
    for path in paths_to_try:
        if path.exists():
            try:
                if path.suffix in ('.yaml', '.yml'):
                    return NetShieldConfig.from_yaml(path)
                elif path.suffix == '.json':
                    return NetShieldConfig.from_json(path)
            except Exception:
                continue
    
    # Return default config
    return NetShieldConfig()


def get_log_integrity_secret() -> Optional[bytes]:
    """Get log integrity secret from environment (Fix #9)."""
    secret = os.environ.get(INTEGRITY_SECRET_ENV)
    if secret:
        return secret.encode('utf-8')
    return None
