"""
NetShield Data Models
=====================
Thread-safe dataclasses with input sanitization.

Security Fixes:
  - #3: Input sanitization for all string fields
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ============================================================================
# SANITIZATION (Fix #3)
# ============================================================================

# Pattern for dangerous characters in logs
DANGEROUS_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')
MAX_FIELD_LENGTH = 256


def sanitize_string(value: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """
    Sanitize string for safe logging.
    
    Security Fix #3: Prevents log injection attacks by:
    1. Removing control characters
    2. Truncating to max length
    3. Stripping leading/trailing whitespace
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Remove control characters
    value = DANGEROUS_CHARS.sub('', value)
    
    # Truncate
    if len(value) > max_length:
        value = value[:max_length - 3] + "..."
    
    return value.strip()


def sanitize_ip(ip: str) -> str:
    """Validate and sanitize IP address format."""
    # Basic IP validation - only allow valid characters
    if not re.match(r'^[\d.:a-fA-F]+$', ip):
        return "invalid"
    return ip[:45]  # Max IPv6 length


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class IPProfile:
    """
    IP address profile with OSINT data.
    All string fields are sanitized on assignment.
    """
    ip: str
    first_seen: str
    last_seen: str
    
    # WHOIS data (sanitized)
    country: str = "Unknown"
    asn: str = "Unknown"
    asn_description: str = "Unknown"
    network_name: str = "Unknown"
    network_cidr: str = "Unknown"
    abuse_contact: str = "Unknown"
    
    # Traffic statistics
    total_bytes: int = 0
    total_packets: int = 0
    throttled_packets: int = 0
    max_speed_mbps: float = 0.0
    
    # Threat assessment
    threat_score: int = 0
    threat_reasons: list = field(default_factory=list)
    
    # Cache management (Fix #2)
    last_access: float = 0.0  # For LRU eviction
    
    def __post_init__(self):
        """Sanitize all string fields after initialization."""
        self.ip = sanitize_ip(self.ip)
        self.country = sanitize_string(self.country, 10)
        self.asn = sanitize_string(self.asn, 20)
        self.asn_description = sanitize_string(self.asn_description, 128)
        self.network_name = sanitize_string(self.network_name, 128)
        self.network_cidr = sanitize_string(self.network_cidr, 50)
        self.abuse_contact = sanitize_string(self.abuse_contact, 128)
    
    def update_whois(self, country: str, asn: str, asn_desc: str, 
                     network_name: str, network_cidr: str, abuse: str):
        """Update WHOIS fields with sanitization."""
        self.country = sanitize_string(country, 10)
        self.asn = sanitize_string(asn, 20)
        self.asn_description = sanitize_string(asn_desc, 128)
        self.network_name = sanitize_string(network_name, 128)
        self.network_cidr = sanitize_string(network_cidr, 50)
        self.abuse_contact = sanitize_string(abuse, 128)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "country": self.country,
            "asn": self.asn,
            "asn_description": self.asn_description,
            "network_name": self.network_name,
            "network_cidr": self.network_cidr,
            "abuse_contact": self.abuse_contact,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "throttled_packets": self.throttled_packets,
            "max_speed_mbps": self.max_speed_mbps,
            "threat_score": self.threat_score,
            "threat_reasons": [sanitize_string(r) for r in self.threat_reasons],
        }


@dataclass
class ThreatEvent:
    """
    Security event record.
    All fields sanitized for safe logging.
    """
    timestamp: str
    event_type: str  # throttle, high_score, burst, whois_error
    ip: str
    speed_mbps: float
    threat_score: int
    details: dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Sanitize fields."""
        self.ip = sanitize_ip(self.ip)
        self.event_type = sanitize_string(self.event_type, 32)
        
        # Sanitize details dict values
        if self.details:
            self.details = {
                sanitize_string(str(k), 64): sanitize_string(str(v), 256)
                if isinstance(v, str) else v
                for k, v in self.details.items()
            }
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "ip": self.ip,
            "speed_mbps": round(self.speed_mbps, 2),
            "threat_score": self.threat_score,
            "details": self.details,
        }


@dataclass  
class SessionStats:
    """Aggregated session statistics."""
    start_time: str = ""
    total_bytes: int = 0
    total_packets: int = 0
    throttled_bytes: int = 0
    throttled_packets: int = 0
    unique_ips: int = 0
    watchlist_count: int = 0
    
    def to_dict(self) -> dict:
        return {
            "start_time": self.start_time,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "throttled_bytes": self.throttled_bytes,
            "throttled_packets": self.throttled_packets,
            "unique_ips": self.unique_ips,
            "watchlist_count": self.watchlist_count,
        }
