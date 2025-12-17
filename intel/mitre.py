"""
MITRE ATT&CK TTP Mapper
=======================
Maps observed network behavior to MITRE ATT&CK techniques.

Reference: https://attack.mitre.org/techniques/enterprise/

Security:
  - Read-only technique database
  - No external dependencies in hot path
  - Deterministic classification
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import IPProfile


@dataclass(frozen=True)
class Technique:
    """MITRE ATT&CK technique definition."""
    id: str
    name: str
    tactic: str
    description: str


# MITRE ATT&CK Techniques relevant to network protection
TECHNIQUES = {
    # Impact
    "T1498": Technique(
        id="T1498",
        name="Network Denial of Service",
        tactic="Impact",
        description="Adversary performs DoS to degrade availability"
    ),
    "T1498.001": Technique(
        id="T1498.001",
        name="Direct Network Flood",
        tactic="Impact",
        description="Volumetric flood attack (UDP/ICMP)"
    ),
    "T1498.002": Technique(
        id="T1498.002",
        name="Reflection Amplification",
        tactic="Impact",
        description="Amplified DoS using third-party services"
    ),
    
    # Command and Control
    "T1090": Technique(
        id="T1090",
        name="Proxy",
        tactic="Command and Control",
        description="Using proxies to route traffic"
    ),
    "T1090.003": Technique(
        id="T1090.003",
        name="Multi-hop Proxy (Tor)",
        tactic="Command and Control",
        description="Traffic routed through Tor network"
    ),
    
    # Defense Evasion
    "T1571": Technique(
        id="T1571",
        name="Non-Standard Port",
        tactic="Defense Evasion",
        description="Using unusual ports to evade detection"
    ),
    
    # Initial Access
    "T1133": Technique(
        id="T1133",
        name="External Remote Services",
        tactic="Initial Access",
        description="Remote services exposed to internet"
    ),
    
    # Collection
    "T1040": Technique(
        id="T1040",
        name="Network Sniffing",
        tactic="Collection",
        description="Passive network traffic capture"
    ),
}


class TTPMapper:
    """
    Maps IP profiles to MITRE ATT&CK techniques.
    
    Usage:
        mapper = TTPMapper()
        ttps = mapper.classify(profile, speed=150, protocol="udp")
        for ttp in ttps:
            print(f"{ttp.id}: {ttp.name}")
    """
    
    # Detection thresholds
    FLOOD_SPEED_THRESHOLD = 100.0  # MB/s
    HIGH_THROTTLE_RATIO = 0.5
    
    # Known proxy/anonymizer keywords
    PROXY_KEYWORDS = frozenset({
        'tor', 'exit', 'relay', 'vpn', 'proxy', 'anonymous',
        'mullvad', 'nordvpn', 'expressvpn', 'proton'
    })
    
    # Known bulletproof hosting
    BULLETPROOF_KEYWORDS = frozenset({
        'bulletproof', 'offshore', 'privacy', 'anonymous'
    })
    
    def classify(self, profile: "IPProfile", 
                 speed_mbps: float = 0.0,
                 protocol: str = "udp") -> list[Technique]:
        """
        Classify IP behavior to MITRE techniques.
        
        Args:
            profile: IP profile with WHOIS data
            speed_mbps: Current traffic speed
            protocol: Protocol (udp/tcp)
            
        Returns:
            List of detected MITRE techniques
        """
        detected = []
        
        # T1498.001: Direct Network Flood
        if speed_mbps > self.FLOOD_SPEED_THRESHOLD:
            detected.append(TECHNIQUES["T1498.001"])
        
        # T1498: General DoS (high throttle ratio indicates sustained attack)
        if profile.total_packets > 100:
            ratio = profile.throttled_packets / profile.total_packets
            if ratio > self.HIGH_THROTTLE_RATIO:
                if TECHNIQUES["T1498"] not in detected:
                    detected.append(TECHNIQUES["T1498"])
        
        # T1090.003: Tor/Proxy
        asn_lower = profile.asn_description.lower()
        network_lower = profile.network_name.lower()
        combined = asn_lower + " " + network_lower
        
        if any(kw in combined for kw in self.PROXY_KEYWORDS):
            detected.append(TECHNIQUES["T1090.003"])
        
        # T1090: General Proxy (VPN/hosting)
        if any(kw in combined for kw in self.BULLETPROOF_KEYWORDS):
            detected.append(TECHNIQUES["T1090"])
        
        # T1571: Non-standard port (not common VRChat ports)
        # Placeholder: would need port info
        
        return detected
    
    def get_technique(self, technique_id: str) -> Technique | None:
        """Get technique by ID."""
        return TECHNIQUES.get(technique_id)
    
    def format_report(self, techniques: list[Technique]) -> str:
        """Format detected techniques as report string."""
        if not techniques:
            return "No MITRE ATT&CK techniques detected"
        
        lines = ["MITRE ATT&CK Classification:"]
        for t in techniques:
            lines.append(f"  [{t.id}] {t.name} ({t.tactic})")
        
        return "\n".join(lines)
