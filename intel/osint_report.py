"""
OSINT Report Generator
======================
Generates comprehensive OSINT reports from collected IP intelligence.

Features:
  - WHOIS data aggregation
  - GeoIP enrichment
  - ASN analysis
  - Abuse contact extraction
  - Threat correlation
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from ..models import IPProfile


class OSINTReport:
    """
    Generates detailed OSINT reports from IP profiles.
    
    Output Formats:
      - JSON (machine-readable)
      - Markdown (human-readable)
      - CSV (for SIEM import)
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for report files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_profile_report(self, profile: "IPProfile") -> dict:
        """
        Generate OSINT report for single IP.
        
        Returns dict with all available intelligence.
        """
        return {
            "ip": profile.ip,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            
            # GeoIP / WHOIS
            "geolocation": {
                "country_code": profile.country,
                "network_name": profile.network_name,
                "cidr": profile.network_cidr,
            },
            
            # ASN Analysis
            "asn": {
                "number": profile.asn,
                "description": profile.asn_description,
                "is_hosting": self._is_hosting_asn(profile.asn_description),
                "is_proxy": self._is_proxy_asn(profile.asn_description),
            },
            
            # Abuse Contact
            "abuse": {
                "contact": profile.abuse_contact,
            },
            
            # Traffic Analysis
            "traffic": {
                "total_bytes": profile.total_bytes,
                "total_packets": profile.total_packets,
                "throttled_packets": profile.throttled_packets,
                "throttle_ratio": self._safe_ratio(
                    profile.throttled_packets, 
                    profile.total_packets
                ),
                "max_speed_mbps": profile.max_speed_mbps,
            },
            
            # Threat Assessment
            "threat": {
                "score": profile.threat_score,
                "classification": self._classify_threat(profile.threat_score),
                "reasons": profile.threat_reasons,
            },
            
            # Metadata
            "generated_at": datetime.now().isoformat(),
        }
    
    def generate_session_report(self, 
                                 profiles: list["IPProfile"],
                                 session_stats: dict = None) -> dict:
        """
        Generate comprehensive OSINT report for session.
        """
        # Aggregate statistics
        total_ips = len(profiles)
        high_risk_ips = [p for p in profiles if p.threat_score >= 80]
        medium_risk_ips = [p for p in profiles if 50 <= p.threat_score < 80]
        
        # Country breakdown
        countries = {}
        for p in profiles:
            countries[p.country] = countries.get(p.country, 0) + 1
        
        # ASN breakdown
        asns = {}
        for p in profiles:
            key = f"{p.asn} ({p.asn_description[:30]}...)" if len(p.asn_description) > 30 else f"{p.asn} ({p.asn_description})"
            asns[key] = asns.get(key, 0) + 1
        
        # Top offenders
        top_by_traffic = sorted(profiles, key=lambda x: x.total_bytes, reverse=True)[:10]
        top_by_throttle = sorted(profiles, key=lambda x: x.throttled_packets, reverse=True)[:10]
        top_by_score = sorted(profiles, key=lambda x: x.threat_score, reverse=True)[:10]
        
        return {
            "summary": {
                "total_ips": total_ips,
                "high_risk_count": len(high_risk_ips),
                "medium_risk_count": len(medium_risk_ips),
            },
            
            "geographic_distribution": dict(sorted(
                countries.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:20]),
            
            "asn_distribution": dict(sorted(
                asns.items(),
                key=lambda x: x[1],
                reverse=True
            )[:20]),
            
            "top_offenders": {
                "by_traffic": [self._short_profile(p) for p in top_by_traffic],
                "by_throttled": [self._short_profile(p) for p in top_by_throttle],
                "by_threat_score": [self._short_profile(p) for p in top_by_score],
            },
            
            "high_risk_ips": [self.generate_profile_report(p) for p in high_risk_ips[:50]],
            
            "session_stats": session_stats or {},
            
            "generated_at": datetime.now().isoformat(),
        }
    
    def save_json(self, report: dict, filename: str):
        """Save report as JSON."""
        path = self.output_dir / f"{filename}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return path
    
    def save_markdown(self, report: dict, filename: str) -> Path:
        """Save report as Markdown."""
        path = self.output_dir / f"{filename}.md"
        
        lines = [
            "# NetShield OSINT Report",
            f"\n**Generated:** {report.get('generated_at', 'N/A')}",
            "\n---\n",
        ]
        
        # Summary
        if 'summary' in report:
            s = report['summary']
            lines.extend([
                "## Summary\n",
                f"- **Total IPs:** {s.get('total_ips', 0)}",
                f"- **High Risk:** {s.get('high_risk_count', 0)}",
                f"- **Medium Risk:** {s.get('medium_risk_count', 0)}",
                "\n"
            ])
        
        # Geographic Distribution
        if 'geographic_distribution' in report:
            lines.append("## Geographic Distribution\n")
            lines.append("| Country | Count |")
            lines.append("|---------|-------|")
            for country, count in list(report['geographic_distribution'].items())[:10]:
                lines.append(f"| {country} | {count} |")
            lines.append("\n")
        
        # Top Offenders
        if 'top_offenders' in report:
            lines.append("## Top Offenders (by Threat Score)\n")
            lines.append("| IP | Country | ASN | Score |")
            lines.append("|----|---------|-----|-------|")
            for p in report['top_offenders'].get('by_threat_score', [])[:10]:
                lines.append(f"| {p['ip']} | {p['country']} | {p['asn']} | {p['score']} |")
            lines.append("\n")
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        return path
    
    def _short_profile(self, profile: "IPProfile") -> dict:
        """Get shortened profile for lists."""
        return {
            "ip": profile.ip,
            "country": profile.country,
            "asn": profile.asn,
            "score": profile.threat_score,
            "bytes": profile.total_bytes,
            "throttled": profile.throttled_packets,
        }
    
    def _safe_ratio(self, numerator: int, denominator: int) -> float:
        """Safe division."""
        if denominator == 0:
            return 0.0
        return round(numerator / denominator, 4)
    
    def _classify_threat(self, score: int) -> str:
        """Classify threat level."""
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 25:
            return "LOW"
        return "NORMAL"
    
    def _is_hosting_asn(self, asn_desc: str) -> bool:
        """Check if ASN is hosting/cloud."""
        keywords = {'hosting', 'cloud', 'vps', 'server', 'datacenter', 
                    'hetzner', 'ovh', 'digitalocean', 'vultr', 'linode', 'aws', 'azure'}
        return any(kw in asn_desc.lower() for kw in keywords)
    
    def _is_proxy_asn(self, asn_desc: str) -> bool:
        """Check if ASN is proxy/VPN."""
        keywords = {'tor', 'vpn', 'proxy', 'anonymous', 'privacy', 
                    'mullvad', 'nordvpn', 'expressvpn', 'proton'}
        return any(kw in asn_desc.lower() for kw in keywords)
