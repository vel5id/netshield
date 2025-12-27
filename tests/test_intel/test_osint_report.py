"""
OSINT Report Tests
==================
Tests for OSINT report generation.
"""

import pytest
from pathlib import Path

from netshield.intel.osint_report import OSINTReport
from netshield.models import IPProfile


class TestOSINTReportTopOffenders:
    """Tests for top offenders extraction using heapq."""
    
    def test_top_offenders_by_traffic(self, tmp_path):
        """Top offenders by traffic should return highest traffic IPs."""
        report = OSINTReport(tmp_path)
        
        # Create profiles with varying traffic
        profiles = []
        for i in range(20):
            p = IPProfile(
                ip=f"192.168.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            p.total_bytes = i * 1000
            p.throttled_packets = i
            p.threat_score = i * 5
            profiles.append(p)
        
        result = report.generate_session_report(profiles)
        
        # Top 10 by traffic should be IPs 19 down to 10
        top_traffic = result["top_offenders"]["by_traffic"]
        assert len(top_traffic) == 10
        assert top_traffic[0]["ip"] == "192.168.1.19"
        assert top_traffic[0]["bytes"] == 19000
    
    def test_top_offenders_by_throttle(self, tmp_path):
        """Top offenders by throttle should return highest throttled IPs."""
        report = OSINTReport(tmp_path)
        
        profiles = []
        for i in range(20):
            p = IPProfile(
                ip=f"192.168.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            p.total_bytes = 1000
            p.throttled_packets = i * 10
            p.threat_score = 50
            profiles.append(p)
        
        result = report.generate_session_report(profiles)
        
        top_throttle = result["top_offenders"]["by_throttled"]
        assert len(top_throttle) == 10
        assert top_throttle[0]["ip"] == "192.168.1.19"
        assert top_throttle[0]["throttled"] == 190
    
    def test_top_offenders_by_score(self, tmp_path):
        """Top offenders by score should return highest threat score IPs."""
        report = OSINTReport(tmp_path)
        
        profiles = []
        for i in range(20):
            p = IPProfile(
                ip=f"192.168.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            p.total_bytes = 1000
            p.throttled_packets = 10
            p.threat_score = i * 5
            profiles.append(p)
        
        result = report.generate_session_report(profiles)
        
        top_score = result["top_offenders"]["by_threat_score"]
        assert len(top_score) == 10
        assert top_score[0]["ip"] == "192.168.1.19"
        assert top_score[0]["score"] == 95
    
    def test_handles_small_profile_list(self, tmp_path):
        """Should handle lists smaller than 10."""
        report = OSINTReport(tmp_path)
        
        profiles = []
        for i in range(3):
            p = IPProfile(
                ip=f"192.168.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            p.total_bytes = i * 1000
            profiles.append(p)
        
        result = report.generate_session_report(profiles)
        
        assert len(result["top_offenders"]["by_traffic"]) == 3
    
    def test_handles_empty_profile_list(self, tmp_path):
        """Should handle empty profile list."""
        report = OSINTReport(tmp_path)
        
        result = report.generate_session_report([])
        
        assert result["summary"]["total_ips"] == 0
        assert len(result["top_offenders"]["by_traffic"]) == 0


class TestOSINTReportRiskCategories:
    """Tests for risk category aggregation."""
    
    def test_high_risk_count(self, tmp_path):
        """Should correctly count high risk IPs."""
        report = OSINTReport(tmp_path)
        
        profiles = []
        for i in range(10):
            p = IPProfile(
                ip=f"192.168.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            # 3 high risk (score >= 80)
            p.threat_score = 90 if i < 3 else 30
            profiles.append(p)
        
        result = report.generate_session_report(profiles)
        
        assert result["summary"]["high_risk_count"] == 3
    
    def test_medium_risk_count(self, tmp_path):
        """Should correctly count medium risk IPs."""
        report = OSINTReport(tmp_path)
        
        profiles = []
        for i in range(10):
            p = IPProfile(
                ip=f"192.168.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            # 4 medium risk (50 <= score < 80)
            if i < 4:
                p.threat_score = 60
            else:
                p.threat_score = 30
            profiles.append(p)
        
        result = report.generate_session_report(profiles)
        
        assert result["summary"]["medium_risk_count"] == 4
