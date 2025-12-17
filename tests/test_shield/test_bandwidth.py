"""
Bandwidth Monitor Tests
=======================
Tests for real-time speed measurement.
"""

import pytest
import time

from netshield.shield.bandwidth import BandwidthMonitor


class TestBandwidthMonitorBasic:
    """Basic functionality tests."""
    
    def test_speed_calculation(self):
        """Speed should be calculated correctly."""
        monitor = BandwidthMonitor(window_sec=1.0)
        
        # Add 1 MB of samples
        for _ in range(10):
            monitor.add_sample(102400)  # 100 KB each
        
        speed = monitor.get_speed_mbps()
        assert speed == pytest.approx(1.0, rel=0.2)
    
    def test_empty_window_zero(self):
        """Empty window should return 0."""
        monitor = BandwidthMonitor(window_sec=1.0)
        
        assert monitor.get_speed_mbps() == 0.0
    
    def test_sliding_window_expiry(self):
        """Old samples should be removed."""
        monitor = BandwidthMonitor(window_sec=0.1)
        
        monitor.add_sample(1000000)  # 1 MB
        time.sleep(0.15)  # Wait for expiry
        
        speed = monitor.get_speed_mbps()
        assert speed == 0.0


class TestBandwidthMonitorValidation:
    """Input validation tests."""
    
    def test_reject_negative_window(self):
        """Negative window should raise ValueError."""
        with pytest.raises(ValueError):
            BandwidthMonitor(window_sec=-1.0)
    
    def test_reject_zero_window(self):
        """Zero window should raise ValueError."""
        with pytest.raises(ValueError):
            BandwidthMonitor(window_sec=0.0)
    
    def test_negative_bytes_ignored(self):
        """Negative bytes should be ignored."""
        monitor = BandwidthMonitor(window_sec=1.0)
        monitor.add_sample(-1000)
        
        assert monitor.get_sample_count() == 0


class TestBandwidthMonitorWindow:
    """Sliding window behavior tests."""
    
    def test_samples_within_window(self):
        """Samples within window should be counted."""
        monitor = BandwidthMonitor(window_sec=1.0)
        
        for _ in range(5):
            monitor.add_sample(1000)
        
        assert monitor.get_sample_count() == 5
    
    def test_window_cleanup(self):
        """get_speed should clean up old samples."""
        monitor = BandwidthMonitor(window_sec=0.1)
        
        monitor.add_sample(1000)
        time.sleep(0.15)
        
        # This should trigger cleanup
        _ = monitor.get_speed_mbps()
        
        assert monitor.get_sample_count() == 0
    
    def test_reset_clears_all(self):
        """reset should clear all samples."""
        monitor = BandwidthMonitor(window_sec=1.0)
        
        for _ in range(10):
            monitor.add_sample(1000)
        
        monitor.reset()
        
        assert monitor.get_sample_count() == 0
        assert monitor.get_speed_mbps() == 0.0


class TestBandwidthMonitorPrecision:
    """Precision and accuracy tests."""
    
    def test_speed_bps(self):
        """get_speed_bps should return bytes per second."""
        monitor = BandwidthMonitor(window_sec=1.0)
        
        monitor.add_sample(1000000)  # 1 MB
        
        speed_bps = monitor.get_speed_bps()
        speed_mbps = monitor.get_speed_mbps()
        
        assert speed_bps == pytest.approx(speed_mbps * 1024 * 1024, rel=0.01)
    
    def test_multiple_samples_accuracy(self):
        """Multiple samples should be summed correctly."""
        monitor = BandwidthMonitor(window_sec=1.0)
        
        # Add exactly 10 MB
        for _ in range(10):
            monitor.add_sample(1024 * 1024)
        
        speed = monitor.get_speed_mbps()
        assert speed == pytest.approx(10.0, rel=0.1)
