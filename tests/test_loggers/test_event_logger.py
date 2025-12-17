"""
Event Logger Tests
==================
Tests for async logging with HMAC integrity.

Security Fixes Tested:
  - #9: HMAC integrity verification
  - #10: Async non-blocking writes
"""

import pytest
import json
import time
import os
from pathlib import Path

from netshield.loggers.event_logger import EventLogger
from netshield.models import IPProfile, ThreatEvent


class TestEventLoggerBasic:
    """Basic logging functionality tests."""
    
    def test_creates_log_directory(self, temp_log_dir):
        """Logger should create log directory."""
        new_dir = temp_log_dir.parent / "new_logs"
        logger = EventLogger(new_dir)
        
        try:
            assert new_dir.exists()
        finally:
            logger.stop()
    
    def test_creates_traffic_csv(self, temp_log_dir):
        """Logger should create traffic CSV with headers."""
        logger = EventLogger(temp_log_dir)
        
        try:
            import csv
            with open(logger.traffic_file, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader)
            
            assert "Timestamp" in headers
            assert "IP" in headers
            assert "ThreatScore" in headers
        finally:
            logger.stop()
    
    def test_log_event(self, temp_log_dir, sample_event):
        """log_event should write to events file."""
        logger = EventLogger(temp_log_dir)
        
        try:
            logger.log_event(sample_event)
            logger.flush()
            time.sleep(0.2)
            
            with open(logger.events_file, 'r') as f:
                lines = f.readlines()
            
            assert len(lines) >= 1
            data = json.loads(lines[0])
            assert data['ip'] == sample_event.ip
        finally:
            logger.stop()
    
    def test_log_traffic(self, temp_log_dir, sample_ip_profile):
        """log_traffic should write to CSV."""
        logger = EventLogger(temp_log_dir)
        
        try:
            logger.log_traffic(sample_ip_profile, 25.5, True)
            logger.flush()
            time.sleep(0.2)
            
            import csv
            with open(logger.traffic_file, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                row = next(reader)
            
            assert sample_ip_profile.ip in row
            assert "Yes" in row  # Throttled
        finally:
            logger.stop()


class TestAsyncLogging:
    """Async logging tests (Fix #10)."""
    
    def test_non_blocking_write(self, temp_log_dir, sample_event):
        """Log calls should return immediately (non-blocking)."""
        logger = EventLogger(temp_log_dir)
        
        try:
            start = time.time()
            
            for _ in range(100):
                logger.log_event(sample_event)
            
            elapsed = time.time() - start
            
            # Should be fast (<0.1s for queuing)
            assert elapsed < 0.5
        finally:
            logger.stop()
    
    def test_queue_overflow_handled(self, temp_log_dir, sample_event):
        """Queue overflow should not crash."""
        logger = EventLogger(temp_log_dir)
        
        try:
            # Try to overflow queue (10000 max)
            for _ in range(15000):
                logger.log_event(sample_event)
            
            # Should not raise
            logger.stop()
        except Exception as e:
            pytest.fail(f"Queue overflow crashed: {e}")
    
    def test_flush_waits_for_writes(self, temp_log_dir, sample_event):
        """flush() should wait for pending writes."""
        logger = EventLogger(temp_log_dir)
        
        try:
            for _ in range(10):
                logger.log_event(sample_event)
            
            logger.flush()
            time.sleep(0.2)
            
            with open(logger.events_file, 'r') as f:
                lines = f.readlines()
            
            assert len(lines) == 10
        finally:
            logger.stop()


class TestHMACIntegrity:
    """HMAC integrity tests (Fix #9)."""
    
    def test_hmac_computed_when_enabled(self, temp_log_dir, integrity_secret):
        """HMAC signature should be added when enabled."""
        logger = EventLogger(temp_log_dir, enable_integrity=True)
        
        try:
            event = ThreatEvent(
                timestamp="2024-01-01",
                event_type="test",
                ip="8.8.8.8",
                speed_mbps=10.0,
                threat_score=50
            )
            
            logger.log_event(event)
            logger.flush()
            time.sleep(0.2)
            
            with open(logger.events_file, 'r') as f:
                data = json.loads(f.readline())
            
            assert '_sig' in data
            assert len(data['_sig']) == 16  # Truncated HMAC
        finally:
            logger.stop()
    
    def test_hmac_not_added_when_disabled(self, temp_log_dir, sample_event):
        """HMAC should not be added when disabled."""
        logger = EventLogger(temp_log_dir, enable_integrity=False)
        
        try:
            logger.log_event(sample_event)
            logger.flush()
            time.sleep(0.2)
            
            with open(logger.events_file, 'r') as f:
                data = json.loads(f.readline())
            
            assert '_sig' not in data
        finally:
            logger.stop()
    
    def test_hmac_in_watchlist(self, temp_log_dir, sample_ip_profile, integrity_secret):
        """Watchlist entries should have HMAC when enabled."""
        logger = EventLogger(temp_log_dir, enable_integrity=True)
        
        try:
            logger.save_watchlist([sample_ip_profile])
            
            with open(logger.watchlist_file, 'r') as f:
                data = json.load(f)
            
            assert len(data) == 1
            assert '_sig' in data[0]
        finally:
            logger.stop()
    
    def test_hmac_in_traffic_csv(self, temp_log_dir, sample_ip_profile, integrity_secret):
        """Traffic CSV should have signature column when enabled."""
        logger = EventLogger(temp_log_dir, enable_integrity=True)
        
        try:
            logger.log_traffic(sample_ip_profile, 10.0, False)
            logger.flush()
            time.sleep(0.2)
            
            import csv
            with open(logger.traffic_file, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader)
                row = next(reader)
            
            assert "Signature" in headers
            assert len(row[-1]) > 0  # Signature present
        finally:
            logger.stop()


class TestAtomicWrites:
    """Atomic file write tests."""
    
    def test_watchlist_atomic_replace(self, temp_log_dir, sample_ip_profile):
        """Watchlist should be atomically replaced."""
        logger = EventLogger(temp_log_dir)
        
        try:
            # Write initial
            logger.save_watchlist([sample_ip_profile])
            
            # Write again
            sample_ip_profile.threat_score = 99
            logger.save_watchlist([sample_ip_profile])
            
            # Should have updated data
            with open(logger.watchlist_file, 'r') as f:
                data = json.load(f)
            
            assert data[0]['threat_score'] == 99
            
            # Temp file should not exist
            temp_file = logger.watchlist_file.with_suffix('.tmp')
            assert not temp_file.exists()
        finally:
            logger.stop()


class TestLoggerCleanup:
    """Cleanup and shutdown tests."""
    
    def test_stop_graceful(self, temp_log_dir):
        """stop() should complete without errors."""
        logger = EventLogger(temp_log_dir)
        logger.stop()
        # Should not raise
    
    def test_stop_after_writes(self, temp_log_dir, sample_event):
        """stop() after writes should flush."""
        logger = EventLogger(temp_log_dir)
        
        for _ in range(5):
            logger.log_event(sample_event)
        
        logger.stop()
        time.sleep(0.2)
        
        # Check writes completed
        with open(logger.events_file, 'r') as f:
            lines = f.readlines()
        
        assert len(lines) >= 1  # At least some written
