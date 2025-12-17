"""
Token Bucket Tests
==================
Tests for rate limiting algorithm.
"""

import pytest
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from netshield.shield.token_bucket import TokenBucket


class TestTokenBucketBasic:
    """Basic token bucket functionality tests."""
    
    def test_full_bucket_allows_all(self):
        """Full bucket should allow packets."""
        bucket = TokenBucket(
            rate_bytes_per_sec=1000.0,
            bucket_size_bytes=1000.0
        )
        
        allowed, wait_time = bucket.consume(500)
        assert allowed is True
        assert wait_time == 0.0
    
    def test_empty_bucket_throttles(self):
        """Empty bucket should throttle."""
        bucket = TokenBucket(
            rate_bytes_per_sec=100.0,
            bucket_size_bytes=100.0
        )
        
        # Exhaust bucket
        bucket.consume(100)
        
        # Next should throttle
        allowed, wait_time = bucket.consume(50)
        assert allowed is False
        assert wait_time > 0
    
    def test_refill_over_time(self):
        """Tokens should refill over time."""
        bucket = TokenBucket(
            rate_bytes_per_sec=1000.0,
            bucket_size_bytes=1000.0
        )
        
        # Exhaust bucket
        bucket.consume(1000)
        
        # Wait for refill
        time.sleep(0.5)
        
        # Should have ~500 tokens refilled
        allowed, _ = bucket.consume(400)
        assert allowed is True
    
    def test_bucket_caps_at_max(self):
        """Tokens should not exceed bucket size."""
        bucket = TokenBucket(
            rate_bytes_per_sec=10000.0,  # Fast refill
            bucket_size_bytes=100.0
        )
        
        # Wait for "extra" refill
        time.sleep(0.1)
        
        # Should still be capped at 100
        allowed, _ = bucket.consume(100)
        assert allowed is True
        
        allowed, _ = bucket.consume(1)  # Any more should fail
        assert allowed is False


class TestTokenBucketValidation:
    """Input validation tests."""
    
    def test_reject_negative_rate(self):
        """Negative rate should raise ValueError."""
        with pytest.raises(ValueError):
            TokenBucket(rate_bytes_per_sec=-100.0, bucket_size_bytes=100.0)
    
    def test_reject_zero_rate(self):
        """Zero rate should raise ValueError."""
        with pytest.raises(ValueError):
            TokenBucket(rate_bytes_per_sec=0.0, bucket_size_bytes=100.0)
    
    def test_reject_negative_bucket(self):
        """Negative bucket size should raise ValueError."""
        with pytest.raises(ValueError):
            TokenBucket(rate_bytes_per_sec=100.0, bucket_size_bytes=-100.0)
    
    def test_reject_negative_bytes(self):
        """Negative bytes should raise ValueError."""
        bucket = TokenBucket(
            rate_bytes_per_sec=100.0,
            bucket_size_bytes=100.0
        )
        with pytest.raises(ValueError):
            bucket.consume(-10)


class TestTokenBucketStats:
    """Statistics tracking tests."""
    
    def test_stats_total_bytes(self):
        """total_bytes should accumulate."""
        bucket = TokenBucket(
            rate_bytes_per_sec=10000.0,
            bucket_size_bytes=10000.0
        )
        
        bucket.consume(100)
        bucket.consume(200)
        bucket.consume(300)
        
        stats = bucket.get_stats()
        assert stats['total_bytes'] == 600
    
    def test_stats_packet_count(self):
        """packets should count consume calls."""
        bucket = TokenBucket(
            rate_bytes_per_sec=10000.0,
            bucket_size_bytes=10000.0
        )
        
        for _ in range(10):
            bucket.consume(10)
        
        stats = bucket.get_stats()
        assert stats['packets'] == 10
    
    def test_stats_throttled_count(self):
        """throttled should count denied consumes."""
        bucket = TokenBucket(
            rate_bytes_per_sec=100.0,
            bucket_size_bytes=100.0
        )
        
        bucket.consume(100)  # Allowed
        bucket.consume(50)   # Throttled
        bucket.consume(50)   # Throttled
        
        stats = bucket.get_stats()
        assert stats['throttled'] == 2
    
    def test_stats_mb_conversion(self):
        """total_mb should be correct conversion."""
        bucket = TokenBucket(
            rate_bytes_per_sec=10000000.0,
            bucket_size_bytes=10000000.0
        )
        
        bucket.consume(1024 * 1024)  # 1 MB
        
        stats = bucket.get_stats()
        assert stats['total_mb'] == pytest.approx(1.0, rel=0.01)
    
    def test_stats_reset(self):
        """reset_stats should clear counters."""
        bucket = TokenBucket(
            rate_bytes_per_sec=10000.0,
            bucket_size_bytes=10000.0
        )
        
        bucket.consume(1000)
        bucket.reset_stats()
        
        stats = bucket.get_stats()
        assert stats['total_bytes'] == 0
        assert stats['packets'] == 0


class TestTokenBucketThreadSafety:
    """Thread safety tests."""
    
    def test_concurrent_consume(self):
        """Concurrent consume should be thread-safe."""
        bucket = TokenBucket(
            rate_bytes_per_sec=1000000.0,
            bucket_size_bytes=1000000.0
        )
        
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    bucket.consume(10)
            except Exception as e:
                errors.append(e)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(10)]
            for f in futures:
                f.result()
        
        assert len(errors) == 0
        
        stats = bucket.get_stats()
        assert stats['packets'] == 1000  # 10 threads * 100 each
    
    def test_concurrent_stats(self):
        """Concurrent stats access should be thread-safe."""
        bucket = TokenBucket(
            rate_bytes_per_sec=1000000.0,
            bucket_size_bytes=1000000.0
        )
        
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    bucket.consume(10)
                    bucket.get_stats()
            except Exception as e:
                errors.append(e)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(10)]
            for f in futures:
                f.result()
        
        assert len(errors) == 0


class TestWaitTimeCalculation:
    """Wait time calculation tests."""
    
    def test_wait_time_calculation(self):
        """Wait time should be based on needed tokens and rate."""
        bucket = TokenBucket(
            rate_bytes_per_sec=100.0,  # 100 bytes/sec
            bucket_size_bytes=100.0
        )
        
        bucket.consume(100)  # Empty bucket
        
        _, wait_time = bucket.consume(50)  # Need 50 bytes
        
        # Should wait ~0.5 seconds (50 bytes / 100 bytes/sec)
        assert wait_time == pytest.approx(0.5, rel=0.1)
