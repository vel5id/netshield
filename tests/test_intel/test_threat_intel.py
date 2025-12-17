"""
Threat Intelligence Tests
=========================
Tests for WHOIS, caching, and rate limiting.

Security Fixes Tested:
  - #1: Thread-safe queue
  - #2: LRU cache with eviction
  - #7: WHOIS rate limiting
  - #8: Specific exception handling
"""

import pytest
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from netshield.config import NetShieldConfig
from netshield.intel.threat_intel import (
    ThreatIntel,
    LRUCache,
    RateLimiter,
)
from netshield.models import IPProfile


class TestLRUCache:
    """Tests for LRU cache (Fix #2)."""
    
    def test_lru_cache_basic_get_put(self):
        """Basic get/put should work."""
        cache = LRUCache(max_size=10)
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01"
        )
        
        cache.put("8.8.8.8", profile)
        result = cache.get("8.8.8.8")
        
        assert result is not None
        assert result.ip == "8.8.8.8"
    
    def test_lru_cache_eviction_at_capacity(self):
        """Oldest items should be evicted when at capacity."""
        cache = LRUCache(max_size=3)
        
        # Add 3 items
        for i in range(3):
            profile = IPProfile(
                ip=f"1.1.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            cache.put(f"1.1.1.{i}", profile)
            time.sleep(0.01)  # Ensure ordering
        
        # Add 4th item
        profile = IPProfile(
            ip="1.1.1.99",
            first_seen="2024-01-01",
            last_seen="2024-01-01"
        )
        cache.put("1.1.1.99", profile)
        
        # First item should be evicted
        assert cache.get("1.1.1.0") is None
        assert cache.get("1.1.1.99") is not None
        assert len(cache) == 3
    
    def test_lru_cache_respects_max_size(self):
        """Cache should never exceed max_size."""
        cache = LRUCache(max_size=5)
        
        for i in range(100):
            profile = IPProfile(
                ip=f"1.1.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            cache.put(f"1.1.1.{i}", profile)
        
        assert len(cache) <= 5
    
    def test_lru_cache_access_updates_order(self):
        """Accessing an item should move it to end (most recent)."""
        cache = LRUCache(max_size=3)
        
        for i in range(3):
            profile = IPProfile(
                ip=f"1.1.1.{i}",
                first_seen="2024-01-01",
                last_seen="2024-01-01"
            )
            cache.put(f"1.1.1.{i}", profile)
        
        # Access first item, making it most recent
        cache.get("1.1.1.0")
        
        # Add new item
        profile = IPProfile(
            ip="1.1.1.99",
            first_seen="2024-01-01",
            last_seen="2024-01-01"
        )
        cache.put("1.1.1.99", profile)
        
        # Second item (1.1.1.1) should be evicted, not first
        assert cache.get("1.1.1.0") is not None
        assert cache.get("1.1.1.1") is None
    
    def test_lru_cache_ttl_expiration(self):
        """Items should expire after TTL."""
        cache = LRUCache(max_size=10, ttl_hours=0)  # 0 hours = immediate expiry
        
        profile = IPProfile(
            ip="8.8.8.8",
            first_seen="2024-01-01",
            last_seen="2024-01-01"
        )
        cache.put("8.8.8.8", profile)
        
        # Wait a tiny bit
        time.sleep(0.01)
        
        # Should be expired
        result = cache.get("8.8.8.8")
        assert result is None
    
    def test_lru_cache_thread_safety(self):
        """Cache should be thread-safe."""
        cache = LRUCache(max_size=100)
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(50):
                    key = f"{thread_id}.{i}"
                    profile = IPProfile(
                        ip=key,
                        first_seen="2024-01-01",
                        last_seen="2024-01-01"
                    )
                    cache.put(key, profile)
                    cache.get(key)
            except Exception as e:
                errors.append(e)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for f in futures:
                f.result()
        
        assert len(errors) == 0


class TestRateLimiter:
    """Tests for WHOIS rate limiter (Fix #7)."""
    
    def test_rate_limiter_allows_initial(self):
        """First requests should be allowed."""
        limiter = RateLimiter(rate_per_sec=10.0)
        
        assert limiter.acquire(timeout=0.1) is True
        assert limiter.acquire(timeout=0.1) is True
    
    def test_rate_limiter_blocks_when_exceeded(self):
        """Should block when rate exceeded."""
        limiter = RateLimiter(rate_per_sec=2.0)
        
        # Exhaust tokens
        limiter.acquire(timeout=0.1)
        limiter.acquire(timeout=0.1)
        
        # Next should block
        start = time.time()
        result = limiter.acquire(timeout=0.3)
        elapsed = time.time() - start
        
        # Should have waited some time
        assert elapsed >= 0.1
    
    def test_rate_limiter_refills(self):
        """Tokens should refill over time."""
        limiter = RateLimiter(rate_per_sec=10.0)
        
        # Exhaust tokens
        for _ in range(10):
            limiter.acquire(timeout=0.01)
        
        # Wait for refill
        time.sleep(0.5)
        
        # Should be able to acquire again
        assert limiter.acquire(timeout=0.1) is True


class TestThreatIntel:
    """Tests for ThreatIntel class."""
    
    @pytest.fixture
    def intel(self, test_config, no_whois):
        """ThreatIntel with WHOIS disabled."""
        ti = ThreatIntel(test_config)
        yield ti
        ti.stop()
    
    def test_private_ip_skipped(self, intel):
        """Private IPs should return None."""
        assert intel.get_or_create_profile("192.168.1.1") is None
        assert intel.get_or_create_profile("10.0.0.1") is None
        assert intel.get_or_create_profile("127.0.0.1") is None
    
    def test_public_ip_creates_profile(self, intel):
        """Public IPs should create profile."""
        profile = intel.get_or_create_profile("8.8.8.8")
        assert profile is not None
        assert profile.ip == "8.8.8.8"
    
    def test_profile_caching(self, intel):
        """Same IP should return same profile."""
        profile1 = intel.get_or_create_profile("8.8.8.8")
        profile2 = intel.get_or_create_profile("8.8.8.8")
        
        assert profile1 is profile2
    
    def test_update_stats(self, intel):
        """update_stats should update profile."""
        intel.get_or_create_profile("8.8.8.8")
        intel.update_stats("8.8.8.8", 1000, True, 25.0)
        
        profile = intel.cache.get("8.8.8.8")
        assert profile.total_bytes == 1000
        assert profile.total_packets == 1
        assert profile.throttled_packets == 1
        assert profile.max_speed_mbps == 25.0
    
    def test_get_watchlist(self, intel):
        """get_watchlist should return high-score profiles."""
        profile = intel.get_or_create_profile("1.2.3.4")
        profile.threat_score = 90
        
        watchlist = intel.get_watchlist(threshold=80)
        assert len(watchlist) == 1
        assert watchlist[0].ip == "1.2.3.4"
    
    def test_get_watchlist_threshold(self, intel):
        """Profiles below threshold should not be in watchlist."""
        profile = intel.get_or_create_profile("8.8.8.8")
        profile.threat_score = 50
        
        watchlist = intel.get_watchlist(threshold=80)
        assert len(watchlist) == 0
    
    def test_cache_size_limit(self, test_config, no_whois):
        """Cache should respect size limit."""
        config = NetShieldConfig(cache_max_size=5, cache_ttl_hours=24)
        intel = ThreatIntel(config)
        
        try:
            for i in range(20):
                intel.get_or_create_profile(f"1.1.1.{i}")
            
            assert len(intel.cache) <= 5
        finally:
            intel.stop()
    
    def test_queue_thread_safety(self, test_config, no_whois):
        """Queue operations should be thread-safe (Fix #1)."""
        intel = ThreatIntel(test_config)
        errors = []
        
        def worker():
            try:
                for i in range(50):
                    intel.get_or_create_profile(f"2.2.2.{i % 256}")
            except Exception as e:
                errors.append(e)
        
        try:
            threads = [threading.Thread(target=worker) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            assert len(errors) == 0
        finally:
            intel.stop()
