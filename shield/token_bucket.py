"""
Token Bucket Rate Limiter
=========================
Classic token bucket algorithm for bandwidth limiting.
"""

import time
from threading import Lock


class TokenBucket:
    """
    Thread-safe Token Bucket rate limiter.
    
    Tokens are added at a constant rate.
    Each packet consumes tokens equal to its size.
    If insufficient tokens, packet is throttled.
    """
    
    def __init__(self, rate_bytes_per_sec: float, bucket_size_bytes: float):
        """
        Initialize token bucket.
        
        Args:
            rate_bytes_per_sec: Rate at which tokens refill (bandwidth limit)
            bucket_size_bytes: Maximum bucket capacity (burst allowance)
        """
        if rate_bytes_per_sec <= 0:
            raise ValueError("rate_bytes_per_sec must be positive")
        if bucket_size_bytes <= 0:
            raise ValueError("bucket_size_bytes must be positive")
        
        self.rate = rate_bytes_per_sec
        self.bucket_size = bucket_size_bytes
        self.tokens = bucket_size_bytes  # Start full
        self.last_update = time.perf_counter()
        self._lock = Lock()
        
        # Statistics
        self._total_bytes = 0
        self._throttled_bytes = 0
        self._packet_count = 0
        self._throttled_count = 0
    
    def consume(self, num_bytes: int) -> tuple[bool, float]:
        """
        Attempt to consume tokens for a packet.
        
        Args:
            num_bytes: Size of packet in bytes
            
        Returns:
            (allowed, wait_time): 
                - allowed: True if packet can pass immediately
                - wait_time: Seconds to wait if throttled
        """
        if num_bytes < 0:
            raise ValueError("num_bytes cannot be negative")
        
        with self._lock:
            now = time.perf_counter()
            elapsed = now - self.last_update
            self.last_update = now
            
            # Refill tokens
            self.tokens = min(
                self.bucket_size, 
                self.tokens + elapsed * self.rate
            )
            
            # Update stats
            self._packet_count += 1
            self._total_bytes += num_bytes
            
            if self.tokens >= num_bytes:
                # Sufficient tokens - allow
                self.tokens -= num_bytes
                return True, 0.0
            else:
                # Insufficient - throttle
                self._throttled_count += 1
                self._throttled_bytes += num_bytes
                
                # Calculate wait time
                needed = num_bytes - self.tokens
                wait_time = needed / self.rate
                return False, wait_time
    
    def get_stats(self) -> dict:
        """Get current statistics."""
        with self._lock:
            return {
                'total_bytes': self._total_bytes,
                'total_mb': self._total_bytes / (1024 * 1024),
                'throttled_bytes': self._throttled_bytes,
                'throttled_mb': self._throttled_bytes / (1024 * 1024),
                'packets': self._packet_count,
                'throttled': self._throttled_count,
                'current_tokens': self.tokens,
            }
    
    def reset_stats(self):
        """Reset statistics counters."""
        with self._lock:
            self._total_bytes = 0
            self._throttled_bytes = 0
            self._packet_count = 0
            self._throttled_count = 0
