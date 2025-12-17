"""
Bandwidth Monitor
=================
Real-time bandwidth measurement using sliding window.
"""

import time
from threading import Lock
from collections import deque


class BandwidthMonitor:
    """
    Thread-safe sliding window bandwidth monitor.
    Tracks throughput over a configurable time window.
    """
    
    def __init__(self, window_sec: float = 1.0):
        """
        Initialize monitor.
        
        Args:
            window_sec: Size of sliding window in seconds
        """
        if window_sec <= 0:
            raise ValueError("window_sec must be positive")
        
        self.window = window_sec
        self._samples: deque = deque()
        self._lock = Lock()
    
    def add_sample(self, num_bytes: int):
        """
        Add a traffic sample.
        
        Args:
            num_bytes: Bytes observed
        """
        if num_bytes < 0:
            return
        
        now = time.perf_counter()
        
        with self._lock:
            self._samples.append((now, num_bytes))
            self._cleanup(now)
    
    def _cleanup(self, now: float):
        """Remove samples outside the window."""
        cutoff = now - self.window
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()
    
    def get_speed_mbps(self) -> float:
        """
        Calculate current speed in MB/s.
        
        Returns:
            Speed in megabytes per second
        """
        now = time.perf_counter()
        
        with self._lock:
            self._cleanup(now)
            
            if not self._samples:
                return 0.0
            
            total_bytes = sum(b for _, b in self._samples)
            return total_bytes / (1024 * 1024) / self.window
    
    def get_speed_bps(self) -> float:
        """Get speed in bytes per second."""
        now = time.perf_counter()
        
        with self._lock:
            self._cleanup(now)
            
            if not self._samples:
                return 0.0
            
            total_bytes = sum(b for _, b in self._samples)
            return total_bytes / self.window
    
    def get_sample_count(self) -> int:
        """Get number of samples in window."""
        with self._lock:
            return len(self._samples)
    
    def reset(self):
        """Clear all samples."""
        with self._lock:
            self._samples.clear()
