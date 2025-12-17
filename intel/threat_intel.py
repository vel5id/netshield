"""
Threat Intelligence Module
==========================
WHOIS lookups with LRU cache and rate limiting.

Security Fixes:
  - #1: Thread-safe queue (queue.Queue)
  - #2: LRU cache with max size and TTL
  - #7: Rate limiting on WHOIS requests
  - #8: Specific exception handling
"""

import time
import ipaddress
import logging
from queue import Queue, Empty
from threading import Thread, Lock, RLock
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from collections import OrderedDict

if TYPE_CHECKING:
    from ..config import NetShieldConfig

from ..models import IPProfile
from .scoring import ThreatScorer

logger = logging.getLogger(__name__)

# Optional WHOIS support
try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError, HTTPLookupError, WhoisLookupError
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    logger.warning("ipwhois not installed. WHOIS functions disabled.")


class RateLimiter:
    """
    Token bucket rate limiter for WHOIS requests.
    
    Security Fix #7: Prevents flooding WHOIS servers.
    """
    
    def __init__(self, rate_per_sec: float):
        self.rate = rate_per_sec
        self.tokens = rate_per_sec
        self.last_update = time.monotonic()
        self.lock = Lock()
    
    def acquire(self, timeout: float = 1.0) -> bool:
        """Try to acquire a token. Returns True if allowed."""
        deadline = time.monotonic() + timeout
        
        while time.monotonic() < deadline:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                
                self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
            
            time.sleep(0.05)
        
        return False


class LRUCache:
    """
    Thread-safe LRU cache with max size and TTL.
    
    Security Fix #2: Prevents memory exhaustion DoS.
    """
    
    def __init__(self, max_size: int = 50000, ttl_hours: int = 24):
        self.max_size = max_size
        self.ttl_seconds = ttl_hours * 3600
        self._cache: OrderedDict[str, IPProfile] = OrderedDict()
        self._lock = RLock()
    
    def get(self, key: str) -> Optional[IPProfile]:
        """Get item, updating access order."""
        with self._lock:
            if key not in self._cache:
                return None
            
            profile = self._cache[key]
            
            # Check TTL
            now = time.monotonic()
            if now - profile.last_access > self.ttl_seconds:
                del self._cache[key]
                return None
            
            # Move to end (most recent)
            self._cache.move_to_end(key)
            profile.last_access = now
            
            return profile
    
    def put(self, key: str, value: IPProfile):
        """Add item, evicting LRU if at capacity."""
        with self._lock:
            value.last_access = time.monotonic()
            
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = value
            else:
                # Evict LRU if at capacity
                while len(self._cache) >= self.max_size:
                    self._cache.popitem(last=False)
                
                self._cache[key] = value
    
    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._cache
    
    def values(self) -> list[IPProfile]:
        """Return all values (snapshot)."""
        with self._lock:
            return list(self._cache.values())
    
    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


class ThreatIntel:
    """
    Threat Intelligence engine with WHOIS lookup.
    
    Security Fixes Applied:
      - #1: Uses queue.Queue (thread-safe)
      - #2: LRU cache with eviction
      - #7: Rate-limited WHOIS lookups
      - #8: Specific exception handling
    """
    
    def __init__(self, config: "NetShieldConfig"):
        self.config = config
        self.scorer = ThreatScorer(config)
        
        # Fix #2: LRU cache instead of unbounded dict
        self.cache = LRUCache(
            max_size=config.cache_max_size,
            ttl_hours=config.cache_ttl_hours
        )
        
        # Fix #1: Thread-safe Queue instead of deque
        self.lookup_queue: Queue[str] = Queue(maxsize=1000)
        
        # Fix #7: Rate limiter for WHOIS
        self.rate_limiter = RateLimiter(config.whois_rate_limit)
        
        self.running = True
        
        # Start worker thread
        if config.whois_enabled and IPWHOIS_AVAILABLE:
            self.worker_thread = Thread(
                target=self._lookup_worker, 
                daemon=True,
                name="ThreatIntel-WHOIS"
            )
            self.worker_thread.start()
        else:
            self.worker_thread = None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private or invalid."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return True
    
    def _lookup_worker(self):
        """
        Background worker for WHOIS lookups.
        
        Security Fix #1: Uses Queue.get() which is thread-safe.
        Security Fix #7: Rate-limited requests.
        Security Fix #8: Specific exceptions only.
        """
        while self.running:
            try:
                # Fix #1: Thread-safe blocking get with timeout
                ip = self.lookup_queue.get(timeout=0.5)
            except Empty:
                continue
            
            # Fix #7: Rate limit WHOIS requests
            if not self.rate_limiter.acquire(timeout=2.0):
                logger.warning(f"WHOIS rate limit exceeded, skipping {ip}")
                continue
            
            self._do_whois_lookup(ip)
    
    def _do_whois_lookup(self, ip: str):
        """
        Perform WHOIS lookup with proper error handling.
        
        Security Fix #8: Catch only specific exceptions.
        """
        profile = self.cache.get(ip)
        if profile is None:
            return
        
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            
            # Extract data with sanitization (handled by model)
            country = res.get('asn_country_code', 'Unknown')
            asn = str(res.get('asn', 'Unknown'))
            asn_desc = res.get('asn_description', 'Unknown')
            
            network = res.get('network', {})
            net_name = network.get('name', 'Unknown')
            net_cidr = network.get('cidr', 'Unknown')
            
            # Find abuse contact
            abuse = 'Unknown'
            entities = res.get('entities', [])
            for entity in entities:
                if isinstance(entity, str) and 'abuse' in entity.lower():
                    abuse = entity
                    break
            
            # Update profile (sanitization in model)
            profile.update_whois(country, asn, asn_desc, net_name, net_cidr, abuse)
            
            # Recalculate threat score
            self.scorer.update_profile_score(profile)
            
            logger.debug(f"WHOIS lookup complete for {ip}: {country}")
            
        except IPDefinedError:
            # Private/reserved IP - expected
            profile.country = "Reserved"
        except HTTPLookupError as e:
            # Network error - log and continue
            logger.warning(f"WHOIS HTTP error for {ip}: {e}")
            profile.country = "Lookup Failed"
        except WhoisLookupError as e:
            # WHOIS-specific error
            logger.warning(f"WHOIS lookup error for {ip}: {e}")
            profile.country = "Lookup Failed"
        except (ValueError, KeyError, TypeError) as e:
            # Data parsing errors
            logger.warning(f"WHOIS parse error for {ip}: {e}")
        # Fix #8: DO NOT catch Exception - let unexpected errors propagate
    
    def get_or_create_profile(self, ip: str) -> Optional[IPProfile]:
        """Get existing profile or create new one."""
        if self._is_private_ip(ip):
            return None
        
        # Check cache first
        profile = self.cache.get(ip)
        if profile is not None:
            profile.last_seen = datetime.now().isoformat()
            return profile
        
        # Create new profile
        now = datetime.now().isoformat()
        profile = IPProfile(
            ip=ip,
            first_seen=now,
            last_seen=now
        )
        
        # Add to cache
        self.cache.put(ip, profile)
        
        # Queue for WHOIS lookup (non-blocking)
        try:
            self.lookup_queue.put_nowait(ip)
        except Exception:
            pass  # Queue full, skip WHOIS
        
        return profile
    
    def update_stats(self, ip: str, packet_bytes: int, 
                     was_throttled: bool, speed_mbps: float):
        """Update traffic statistics for IP."""
        profile = self.cache.get(ip)
        if profile is None:
            return
        
        profile.total_bytes += packet_bytes
        profile.total_packets += 1
        if was_throttled:
            profile.throttled_packets += 1
        
        if speed_mbps > profile.max_speed_mbps:
            profile.max_speed_mbps = speed_mbps
            # Recalculate score on speed change
            self.scorer.update_profile_score(profile)
    
    def get_watchlist(self, threshold: int = 80) -> list[IPProfile]:
        """Get all IPs with threat score >= threshold."""
        return [
            p for p in self.cache.values() 
            if p.threat_score >= threshold
        ]
    
    def stop(self):
        """Stop background worker."""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
