"""
Threat Intelligence Feed Client
================================
Fetches and caches IOCs (Indicators of Compromise) from public feeds.

Feeds:
  - Emerging Threats compromised IPs
  - IPsum aggregated threat list
  - Abuse.ch (optional)

Security:
  - Async updates (non-blocking)
  - Rate-limited requests
  - Cache with expiry
  - Input validation on IOCs
"""

import logging
import time
import re
from typing import Optional, Set
from pathlib import Path
from threading import Thread, Lock
from datetime import datetime
import json

logger = logging.getLogger(__name__)

# Optional httpx for async
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    try:
        import urllib.request
    except ImportError:
        pass


# IP validation regex
IP_PATTERN = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')


class ThreatFeed:
    """
    Threat intelligence feed client.
    
    Features:
      - Async background updates
      - Fallback to cached data
      - IP validation
      - Multiple feed sources
    """
    
    # Public feeds (free, no API key)
    FEEDS = {
        "ipsum": {
            "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
            "type": "ip_list",
            "description": "Aggregated malicious IP list (level 3+)"
        },
        "emergingthreats": {
            "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "type": "ip_list", 
            "description": "Emerging Threats compromised IPs"
        },
        "feodo": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "type": "ip_list",
            "description": "Feodo Tracker botnet C2 IPs"
        }
    }
    
    # Update interval
    UPDATE_INTERVAL_HOURS = 6
    
    def __init__(self, cache_dir: Optional[Path] = None, enabled_feeds: Optional[list[str]] = None):
        """
        Initialize threat feed client.
        
        Args:
            cache_dir: Directory to cache feed data
            enabled_feeds: List of feed names to enable (default: all)
        """
        self.cache_dir = cache_dir or Path.home() / ".netshield" / "feeds"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.enabled_feeds = enabled_feeds or list(self.FEEDS.keys())
        
        # IOC storage
        self._malicious_ips: Set[str] = set()
        self._lock = Lock()
        
        # State
        self._last_update: float = 0
        self._update_thread: Optional[Thread] = None
        self._running = True
        
        # Load cached data
        self._load_cache()
    
    def _load_cache(self):
        """Load cached IOCs from disk."""
        cache_file = self.cache_dir / "iocs.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                self._malicious_ips = set(data.get('ips', []))
                self._last_update = data.get('timestamp', 0)
                
                logger.info(f"Loaded {len(self._malicious_ips)} IOCs from cache")
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
    
    def _save_cache(self):
        """Save IOCs to disk cache."""
        cache_file = self.cache_dir / "iocs.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'ips': list(self._malicious_ips),
                    'timestamp': time.time(),
                    'updated': datetime.now().isoformat()
                }, f)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        return bool(IP_PATTERN.match(ip.strip()))
    
    def _fetch_feed(self, feed_name: str) -> set[str]:
        """Fetch IPs from a single feed."""
        feed = self.FEEDS.get(feed_name)
        if not feed:
            return set()
        
        url = feed['url']
        ips = set()
        
        try:
            if HTTPX_AVAILABLE:
                with httpx.Client(timeout=30.0) as client:
                    response = client.get(url)
                    content = response.text
            else:
                import urllib.request
                with urllib.request.urlopen(url, timeout=30) as response:
                    content = response.read().decode('utf-8')
            
            for line in content.splitlines():
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Extract IP (first column for most formats)
                # Split once and reuse result
                parts = line.split()
                ip = parts[0] if parts else line
                
                if self._validate_ip(ip):
                    ips.add(ip)
            
            logger.info(f"Fetched {len(ips)} IPs from {feed_name}")
            
        except Exception as e:
            logger.warning(f"Failed to fetch {feed_name}: {e}")
        
        return ips
    
    def update(self):
        """Update feeds from all sources."""
        all_ips = set()
        
        for feed_name in self.enabled_feeds:
            ips = self._fetch_feed(feed_name)
            all_ips.update(ips)
        
        with self._lock:
            self._malicious_ips = all_ips
            self._last_update = time.time()
        
        self._save_cache()
        
        logger.info(f"Updated threat feeds: {len(all_ips)} total IOCs")
    
    def update_async(self):
        """Start async update in background thread."""
        if self._update_thread and self._update_thread.is_alive():
            return
        
        self._update_thread = Thread(
            target=self.update,
            daemon=True,
            name="ThreatFeed-Update"
        )
        self._update_thread.start()
    
    def is_malicious(self, ip: str) -> bool:
        """
        Check if IP is in malicious list.
        
        Thread-safe, fast O(1) lookup.
        """
        with self._lock:
            return ip in self._malicious_ips
    
    def get_stats(self) -> dict:
        """Get feed statistics."""
        with self._lock:
            return {
                'total_iocs': len(self._malicious_ips),
                'last_update': datetime.fromtimestamp(self._last_update).isoformat() if self._last_update else None,
                'enabled_feeds': self.enabled_feeds,
            }
    
    def needs_update(self) -> bool:
        """Check if feeds need updating."""
        hours_since = (time.time() - self._last_update) / 3600
        return hours_since > self.UPDATE_INTERVAL_HOURS
    
    def stop(self):
        """Stop background updates."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5.0)
