"""
Shield Engine v2 — High Performance
====================================
Main protection engine with WinDivert packet interception.

CRITICAL PERFORMANCE FIXES:
  - NO SLEEP in hot path (DROP instead of DELAY)
  - Sampled logging (every N packets)
  - Minimal work in packet processing loop
  - Protocol separation (UDP/TCP tracked separately)

Security Fixes:
  - #6: Timing jitter NOT used (replaced with DROP)
  - #12: Graceful degradation and state recovery
"""

import time
import logging
from datetime import datetime
from threading import Lock
from typing import TYPE_CHECKING, Optional
from collections import defaultdict
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ..config import NetShieldConfig
    from ..loggers import EventLogger

from ..models import ThreatEvent
from ..intel import ThreatIntel
from .token_bucket import TokenBucket
from .bandwidth import BandwidthMonitor
from ..config import MODE_VRCHAT, MODE_UNIVERSAL

logger = logging.getLogger(__name__)

# Optional pydivert
try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    logger.error("pydivert not installed. Shield engine disabled.")


# ============================================================================
# PROTOCOL TRACKING
# ============================================================================

@dataclass
class ProtocolStats:
    """Per-protocol statistics."""
    packets: int = 0
    bytes: int = 0
    dropped: int = 0
    dropped_bytes: int = 0


@dataclass
class IPStats:
    """Lightweight per-IP stats for hot path (no WHOIS)."""
    packets: int = 0
    bytes: int = 0
    dropped: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    protocol: str = "unknown"  # Last seen protocol


# ============================================================================
# SHIELD ENGINE v2
# ============================================================================

class ShieldEngine:
    """
    High-performance protection engine.
    
    CRITICAL: This version uses DROP strategy instead of SLEEP.
    When bucket is empty, packets are DROPPED, not delayed.
    This prevents kernel buffer overflow during floods.
    
    Changes from v1:
      - No time.sleep() in hot path
      - Sampled logging (every LOG_SAMPLE_RATE packets)
      - Protocol tracking (UDP/TCP separately)
      - Lightweight IP stats (WHOIS moved to background)
    """
    
    # Performance constants
    LOG_SAMPLE_RATE = 100  # Log every Nth packet during flood
    STATS_UPDATE_INTERVAL = 0.5  # Seconds between UI updates
    WATCHLIST_SAVE_INTERVAL = 30  # Seconds between watchlist saves
    
    def __init__(self, config: "NetShieldConfig", event_logger: "EventLogger"):
        if not PYDIVERT_AVAILABLE:
            raise ImportError(
                "pydivert is required for ShieldEngine. "
                "Install with: pip install pydivert"
            )
        
        self.config = config
        self.event_logger = event_logger
        
        # Rate limiting
        rate_bytes = config.max_bandwidth_mbps * 1024 * 1024
        bucket_bytes = config.burst_size_mb * 1024 * 1024
        self.bucket = TokenBucket(rate_bytes, bucket_bytes)
        
        # Bandwidth monitoring
        self.monitor = BandwidthMonitor()
        
        # Intel (WHOIS runs in background thread)
        self.intel = ThreatIntel(config)
        
        # Protocol tracking
        self.proto_stats: dict[str, ProtocolStats] = defaultdict(ProtocolStats)
        self.proto_lock = Lock()
        
        # Lightweight IP tracking (no WHOIS in hot path)
        self.ip_stats: dict[str, IPStats] = {}
        self.ip_lock = Lock()
        
        # State
        self.running = False
        self.start_time: Optional[str] = None
        self.packet_counter = 0
        
        # Flood detection
        self.flood_mode = False
        self.flood_threshold_mbps = config.max_bandwidth_mbps * 0.8
    
    def build_filter(self) -> str:
        """Build WinDivert filter based on mode."""
        if self.config.mode == MODE_VRCHAT:
            # VRChat: Both UDP and TCP for tracking which kills the game
            port_conditions = [
                # UDP Photon
                "(udp and (udp.SrcPort == 5055 or udp.SrcPort == 5056 or udp.SrcPort == 5058))",
                # UDP Steam
                "(udp and udp.SrcPort >= 27000 and udp.SrcPort <= 27100)",
                # TCP (for tracking, не для лимита)
                "(tcp and (tcp.SrcPort == 80 or tcp.SrcPort == 443))"
            ]
            return f"inbound and ({' or '.join(port_conditions)})"
        
        elif self.config.mode == MODE_UNIVERSAL:
            return "inbound and (tcp or udp)"
        
        else:
            return "inbound and udp"
    
    def run(self, stats_callback=None, stop_event=None):
        """
        Main protection loop.
        
        PERFORMANCE CRITICAL:
          - No sleep in hot path
          - Minimal object creation
          - Sampled logging
        """
        filter_str = self.build_filter()
        self.running = True
        self.start_time = datetime.now().isoformat()
        
        last_stats_time = time.perf_counter()
        last_watchlist_save = time.perf_counter()
        last_flood_check = time.perf_counter()
        
        error_count = 0
        
        try:
            with pydivert.WinDivert(filter_str) as w:
                logger.info(f"Shield v2 started: {filter_str[:80]}...")
                
                while self.running:
                    if stop_event and stop_event.is_set():
                        break
                    
                    try:
                        packet = w.recv()
                        error_count = 0
                    except OSError as e:
                        error_count += 1
                        if error_count >= 10:
                            logger.error(f"Fatal error: {e}")
                            break
                        continue
                    
                    if packet is None:
                        continue
                    
                    # === HOT PATH START ===
                    # Minimal work here!
                    
                    packet_size = len(packet.raw)
                    should_drop = self._process_packet_fast(packet, packet_size)
                    
                    if should_drop:
                        # DROP - don't call w.send()
                        # This is safe: WinDivert drops packet if not re-injected
                        pass
                    else:
                        w.send(packet)
                    
                    # === HOT PATH END ===
                    
                    # Periodic tasks (only check time, not every packet)
                    self.packet_counter += 1
                    if self.packet_counter % 100 == 0:
                        now = time.perf_counter()
                        
                        # Stats callback
                        if stats_callback and now - last_stats_time > self.STATS_UPDATE_INTERVAL:
                            stats_callback(self._get_stats())
                            last_stats_time = now
                        
                        # Flood mode check
                        if now - last_flood_check > 1.0:
                            speed = self.monitor.get_speed_mbps()
                            self.flood_mode = speed > self.flood_threshold_mbps
                            last_flood_check = now
                        
                        # Watchlist save
                        if now - last_watchlist_save > self.WATCHLIST_SAVE_INTERVAL:
                            self._save_watchlist_async()
                            last_watchlist_save = now
        
        except PermissionError:
            logger.error("Administrator privileges required")
            raise
        except Exception as e:
            logger.exception(f"Engine error: {e}")
            raise
        finally:
            self._graceful_shutdown()
    
    def _process_packet_fast(self, packet, packet_size: int) -> bool:
        """
        Fast packet processing - HOT PATH.
        
        Returns:
            True = DROP packet, False = ALLOW packet
        """
        # Get protocol (minimal parsing)
        is_udp = hasattr(packet, 'udp') and packet.udp
        proto = "udp" if is_udp else "tcp"
        src_ip = packet.src_addr
        src_port = packet.src_port if hasattr(packet, 'src_port') else 0
        
        # Update bandwidth monitor
        self.monitor.add_sample(packet_size)
        
        # Token bucket check
        allowed, _ = self.bucket.consume(packet_size)
        
        # Update protocol stats (with lock, but fast)
        with self.proto_lock:
            ps = self.proto_stats[proto]
            ps.packets += 1
            ps.bytes += packet_size
            if not allowed:
                ps.dropped += 1
                ps.dropped_bytes += packet_size
        
        # Update IP stats (lightweight)
        now = time.perf_counter()
        with self.ip_lock:
            if src_ip not in self.ip_stats:
                self.ip_stats[src_ip] = IPStats(
                    first_seen=now,
                    protocol=proto
                )
            ips = self.ip_stats[src_ip]
            ips.packets += 1
            ips.bytes += packet_size
            ips.last_seen = now
            ips.protocol = proto
            if not allowed:
                ips.dropped += 1
        
        # Sampled logging (not every packet!)
        if not allowed and self.packet_counter % self.LOG_SAMPLE_RATE == 0:
            self._queue_log_event(src_ip, proto, src_port, packet_size)
        
        # Queue for WHOIS (background, not blocking)
        if self.packet_counter % 500 == 0:
            self.intel.get_or_create_profile(src_ip)
        
        # Return True to DROP if not allowed
        return not allowed
    
    def _queue_log_event(self, ip: str, proto: str, port: int, size: int):
        """Queue log event (non-blocking, sampled)."""
        # Use the async logger
        event = ThreatEvent(
            timestamp=datetime.now().isoformat(),
            event_type="throttle",
            ip=ip,
            speed_mbps=self.monitor.get_speed_mbps(),
            threat_score=0,  # Not calculated in hot path
            details={
                "protocol": proto,
                "port": port,
                "size": size,
                "flood_mode": self.flood_mode,
            }
        )
        self.event_logger.log_event(event)
    
    def _get_stats(self) -> dict:
        """Get current statistics for UI."""
        bucket_stats = self.bucket.get_stats()
        
        with self.proto_lock:
            udp_stats = self.proto_stats.get("udp", ProtocolStats())
            tcp_stats = self.proto_stats.get("tcp", ProtocolStats())
        
        return {
            'speed_mbps': self.monitor.get_speed_mbps(),
            'max_bandwidth': self.config.max_bandwidth_mbps,
            'total_mb': bucket_stats['total_mb'],
            'packets': bucket_stats['packets'],
            'dropped': bucket_stats['throttled'],
            'dropped_mb': bucket_stats['throttled_mb'],
            'unique_ips': len(self.ip_stats),
            'flood_mode': self.flood_mode,
            # Protocol breakdown
            'udp_packets': udp_stats.packets,
            'udp_dropped': udp_stats.dropped,
            'tcp_packets': tcp_stats.packets,
            'tcp_dropped': tcp_stats.dropped,
        }
    
    def _save_watchlist_async(self):
        """Save watchlist (called periodically)."""
        # Get high-traffic IPs from our lightweight stats
        with self.ip_lock:
            high_traffic = [
                (ip, stats) for ip, stats in self.ip_stats.items()
                if stats.dropped > 10 or stats.bytes > 10_000_000
            ]
        
        # Enrich with WHOIS data and save
        watchlist = []
        for ip, stats in high_traffic[:50]:  # Top 50
            profile = self.intel.get_or_create_profile(ip)
            if profile:
                watchlist.append(profile)
        
        if watchlist:
            self.event_logger.save_watchlist(watchlist)
    
    def _graceful_shutdown(self):
        """Clean shutdown."""
        logger.info("Shutting down Shield Engine v2...")
        
        self.intel.stop()
        self._save_watchlist_async()
        
        # Log final protocol stats
        with self.proto_lock:
            for proto, stats in self.proto_stats.items():
                logger.info(
                    f"{proto.upper()}: {stats.packets} pkts, "
                    f"{stats.dropped} dropped ({stats.dropped_bytes/1024/1024:.1f} MB)"
                )
    
    def stop(self):
        """Signal engine to stop."""
        self.running = False
    
    def get_session_summary(self) -> dict:
        """Get final session summary."""
        stats = self._get_stats()
        
        with self.proto_lock:
            proto_summary = {
                proto: {
                    'packets': ps.packets,
                    'bytes': ps.bytes,
                    'dropped': ps.dropped,
                    'dropped_bytes': ps.dropped_bytes,
                }
                for proto, ps in self.proto_stats.items()
            }
        
        # Top offenders
        with self.ip_lock:
            top_dropped = sorted(
                self.ip_stats.items(),
                key=lambda x: x[1].dropped,
                reverse=True
            )[:10]
        
        return {
            'start_time': self.start_time,
            'stats': stats,
            'protocols': proto_summary,
            'top_offenders': [
                {
                    'ip': ip,
                    'packets': s.packets,
                    'dropped': s.dropped,
                    'protocol': s.protocol,
                }
                for ip, s in top_dropped
            ]
        }
