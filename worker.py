"""
NetShield User Worker
=====================
Runs WITHOUT admin privileges — all complex logic here.

Security Principle: Defense in Depth
    Even if this process is compromised, attacker:
    - Cannot intercept network traffic
    - Cannot modify packets
    - Cannot access privileged resources
    
Responsibilities:
    - ML-based anomaly detection
    - OSINT/Intel lookups (WHOIS, GeoIP)
    - Threat scoring
    - Logging and reporting
    - GUI communication (WebSocket)

Run with: python -m netshield.worker
Does NOT require admin privileges
"""

import sys
import time
import signal
import logging
import ctypes
from typing import Optional, Dict
from datetime import datetime
from threading import Thread, Event, Lock
from collections import defaultdict, deque
from dataclasses import dataclass

from .ipc import IPCClient, PacketData, Command, CommandType
from .config import NetShieldConfig, load_config
from .loggers import EventLogger
from .models import IPProfile, ThreatEvent

logger = logging.getLogger(__name__)

# Optional imports
try:
    from .intel import ThreatIntel
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False
    logger.warning("Intel module not available")

try:
    from .ml import AnomalyDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML module not available")


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


@dataclass
class IPTracker:
    """Lightweight IP tracking for threat analysis."""
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    throttle_count: int = 0
    threat_score: int = 0
    
    def update(self, size: int):
        self.last_seen = time.time()
        self.packet_count += 1
        self.byte_count += size


class Worker:
    """
    User-space worker for threat analysis.
    
    Receives packet metadata from admin service via IPC,
    performs analysis, and sends throttle commands back.
    
    NO network interception here — only analysis!
    """
    
    # Thresholds
    THREAT_SCORE_THRESHOLD = 70
    HIGH_RATE_THRESHOLD_MBPS = 50.0
    ANALYSIS_INTERVAL = 0.5
    INTEL_LOOKUP_INTERVAL = 5.0
    LOG_INTERVAL = 1.0
    
    def __init__(self, config: NetShieldConfig):
        # Security check: warn if running as admin
        if is_admin():
            logger.warning("Worker running with admin privileges — NOT recommended!")
            print("[!] WARNING: Worker should run without admin privileges")
        
        self.config = config
        self.running = False
        self.stop_event = Event()
        
        # IPC client
        self.ipc = IPCClient()
        
        # IP tracking
        self.ip_trackers: Dict[str, IPTracker] = {}
        
        # Intel (WHOIS, threat feeds)
        if INTEL_AVAILABLE:
            self.intel = ThreatIntel(config)
        else:
            self.intel = None
        
        # ML anomaly detector
        if ML_AVAILABLE:
            self.ml = AnomalyDetector()
        else:
            self.ml = None
        
        # Logger
        self.logger = EventLogger(config.log_dir)
        
        # Rate tracking (sliding window) - use deque for efficient cleanup
        self.rate_samples: deque = deque(maxlen=10000)
        self.rate_window = 1.0  # seconds
        self._rate_bytes_sum = 0  # Cached sum for efficiency
        self._rate_lock = Lock()  # Thread safety for rate tracking
        
        # Background threads
        self.threads: list = []
    
    def run(self):
        """
        Main worker loop.
        
        1. Connect to admin service
        2. Receive packet metadata via IPC
        3. Analyze threats
        4. Send throttle commands
        """
        print("=" * 50)
        print("  NetShield Worker")
        print("  Threat Analysis Engine")
        print("=" * 50)
        
        # Connect to service
        print("[*] Connecting to admin service...")
        if not self.ipc.connect(timeout_ms=30000):
            print("[!] ERROR: Cannot connect to admin service")
            print("[!] Make sure service.py is running as admin")
            sys.exit(1)
        
        print("[+] Connected to admin service")
        self.running = True
        
        # Start background threads
        self._start_background_tasks()
        
        print("[*] Worker running. Press Ctrl+C to stop.")
        
        try:
            self._packet_loop()
        
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        
        finally:
            self._shutdown()
    
    def _packet_loop(self):
        """Process packets from service."""
        packet_count = 0
        last_stats = time.time()
        
        while self.running and not self.stop_event.is_set():
            # Receive packet metadata
            packet = self.ipc.receive_packet()
            
            if packet is None:
                # Connection closed or error
                if not self.running:
                    break
                time.sleep(0.01)
                continue
            
            # Process packet
            self._analyze_packet(packet)
            packet_count += 1
            
            # Periodic stats
            if time.time() - last_stats > 5.0:
                rate = packet_count / (time.time() - last_stats)
                logger.info(f"Processing rate: {rate:.1f} pkt/s")
                packet_count = 0
                last_stats = time.time()
    
    def _analyze_packet(self, packet: PacketData):
        """
        Analyze packet for threats.
        
        Fast path: minimal per-packet work.
        Heavy analysis in background threads.
        """
        src_ip = packet.src_ip
        now = time.time()
        
        # Update IP tracker
        if src_ip not in self.ip_trackers:
            self.ip_trackers[src_ip] = IPTracker(
                first_seen=now,
                last_seen=now
            )
        
        tracker = self.ip_trackers[src_ip]
        tracker.update(packet.size)
        
        # Rate tracking - add sample and update cached sum (thread-safe)
        with self._rate_lock:
            self.rate_samples.append((now, packet.size))
            self._rate_bytes_sum += packet.size
        
        # Quick threat checks (fast path)
        threat_score = self._quick_threat_check(src_ip, tracker, packet)
        
        if threat_score >= self.THREAT_SCORE_THRESHOLD:
            # Send throttle command to service
            self.ipc.throttle_ip(src_ip)
            tracker.throttle_count += 1
            
            # Log event
            event = ThreatEvent(
                timestamp=datetime.now().isoformat(),
                event_type="high_score",
                ip=src_ip,
                speed_mbps=self._get_ip_rate_mbps(src_ip),
                threat_score=threat_score,
                details={
                    "packets": tracker.packet_count,
                    "bytes": tracker.byte_count
                }
            )
            self.logger.log_event(event)
    
    def _quick_threat_check(self, ip: str, tracker: IPTracker, 
                            packet: PacketData) -> int:
        """
        Quick threat assessment — runs per-packet.
        
        Returns: threat score 0-100
        """
        score = 0
        
        # High packet rate
        rate_mbps = self._get_ip_rate_mbps(ip)
        if rate_mbps > self.HIGH_RATE_THRESHOLD_MBPS:
            score += 40
        elif rate_mbps > self.HIGH_RATE_THRESHOLD_MBPS / 2:
            score += 20
        
        # Previously throttled
        if tracker.throttle_count > 0:
            score += 20
        
        # Use cached intel if available
        if self.intel and hasattr(self.intel, 'profiles'):
            profile = self.intel.profiles.get(ip)
            if profile:
                score += profile.threat_score
        
        # ML anomaly score (if trained)
        if self.ml and hasattr(self.ml, 'predict_score'):
            try:
                features = [
                    tracker.packet_count,
                    tracker.byte_count,
                    rate_mbps,
                    tracker.throttle_count
                ]
                ml_score = self.ml.predict_score(features)
                score += int(ml_score * 30)  # 0-30 from ML
            except:
                pass
        
        tracker.threat_score = min(100, score)
        return tracker.threat_score
    
    def _get_ip_rate_mbps(self, ip: str) -> float:
        """Get current rate for all traffic in MB/s."""
        now = time.time()
        cutoff = now - self.rate_window
        
        # Use the pre-computed sum and remove expired samples (thread-safe)
        with self._rate_lock:
            self._cleanup_rate_samples_unsafe(cutoff)
            return (self._rate_bytes_sum / self.rate_window) / 1024 / 1024
    
    def _cleanup_rate_samples_unsafe(self, cutoff: float = None):
        """Remove old rate samples from the deque. Must be called with _rate_lock held."""
        if cutoff is None:
            cutoff = time.time() - self.rate_window
        
        # Remove expired samples from left (oldest) side
        while self.rate_samples and self.rate_samples[0][0] < cutoff:
            _, size = self.rate_samples.popleft()
            self._rate_bytes_sum -= size
    
    def _start_background_tasks(self):
        """Start background analysis threads."""
        
        # Intel lookup thread
        if self.intel:
            t = Thread(
                target=self._intel_loop,
                daemon=True,
                name="Worker-Intel"
            )
            t.start()
            self.threads.append(t)
        
        # Periodic cleanup
        t = Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="Worker-Cleanup"
        )
        t.start()
        self.threads.append(t)
    
    def _intel_loop(self):
        """Background WHOIS/Intel lookups."""
        while self.running and not self.stop_event.is_set():
            try:
                # Get IPs needing lookup
                ips_to_check = [
                    ip for ip, tracker in self.ip_trackers.items()
                    if tracker.packet_count > 100  # Only high-traffic
                ]
                
                for ip in ips_to_check[:10]:  # Batch of 10
                    if not self.running:
                        break
                    self.intel.get_or_create_profile(ip)
                    time.sleep(0.5)  # Rate limit
                
                time.sleep(self.INTEL_LOOKUP_INTERVAL)
                
            except Exception as e:
                logger.exception(f"Intel loop error: {e}")
                time.sleep(5.0)
    
    def _cleanup_loop(self):
        """Periodic cleanup of old data."""
        while self.running and not self.stop_event.is_set():
            try:
                now = time.time()
                
                # Remove old IP trackers (> 1 hour)
                old_ips = [
                    ip for ip, tracker in self.ip_trackers.items()
                    if now - tracker.last_seen > 3600
                ]
                for ip in old_ips:
                    del self.ip_trackers[ip]
                
                if old_ips:
                    logger.info(f"Cleaned up {len(old_ips)} old IP trackers")
                
                time.sleep(300)  # Every 5 min
                
            except Exception as e:
                logger.exception(f"Cleanup error: {e}")
                time.sleep(60)
    
    def _shutdown(self):
        """Graceful shutdown."""
        self.running = False
        self.stop_event.set()
        
        # Disconnect IPC
        self.ipc.disconnect()
        
        # Stop intel
        if self.intel:
            self.intel.stop()
        
        # Stop logger
        self.logger.stop()
        
        # Print summary
        print(f"\n[*] Worker Summary:")
        print(f"    IPs analyzed: {len(self.ip_trackers)}")
        
        high_threat = sum(
            1 for t in self.ip_trackers.values()
            if t.threat_score >= self.THREAT_SCORE_THRESHOLD
        )
        print(f"    High-threat IPs: {high_threat}")
        
        logger.info("Worker shutdown complete")


def main():
    """Worker entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog='netshield-worker',
        description='NetShield Threat Analysis Worker'
    )
    parser.add_argument('--config', '-c', type=str, help='Config file path')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [WORKER] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Load config
    if args.config:
        from pathlib import Path
        config = load_config(Path(args.config))
    else:
        config = NetShieldConfig()
    
    # Signal handlers
    worker = Worker(config)
    
    def signal_handler(sig, frame):
        print("\n[*] Signal received, stopping...")
        worker.running = False
        worker.stop_event.set()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run
    worker.run()


if __name__ == "__main__":
    main()
