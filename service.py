"""
NetShield Minimal Admin Service
===============================
Runs with elevated privileges — MINIMAL code surface.

Security Principle: Least Privilege
    This service ONLY handles:
    1. WinDivert packet interception
    2. IPC communication with worker
    3. Throttle/drop decisions (from worker commands)
    
    NO ML, NO OSINT, NO Complex Logic here!

Run with: python -m netshield.service
Requires: Administrator privileges
"""

import sys
import time
import signal
import logging
import ctypes
from typing import Optional, Set
from datetime import datetime
from threading import Lock

from .ipc import (
    IPCServer, PacketData, Command, CommandType, StatsResponse,
    WIN32_AVAILABLE
)
from .shield.token_bucket import TokenBucket
from .config import NetShieldConfig, load_config, MODE_VRCHAT, MODE_UNIVERSAL

logger = logging.getLogger(__name__)

# Check for pydivert
try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    logger.error("pydivert not installed")


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


class MinimalService:
    """
    Minimal admin service — only WinDivert + IPC.
    
    Attack Surface Minimization:
        - No external network calls
        - No file I/O except config
        - No dynamic code execution
        - Validated IPC commands only
    
    Allowed Operations:
        INTERCEPT_PACKET — capture from network
        SEND_PACKET — forward to destination
        THROTTLE_IP — add to drop list
        UNTHROTTLE_IP — remove from drop list  
        GET_STATS — return statistics
        SHUTDOWN — graceful exit
    """
    
    # Performance tuning
    STATS_UPDATE_INTERVAL = 1.0
    
    def __init__(self, config: NetShieldConfig):
        self.config = config
        self.running = False
        self.start_time: Optional[float] = None
        
        # Rate limiting (token bucket)
        rate_bytes = config.max_bandwidth_mbps * 1024 * 1024
        bucket_bytes = config.burst_size_mb * 1024 * 1024
        self.bucket = TokenBucket(rate_bytes, bucket_bytes)
        
        # Throttled IPs (from worker commands)
        self.throttled_ips: Set[str] = set()
        self.throttle_lock = Lock()
        
        # Statistics
        self.stats_lock = Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.throttled_count = 0
        
        # IPC
        self.ipc = IPCServer(on_command=self._handle_command)
    
    def _build_filter(self) -> str:
        """Build WinDivert filter based on mode."""
        if self.config.mode == MODE_VRCHAT:
            ports = [
                "(udp.SrcPort == 5055 or udp.SrcPort == 5056 or udp.SrcPort == 5058)",
                "(udp.SrcPort >= 27000 and udp.SrcPort <= 27100)",
            ]
            return f"inbound and udp and ({' or '.join(ports)})"
        
        elif self.config.mode == MODE_UNIVERSAL:
            return "inbound and (tcp or udp)"
        
        return "inbound and udp"
    
    def _handle_command(self, cmd: Command):
        """
        Handle validated command from worker.
        
        Security: Only whitelisted commands reach here.
        """
        try:
            cmd_type = CommandType(cmd.type)
        except ValueError:
            logger.warning(f"Unknown command: {cmd.type}")
            return
        
        if cmd_type == CommandType.THROTTLE_IP:
            if cmd.target_ip:
                with self.throttle_lock:
                    self.throttled_ips.add(cmd.target_ip)
                logger.info(f"Throttling IP: {cmd.target_ip}")
        
        elif cmd_type == CommandType.UNTHROTTLE_IP:
            if cmd.target_ip:
                with self.throttle_lock:
                    self.throttled_ips.discard(cmd.target_ip)
                logger.info(f"Unthrottling IP: {cmd.target_ip}")
        
        elif cmd_type == CommandType.SHUTDOWN:
            logger.info("Shutdown command received")
            self.running = False
        
        elif cmd_type == CommandType.GET_STATS:
            # Stats will be sent via separate mechanism
            pass
    
    def run(self):
        """
        Main service loop — HOT PATH.
        
        Performance Critical:
            - No allocations in loop
            - No locks in hot path (except throttle check)
            - Minimal validation
        """
        if not is_admin():
            logger.error("Administrator privileges required!")
            print("[!] ERROR: Run as Administrator")
            sys.exit(1)
        
        if not PYDIVERT_AVAILABLE:
            logger.error("pydivert not installed")
            print("[!] ERROR: pip install pydivert")
            sys.exit(1)
        
        # Start IPC
        self.ipc.start()
        print("[*] Waiting for worker to connect...")
        
        if not self.ipc.wait_for_client(timeout_ms=30000):
            logger.error("Worker did not connect")
            print("[!] ERROR: Worker connection timeout")
            self.ipc.stop()
            sys.exit(1)
        
        print("[+] Worker connected")
        
        # Build filter
        filter_str = self._build_filter()
        self.running = True
        self.start_time = time.time()
        
        print(f"[*] Filter: {filter_str[:60]}...")
        print("[*] Service running. Press Ctrl+C to stop.")
        
        try:
            with pydivert.WinDivert(filter_str) as w:
                logger.info("WinDivert opened successfully")
                
                while self.running:
                    try:
                        packet = w.recv()
                    except OSError as e:
                        logger.error(f"Recv error: {e}")
                        continue
                    
                    if packet is None:
                        continue
                    
                    # === HOT PATH START ===
                    
                    src_ip = packet.src_addr
                    packet_size = len(packet.raw)
                    
                    # Check if IP is throttled by worker
                    with self.throttle_lock:
                        ip_throttled = src_ip in self.throttled_ips
                    
                    # Token bucket check
                    allowed, _ = self.bucket.consume(packet_size)
                    
                    # Decision: drop or forward
                    should_drop = ip_throttled or not allowed
                    
                    # Update stats
                    with self.stats_lock:
                        self.total_packets += 1
                        self.total_bytes += packet_size
                        if should_drop:
                            self.throttled_count += 1
                    
                    if should_drop:
                        # DROP — don't call w.send()
                        pass
                    else:
                        # FORWARD
                        w.send(packet)
                        
                        # Send packet info to worker for analysis
                        # (only for non-dropped packets to reduce IPC load)
                        packet_data = PacketData(
                            src_ip=src_ip,
                            dst_ip=packet.dst_addr,
                            src_port=packet.src_port or 0,
                            dst_port=packet.dst_port or 0,
                            protocol="udp" if packet.udp else "tcp",
                            size=packet_size,
                            timestamp=time.time(),
                        )
                        self.ipc.send_packet(packet_data)
                    
                    # === HOT PATH END ===
        
        except PermissionError:
            logger.error("Permission denied — need admin")
            print("[!] ERROR: Administrator privileges required")
            raise
        
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        
        except Exception as e:
            logger.exception(f"Service error: {e}")
            raise
        
        finally:
            self._shutdown()
    
    def _shutdown(self):
        """Graceful shutdown."""
        self.running = False
        self.ipc.stop()
        
        # Print final stats
        uptime = time.time() - (self.start_time or time.time())
        print(f"\n[*] Session Stats:")
        print(f"    Uptime: {uptime:.1f}s")
        print(f"    Packets: {self.total_packets:,}")
        print(f"    Bytes: {self.total_bytes / 1024 / 1024:.2f} MB")
        print(f"    Throttled: {self.throttled_count:,}")
        print(f"    Blocked IPs: {len(self.throttled_ips)}")
        
        logger.info("Service shutdown complete")
    
    def get_stats(self) -> StatsResponse:
        """Get current statistics."""
        with self.stats_lock:
            return StatsResponse(
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                throttled_packets=self.throttled_count,
                throttled_ips=list(self.throttled_ips),
                uptime_seconds=time.time() - (self.start_time or time.time())
            )


def main():
    """Service entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog='netshield-service',
        description='NetShield Minimal Admin Service'
    )
    parser.add_argument('--config', '-c', type=str, help='Config file path')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [SERVICE] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Load config
    if args.config:
        from pathlib import Path
        config = load_config(Path(args.config))
    else:
        config = NetShieldConfig()
    
    print("=" * 50)
    print("  NetShield Admin Service")
    print("  Security: Minimal Attack Surface")
    print("=" * 50)
    print(f"  Mode: {config.mode}")
    print(f"  Limit: {config.max_bandwidth_mbps} MB/s")
    print("=" * 50)
    
    # Signal handler
    service = MinimalService(config)
    
    def signal_handler(sig, frame):
        print("\n[*] Signal received, stopping...")
        service.running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run
    service.run()


if __name__ == "__main__":
    main()
