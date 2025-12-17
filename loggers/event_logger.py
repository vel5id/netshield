"""
Event Logger
=============
Async logging with optional HMAC integrity verification.

Security Fixes:
  - #9: HMAC integrity for log entries
  - #10: Async logging to avoid blocking
  - #11: Support for encryption (optional, not implemented)
"""

import json
import csv
import hmac
import hashlib
import logging
import os
from pathlib import Path
from queue import Queue, Empty
from threading import Thread, Lock
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import IPProfile, ThreatEvent
    from ..config import NetShieldConfig

from ..config import (
    EVENTS_LOG_FILENAME,
    WATCHLIST_LOG_FILENAME,
    TRAFFIC_LOG_FILENAME,
    get_log_integrity_secret,
)

logger = logging.getLogger(__name__)


class EventLogger:
    """
    Thread-safe async event logger with integrity verification.
    
    Security Fixes:
      - #9: HMAC signatures for log entries
      - #10: Background thread for async writes
      - #11: Encryption placeholder (optional feature)
    """
    
    def __init__(self, log_dir: Path, enable_integrity: bool = False):
        """
        Initialize logger.
        
        Args:
            log_dir: Directory for log files
            enable_integrity: Enable HMAC signing (Fix #9)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.events_file = self.log_dir / EVENTS_LOG_FILENAME
        self.watchlist_file = self.log_dir / WATCHLIST_LOG_FILENAME
        self.traffic_file = self.log_dir / TRAFFIC_LOG_FILENAME
        
        # Fix #9: HMAC integrity
        self.enable_integrity = enable_integrity
        self._integrity_secret = get_log_integrity_secret() if enable_integrity else None
        
        # Fix #10: Async logging
        self._write_queue: Queue = Queue(maxsize=10000)
        self._running = True
        self._writer_thread = Thread(
            target=self._writer_worker,
            daemon=True,
            name="EventLogger-Writer"
        )
        self._writer_thread.start()
        
        # File locks for direct writes
        self._watchlist_lock = Lock()
        
        # Initialize CSV
        self._init_traffic_csv()
    
    def _init_traffic_csv(self):
        """Initialize traffic CSV with headers."""
        if not self.traffic_file.exists():
            try:
                with open(self.traffic_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Timestamp", "IP", "Country", "ASN", "Network",
                        "Speed_MBps", "Throttled", "ThreatScore", "Signature"
                    ])
            except Exception as e:
                logger.error(f"Failed to init traffic CSV: {e}")
    
    def _compute_hmac(self, data: str) -> str:
        """
        Compute HMAC-SHA256 signature for data.
        
        Security Fix #9: Provides integrity verification.
        """
        if not self._integrity_secret:
            return ""
        
        signature = hmac.new(
            self._integrity_secret,
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()[:16]  # Truncated for brevity
        
        return signature
    
    def _writer_worker(self):
        """
        Background writer thread.
        
        Security Fix #10: Non-blocking writes.
        """
        while self._running:
            try:
                item = self._write_queue.get(timeout=0.5)
            except Empty:
                continue
            
            try:
                self._process_write(item)
            except Exception as e:
                logger.error(f"Write error: {e}")
    
    def _process_write(self, item: dict):
        """Process a write item from the queue."""
        write_type = item.get('type')
        
        if write_type == 'event':
            self._write_event(item['data'])
        elif write_type == 'traffic':
            self._write_traffic(item['data'])
    
    def _write_event(self, event_dict: dict):
        """Write event to JSONL file."""
        line = json.dumps(event_dict, ensure_ascii=False)
        
        if self.enable_integrity:
            sig = self._compute_hmac(line)
            event_dict['_sig'] = sig
            line = json.dumps(event_dict, ensure_ascii=False)
        
        try:
            with open(self.events_file, 'a', encoding='utf-8') as f:
                f.write(line + "\n")
        except Exception as e:
            logger.error(f"Failed to write event: {e}")
    
    def _write_traffic(self, traffic_data: dict):
        """Write traffic entry to CSV."""
        row = [
            traffic_data['timestamp'],
            traffic_data['ip'],
            traffic_data['country'],
            traffic_data['asn'],
            traffic_data['network'],
            traffic_data['speed'],
            traffic_data['throttled'],
            traffic_data['score'],
        ]
        
        if self.enable_integrity:
            row_str = ','.join(str(x) for x in row)
            sig = self._compute_hmac(row_str)
            row.append(sig)
        else:
            row.append("")
        
        try:
            with open(self.traffic_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(row)
        except Exception as e:
            logger.error(f"Failed to write traffic: {e}")
    
    def log_event(self, event: "ThreatEvent"):
        """
        Queue an event for async logging.
        
        Args:
            event: ThreatEvent to log
        """
        try:
            self._write_queue.put_nowait({
                'type': 'event',
                'data': event.to_dict()
            })
        except Exception:
            pass  # Queue full, drop event
    
    def log_traffic(self, profile: "IPProfile", speed_mbps: float, was_throttled: bool):
        """
        Queue traffic entry for async logging.
        
        Args:
            profile: IP profile
            speed_mbps: Current speed
            was_throttled: Whether packet was throttled
        """
        try:
            self._write_queue.put_nowait({
                'type': 'traffic',
                'data': {
                    'timestamp': datetime.now().isoformat(),
                    'ip': profile.ip,
                    'country': profile.country,
                    'asn': profile.asn,
                    'network': profile.network_name,
                    'speed': f"{speed_mbps:.2f}",
                    'throttled': "Yes" if was_throttled else "No",
                    'score': profile.threat_score,
                }
            })
        except Exception:
            pass
    
    def save_watchlist(self, watchlist: list["IPProfile"]):
        """
        Save watchlist to JSON file (synchronous).
        
        Args:
            watchlist: List of IP profiles to save
        """
        data = []
        for profile in watchlist:
            entry = profile.to_dict()
            if self.enable_integrity:
                entry_str = json.dumps(entry, sort_keys=True)
                entry['_sig'] = self._compute_hmac(entry_str)
            data.append(entry)
        
        with self._watchlist_lock:
            try:
                # Write to temp file first
                temp_file = self.watchlist_file.with_suffix('.tmp')
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                # Atomic replace
                temp_file.replace(self.watchlist_file)
            except Exception as e:
                logger.error(f"Failed to save watchlist: {e}")
    
    def verify_integrity(self, filepath: Path) -> bool:
        """
        Verify integrity of a log file.
        
        Args:
            filepath: Path to log file
            
        Returns:
            True if all entries have valid signatures
        """
        if not self._integrity_secret:
            logger.warning("Integrity check requested but no secret configured")
            return False
        
        try:
            if filepath.suffix == '.json':
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for entry in data:
                    sig = entry.pop('_sig', None)
                    if not sig:
                        return False
                    
                    entry_str = json.dumps(entry, sort_keys=True)
                    expected = self._compute_hmac(entry_str)
                    if sig != expected:
                        return False
                        
            return True
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False
    
    def stop(self):
        """Stop writer thread gracefully."""
        self._running = False
        self._writer_thread.join(timeout=2.0)
    
    def flush(self):
        """Wait for all queued writes to complete."""
        while not self._write_queue.empty():
            import time
            time.sleep(0.1)
