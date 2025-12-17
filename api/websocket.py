"""
WebSocket Server for NetShield GUI
==================================
Provides real-time statistics streaming and command control for the GUI.

Communication Protocol:
  - JSON messages
  - "stats" broadcast every X seconds
  - "logs" broadcast with recent traffic entries
  - "alert" events pushed immediately
"""

import asyncio
import csv
import json
import logging
import threading
from pathlib import Path
from typing import Optional, TYPE_CHECKING, List, Dict
from queue import Queue, Empty

if TYPE_CHECKING:
    from ..shield.engine import ShieldEngine

logger = logging.getLogger(__name__)

# Optional websockets
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    logger.warning("websockets not installed. GUI support disabled.")

# Log file path
LOG_FILE = Path("d:/Py/netshield_logs/traffic.csv")


class WebSocketServer:
    """
    Async WebSocket server running in a separate thread.
    """
    
    HOST = "127.0.0.1"
    PORT = 8765
    
    def __init__(self, engine: "ShieldEngine"):
        self.engine = engine
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.clients = set()
        
        # Command queue from GUI to Engine
        self.command_queue: Queue = Queue()
        
        # Track last sent log line count
        self._last_log_line = 0
    
    def start(self):
        """Start the WebSocket server thread."""
        if not WEBSOCKETS_AVAILABLE:
            return
            
        self.running = True
        self.thread = threading.Thread(
            target=self._run_server,
            name="NetShield-WebSocket",
            daemon=True
        )
        self.thread.start()
    
    def stop(self):
        """Stop server and close connections."""
        self.running = False
        if self.loop:
            # Schedule stop in the loop
            self.loop.call_soon_threadsafe(self.loop.stop)
        
        if self.thread:
            self.thread.join(timeout=1.0)
    
    def _run_server(self):
        """Main server loop in separate thread."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        async def runner():
            logger.info(f"GUI WebSocket server listening on ws://{self.HOST}:{self.PORT}")
            
            # Start broadcaster
            self.loop.create_task(self._broadcast_stats())
            
            async with websockets.serve(self._handler, self.HOST, self.PORT):
                # Keep running until stop signal
                while self.running:
                    await asyncio.sleep(0.1)

        try:
            self.loop.run_until_complete(runner())
        except Exception as e:
            if self.running: # Only log if not expected stop
                logger.error(f"WebSocket server error: {e}")
        finally:
            # Cleanup pending tasks
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            
            self.loop.close()
    
    async def _handler(self, websocket):
        """Handle individual client connection."""
        self.clients.add(websocket)
        
        # Send initial history snapshot
        try:
            history = self._read_log_tail(50)
            await websocket.send(json.dumps({
                "type": "logs",
                "data": history,
                "is_initial": True
            }))
        except Exception as e:
            logger.warning(f"Failed to send initial history: {e}")
        
        try:
            async for message in websocket:
                await self._process_message(json.loads(message))
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.remove(websocket)
    
    async def _process_message(self, msg: dict):
        """Process command from GUI."""
        cmd = msg.get("command")
        if cmd == "stop_engine":
            self.engine.stop()
        elif cmd == "get_logs":
            # Request for log history
            count = msg.get("count", 50)
            # Will be sent via broadcast
    
    def _read_log_tail(self, n: int = 50) -> List[Dict]:
        """Read last N lines from traffic.csv."""
        entries = []
        
        if not LOG_FILE.exists():
            return entries
        
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                all_rows = list(reader)
                
                # Get last N
                for row in all_rows[-n:]:
                    entries.append({
                        "timestamp": row.get("Timestamp", ""),
                        "ip": row.get("IP", ""),
                        "country": row.get("Country", ""),
                        "asn": row.get("ASN", ""),
                        "speed": row.get("Speed_MBps", "0"),
                        "throttled": row.get("Throttled", "False") == "True",
                        "threat_score": int(row.get("ThreatScore", "0") or 0),
                        "signature": row.get("Signature", "")
                    })
        except Exception as e:
            logger.warning(f"Failed to read log file: {e}")
        
        return entries
    
    async def _broadcast_stats(self):
        """Periodically broadcast stats to all clients."""
        while self.running:
            if self.clients:
                stats = self.engine._get_stats()
                
                # Add flood mode and timestamp
                payload = json.dumps({
                    "type": "stats",
                    "data": stats,
                    "timestamp": asyncio.get_event_loop().time()
                })
                
                # Broadcast stats
                await asyncio.gather(
                    *[client.send(payload) for client in self.clients],
                    return_exceptions=True
                )
                
                # Also broadcast new log entries (every 2s)
                try:
                    new_logs = self._read_log_tail(10)  # Last 10 for incremental
                    if new_logs:
                        log_payload = json.dumps({
                            "type": "logs",
                            "data": new_logs,
                            "is_initial": False
                        })
                        await asyncio.gather(
                            *[client.send(log_payload) for client in self.clients],
                            return_exceptions=True
                        )
                except Exception as e:
                    logger.warning(f"Failed to broadcast logs: {e}")
            
            await asyncio.sleep(0.5)  # 2Hz update rate

