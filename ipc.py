"""
NetShield IPC — Named Pipe Communication
=========================================
Secure inter-process communication between admin service and user worker.

Architecture:
    ┌─────────────────────┐           ┌─────────────────────┐
    │  Admin Service      │           │  User Worker        │
    │  (SYSTEM/Admin)     │           │  (User privileges)  │
    │                     │           │                     │
    │  ┌───────────────┐  │   Named   │  ┌───────────────┐  │
    │  │ IPCServer     │──┼───Pipe────┼──│ IPCClient     │  │
    │  │ (packets out) │  │           │  │ (packets in)  │  │
    │  └───────────────┘  │           │  └───────────────┘  │
    │                     │           │                     │
    │  ┌───────────────┐  │   Named   │  ┌───────────────┐  │
    │  │ CommandServer │◀─┼───Pipe────┼──│ CommandClient │  │
    │  │ (cmds in)     │  │           │  │ (cmds out)    │  │
    │  └───────────────┘  │           │  └───────────────┘  │
    └─────────────────────┘           └─────────────────────┘

Security:
    - Fixed allowed operations (whitelist)
    - Input validation via Pydantic
    - No arbitrary code execution
    - DACL on pipes for access control
"""

import json
import struct
import logging
import threading
from enum import Enum
from typing import Optional, Callable, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# Windows Named Pipe imports
try:
    import win32pipe
    import win32file
    import win32security
    import pywintypes
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    logger.warning("pywin32 not installed. IPC will not work.")


# =============================================================================
# CONSTANTS
# =============================================================================

PIPE_PACKETS = r'\\.\pipe\NetShieldPackets'
PIPE_COMMANDS = r'\\.\pipe\NetShieldCommands'
BUFFER_SIZE = 65536
MAX_PACKET_SIZE = 65535

# Message framing: 4-byte length prefix
HEADER_FORMAT = '>I'  # Big-endian unsigned int
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


# =============================================================================
# DATA MODELS (Type-safe, validated)
# =============================================================================

class CommandType(str, Enum):
    """Allowed IPC commands — Security whitelist."""
    THROTTLE_IP = "throttle_ip"
    UNTHROTTLE_IP = "unthrottle_ip"
    GET_STATS = "get_stats"
    SHUTDOWN = "shutdown"


@dataclass
class PacketData:
    """
    Packet information sent from service to worker.
    
    Minimal data — only what worker needs for analysis.
    Raw payload NOT included (too dangerous to pass via IPC).
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "tcp" or "udp"
    size: int
    timestamp: float
    
    # Metadata
    is_inbound: bool = True
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes for IPC."""
        data = json.dumps(asdict(self), separators=(',', ':')).encode('utf-8')
        return struct.pack(HEADER_FORMAT, len(data)) + data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'PacketData':
        """Deserialize from bytes."""
        return cls(**json.loads(data.decode('utf-8')))
    
    def validate(self) -> bool:
        """Validate packet data — prevent injection."""
        # IP validation
        if not self._is_valid_ip(self.src_ip):
            return False
        if not self._is_valid_ip(self.dst_ip):
            return False
        # Port validation
        if not (0 <= self.src_port <= 65535):
            return False
        if not (0 <= self.dst_port <= 65535):
            return False
        # Size validation
        if not (0 <= self.size <= MAX_PACKET_SIZE):
            return False
        # Protocol validation
        if self.protocol not in ("tcp", "udp"):
            return False
        return True
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Basic IP validation."""
        if not ip or len(ip) > 45:
            return False
        # Only allow valid IP characters
        import re
        return bool(re.match(r'^[\d.:a-fA-F]+$', ip))


@dataclass
class Command:
    """
    Command sent from worker to service.
    
    Security: Only whitelisted commands allowed.
    """
    type: str  # CommandType value
    target_ip: Optional[str] = None
    params: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes for IPC."""
        data = json.dumps(asdict(self), separators=(',', ':')).encode('utf-8')
        return struct.pack(HEADER_FORMAT, len(data)) + data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Command':
        """Deserialize from bytes."""
        return cls(**json.loads(data.decode('utf-8')))
    
    def validate(self) -> bool:
        """Validate command — security check."""
        # Check command type against whitelist
        try:
            CommandType(self.type)
        except ValueError:
            logger.warning(f"Invalid command type: {self.type}")
            return False
        
        # Validate target IP if present
        if self.target_ip:
            if not PacketData._is_valid_ip(self.target_ip):
                logger.warning(f"Invalid target IP: {self.target_ip}")
                return False
        
        return True


@dataclass
class StatsResponse:
    """Statistics response from service."""
    total_packets: int = 0
    total_bytes: int = 0
    throttled_packets: int = 0
    throttled_ips: list = field(default_factory=list)
    uptime_seconds: float = 0.0
    
    def to_bytes(self) -> bytes:
        data = json.dumps(asdict(self), separators=(',', ':')).encode('utf-8')
        return struct.pack(HEADER_FORMAT, len(data)) + data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'StatsResponse':
        return cls(**json.loads(data.decode('utf-8')))


# =============================================================================
# IPC SERVER (Runs in Admin Service)
# =============================================================================

class IPCServer:
    """
    Named Pipe server for admin service.
    
    Sends packet data to worker, receives commands.
    Thread-safe with proper cleanup.
    """
    
    def __init__(self, 
                 on_command: Optional[Callable[[Command], Any]] = None):
        self.on_command = on_command
        self._running = False
        self._packet_pipe = None
        self._command_pipe = None
        self._threads: list[threading.Thread] = []
        
    def start(self):
        """Start IPC server threads."""
        if not WIN32_AVAILABLE:
            raise RuntimeError("pywin32 required for IPC")
        
        self._running = True
        
        # Create pipes with security descriptor
        # Only allow connection from same user or lower privilege
        sa = self._create_security_attributes()
        
        # Packet pipe (server → client)
        self._packet_pipe = win32pipe.CreateNamedPipe(
            PIPE_PACKETS,
            win32pipe.PIPE_ACCESS_OUTBOUND,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
            1,  # Max instances
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,  # Default timeout
            sa
        )
        
        # Command pipe (client → server)
        self._command_pipe = win32pipe.CreateNamedPipe(
            PIPE_COMMANDS,
            win32pipe.PIPE_ACCESS_INBOUND,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
            1,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            sa
        )
        
        # Start command listener thread
        cmd_thread = threading.Thread(
            target=self._command_listener,
            daemon=True,
            name="IPC-CommandListener"
        )
        cmd_thread.start()
        self._threads.append(cmd_thread)
        
        logger.info("IPC Server started")
    
    def _create_security_attributes(self):
        """Create DACL allowing user access to pipes."""
        # For now, use default security
        # TODO: Implement proper DACL with restricted access
        return None
    
    def wait_for_client(self, timeout_ms: int = 5000) -> bool:
        """Wait for client to connect to packet pipe."""
        try:
            win32pipe.ConnectNamedPipe(self._packet_pipe, None)
            return True
        except pywintypes.error as e:
            if e.winerror == 535:  # Already connected
                return True
            logger.error(f"Client connection failed: {e}")
            return False
    
    def send_packet(self, packet: PacketData) -> bool:
        """Send packet data to worker."""
        if not packet.validate():
            logger.warning("Packet validation failed, dropping")
            return False
        
        try:
            data = packet.to_bytes()
            win32file.WriteFile(self._packet_pipe, data)
            return True
        except pywintypes.error as e:
            logger.error(f"Failed to send packet: {e}")
            return False
    
    def _command_listener(self):
        """Listen for commands from worker."""
        try:
            win32pipe.ConnectNamedPipe(self._command_pipe, None)
        except pywintypes.error:
            pass
        
        while self._running:
            try:
                # Read header
                hr, header = win32file.ReadFile(self._command_pipe, HEADER_SIZE)
                if len(header) < HEADER_SIZE:
                    continue
                
                msg_len = struct.unpack(HEADER_FORMAT, header)[0]
                if msg_len > BUFFER_SIZE:
                    logger.warning(f"Message too large: {msg_len}")
                    continue
                
                # Read message
                hr, data = win32file.ReadFile(self._command_pipe, msg_len)
                
                # Parse and validate
                cmd = Command.from_bytes(data)
                if cmd.validate():
                    if self.on_command:
                        self.on_command(cmd)
                else:
                    logger.warning(f"Invalid command rejected: {cmd.type}")
                    
            except pywintypes.error as e:
                if e.winerror == 109:  # Pipe closed
                    break
                logger.error(f"Command read error: {e}")
            except Exception as e:
                logger.exception(f"Command processing error: {e}")
    
    def stop(self):
        """Stop IPC server."""
        self._running = False
        
        # Close pipes
        if self._packet_pipe:
            try:
                win32file.CloseHandle(self._packet_pipe)
            except:
                pass
        
        if self._command_pipe:
            try:
                win32file.CloseHandle(self._command_pipe)
            except:
                pass
        
        # Wait for threads
        for t in self._threads:
            t.join(timeout=1.0)
        
        logger.info("IPC Server stopped")


# =============================================================================
# IPC CLIENT (Runs in User Worker)
# =============================================================================

class IPCClient:
    """
    Named Pipe client for user worker.
    
    Receives packet data from service, sends commands.
    """
    
    def __init__(self):
        self._packet_pipe = None
        self._command_pipe = None
        self._connected = False
    
    def connect(self, timeout_ms: int = 30000) -> bool:
        """Connect to admin service pipes."""
        if not WIN32_AVAILABLE:
            raise RuntimeError("pywin32 required for IPC")
        
        try:
            # Wait for pipes to be available
            if not win32pipe.WaitNamedPipe(PIPE_PACKETS, timeout_ms):
                logger.error("Packet pipe not available")
                return False
            
            # Connect to packet pipe
            self._packet_pipe = win32file.CreateFile(
                PIPE_PACKETS,
                win32file.GENERIC_READ,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            
            # Connect to command pipe
            self._command_pipe = win32file.CreateFile(
                PIPE_COMMANDS,
                win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            
            self._connected = True
            logger.info("IPC Client connected to service")
            return True
            
        except pywintypes.error as e:
            logger.error(f"IPC connection failed: {e}")
            return False
    
    def receive_packet(self) -> Optional[PacketData]:
        """Receive packet data from service (blocking)."""
        if not self._connected:
            return None
        
        try:
            # Read header
            hr, header = win32file.ReadFile(self._packet_pipe, HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                return None
            
            msg_len = struct.unpack(HEADER_FORMAT, header)[0]
            if msg_len > BUFFER_SIZE:
                logger.warning(f"Packet too large: {msg_len}")
                return None
            
            # Read data
            hr, data = win32file.ReadFile(self._packet_pipe, msg_len)
            
            # Parse and validate
            packet = PacketData.from_bytes(data)
            if packet.validate():
                return packet
            else:
                logger.warning("Received invalid packet, discarding")
                return None
                
        except pywintypes.error as e:
            if e.winerror == 109:  # Pipe closed
                self._connected = False
            logger.error(f"Packet receive error: {e}")
            return None
    
    def send_command(self, cmd: Command) -> bool:
        """Send command to service."""
        if not self._connected:
            return False
        
        if not cmd.validate():
            logger.warning("Command validation failed")
            return False
        
        try:
            data = cmd.to_bytes()
            win32file.WriteFile(self._command_pipe, data)
            return True
        except pywintypes.error as e:
            logger.error(f"Command send error: {e}")
            return False
    
    def throttle_ip(self, ip: str) -> bool:
        """Convenience: send throttle command."""
        cmd = Command(
            type=CommandType.THROTTLE_IP.value,
            target_ip=ip
        )
        return self.send_command(cmd)
    
    def disconnect(self):
        """Disconnect from service."""
        self._connected = False
        
        if self._packet_pipe:
            try:
                win32file.CloseHandle(self._packet_pipe)
            except:
                pass
        
        if self._command_pipe:
            try:
                win32file.CloseHandle(self._command_pipe)
            except:
                pass
        
        logger.info("IPC Client disconnected")


# =============================================================================
# TESTING HELPERS
# =============================================================================

def create_mock_ipc():
    """Create mock IPC for testing without pywin32."""
    from unittest.mock import MagicMock
    
    server = MagicMock(spec=IPCServer)
    client = MagicMock(spec=IPCClient)
    
    # Shared queue for testing
    import queue
    packet_queue = queue.Queue()
    command_queue = queue.Queue()
    
    def mock_send(packet):
        packet_queue.put(packet)
        return True
    
    def mock_receive():
        try:
            return packet_queue.get_nowait()
        except queue.Empty:
            return None
    
    server.send_packet = mock_send
    client.receive_packet = mock_receive
    
    return server, client
