"""
NetShield Security Tests
========================
Tests for privilege separation, IPC validation, and security constraints.

Run with: python -m pytest tests/test_security.py -v
"""

import pytest
import json
import struct
from unittest.mock import MagicMock, patch
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from netshield.ipc import (
    PacketData, Command, CommandType, StatsResponse,
    IPCServer, IPCClient,
    HEADER_FORMAT, BUFFER_SIZE, MAX_PACKET_SIZE,
    create_mock_ipc
)


# =============================================================================
# PACKET DATA VALIDATION TESTS
# =============================================================================

class TestPacketDataValidation:
    """Test PacketData input validation — prevents injection attacks."""
    
    def test_valid_packet(self):
        """Valid packet should pass validation."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is True
    
    def test_invalid_ip_sql_injection(self):
        """SQL injection in IP should fail validation."""
        packet = PacketData(
            src_ip="'; DROP TABLE users; --",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_invalid_ip_script_injection(self):
        """XSS in IP should fail validation."""
        packet = PacketData(
            src_ip="<script>alert('xss')</script>",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_invalid_port_negative(self):
        """Negative port should fail validation."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=-1,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_invalid_port_overflow(self):
        """Port > 65535 should fail validation."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=70000,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_invalid_size_negative(self):
        """Negative size should fail validation."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=-100,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_invalid_size_too_large(self):
        """Size > MAX_PACKET_SIZE should fail validation."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=MAX_PACKET_SIZE + 1,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_invalid_protocol(self):
        """Invalid protocol should fail validation."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="icmp",  # Not in allowed list
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is False
    
    def test_ipv6_valid(self):
        """Valid IPv6 should pass validation."""
        packet = PacketData(
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=5055,
            dst_port=443,
            protocol="tcp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is True
    
    def test_ip_too_long(self):
        """IP > 45 chars should fail validation."""
        packet = PacketData(
            src_ip="a" * 50,
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        assert packet.validate() is False


# =============================================================================
# COMMAND VALIDATION TESTS
# =============================================================================

class TestCommandValidation:
    """Test Command whitelist validation — only allowed operations."""
    
    def test_valid_throttle_command(self):
        """THROTTLE_IP command should be valid."""
        cmd = Command(
            type=CommandType.THROTTLE_IP.value,
            target_ip="192.168.1.100"
        )
        assert cmd.validate() is True
    
    def test_valid_shutdown_command(self):
        """SHUTDOWN command should be valid."""
        cmd = Command(type=CommandType.SHUTDOWN.value)
        assert cmd.validate() is True
    
    def test_invalid_command_type(self):
        """Unknown command type should be rejected."""
        cmd = Command(
            type="EXECUTE_SHELL",
            params={"cmd": "rm -rf /"}
        )
        assert cmd.validate() is False
    
    def test_command_injection_attempt(self):
        """Command injection in type should fail."""
        cmd = Command(
            type="throttle_ip; rm -rf /",
            target_ip="192.168.1.100"
        )
        assert cmd.validate() is False
    
    def test_malicious_target_ip(self):
        """Malicious target IP should be rejected."""
        cmd = Command(
            type=CommandType.THROTTLE_IP.value,
            target_ip="$(cat /etc/passwd)"
        )
        assert cmd.validate() is False


# =============================================================================
# SERIALIZATION TESTS
# =============================================================================

class TestSerialization:
    """Test safe serialization/deserialization."""
    
    def test_packet_roundtrip(self):
        """Packet should survive serialization roundtrip."""
        original = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        
        # Serialize
        data = original.to_bytes()
        
        # Extract message (skip length header)
        msg_len = struct.unpack(HEADER_FORMAT, data[:4])[0]
        msg_data = data[4:4+msg_len]
        
        # Deserialize
        restored = PacketData.from_bytes(msg_data)
        
        assert restored.src_ip == original.src_ip
        assert restored.dst_ip == original.dst_ip
        assert restored.src_port == original.src_port
        assert restored.protocol == original.protocol
        assert restored.size == original.size
    
    def test_command_roundtrip(self):
        """Command should survive serialization roundtrip."""
        original = Command(
            type=CommandType.THROTTLE_IP.value,
            target_ip="10.0.0.5",
            params={"duration": 60}
        )
        
        data = original.to_bytes()
        msg_len = struct.unpack(HEADER_FORMAT, data[:4])[0]
        msg_data = data[4:4+msg_len]
        
        restored = Command.from_bytes(msg_data)
        
        assert restored.type == original.type
        assert restored.target_ip == original.target_ip
        assert restored.params == original.params
    
    def test_message_length_check(self):
        """Oversized messages should be detectable."""
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        
        data = packet.to_bytes()
        msg_len = struct.unpack(HEADER_FORMAT, data[:4])[0]
        
        assert msg_len < BUFFER_SIZE


# =============================================================================
# MOCK IPC TESTS
# =============================================================================

class TestMockIPC:
    """Test IPC using mock (no Windows pipes needed)."""
    
    def test_mock_packet_transfer(self):
        """Test packet transfer via mock IPC."""
        server, client = create_mock_ipc()
        
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=5055,
            dst_port=443,
            protocol="udp",
            size=1024,
            timestamp=1234567890.0
        )
        
        # Send via server
        assert server.send_packet(packet) is True
        
        # Receive via client
        received = client.receive_packet()
        assert received is not None
        assert received.src_ip == packet.src_ip
    
    def test_mock_empty_queue(self):
        """Empty queue should return None."""
        server, client = create_mock_ipc()
        
        received = client.receive_packet()
        assert received is None


# =============================================================================
# PRIVILEGE SEPARATION TESTS
# =============================================================================

class TestPrivilegeSeparation:
    """Test privilege separation requirements."""
    
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows only")
    def test_worker_no_pydivert_import(self):
        """Worker should not import pydivert directly."""
        # This tests that worker.py doesn't have WinDivert code
        import netshield.worker as worker_module
        
        # Check module globals
        assert 'pydivert' not in dir(worker_module)
    
    def test_command_whitelist_enforced(self):
        """Only whitelisted commands should be valid."""
        valid_types = [cmd.value for cmd in CommandType]
        
        # Test each valid type
        for cmd_type in valid_types:
            cmd = Command(type=cmd_type)
            assert cmd.validate() is True
        
        # Test invalid types
        invalid_types = [
            "exec",
            "shell",
            "eval",
            "import",
            "open_file",
            "write_file",
            "delete_file",
            "network_request"
        ]
        
        for cmd_type in invalid_types:
            cmd = Command(type=cmd_type)
            assert cmd.validate() is False


# =============================================================================
# STATS RESPONSE TESTS
# =============================================================================

class TestStatsResponse:
    """Test statistics response model."""
    
    def test_stats_roundtrip(self):
        """Stats should survive serialization roundtrip."""
        original = StatsResponse(
            total_packets=10000,
            total_bytes=1024000,
            throttled_packets=500,
            throttled_ips=["1.2.3.4", "5.6.7.8"],
            uptime_seconds=3600.5
        )
        
        data = original.to_bytes()
        msg_len = struct.unpack(HEADER_FORMAT, data[:4])[0]
        msg_data = data[4:4+msg_len]
        
        restored = StatsResponse.from_bytes(msg_data)
        
        assert restored.total_packets == original.total_packets
        assert restored.throttled_ips == original.throttled_ips


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
