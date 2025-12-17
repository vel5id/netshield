"""
Shield Engine v2 Tests
======================
Tests for high-performance protection engine.

Tests:
  - DROP strategy (no sleep)
  - Protocol tracking (UDP/TCP)
  - Sampled logging
  - Flood mode detection
"""

import pytest
import time
from unittest.mock import MagicMock, patch

from netshield.config import NetShieldConfig, MODE_VRCHAT, MODE_UNIVERSAL


@pytest.fixture
def mock_logger():
    """Mock event logger."""
    logger = MagicMock()
    return logger


@pytest.fixture
def engine_no_pydivert(test_config, mock_logger):
    """ShieldEngine with pydivert mocked out."""
    with patch('netshield.shield.engine.PYDIVERT_AVAILABLE', True):
        with patch('netshield.shield.engine.pydivert'):
            from netshield.shield.engine import ShieldEngine
            engine = ShieldEngine(test_config, mock_logger)
            yield engine


class TestShieldEngineFilter:
    """Filter string generation tests."""
    
    def test_filter_vrchat_mode(self, engine_no_pydivert):
        """VRChat mode should filter UDP and TCP ports."""
        engine_no_pydivert.config.mode = MODE_VRCHAT
        
        filter_str = engine_no_pydivert.build_filter()
        
        assert "inbound" in filter_str
        assert "udp" in filter_str
        assert "5055" in filter_str
        assert "27000" in filter_str
        # v2: Also includes TCP for tracking
        assert "tcp" in filter_str
    
    def test_filter_universal_mode(self, test_config, mock_logger):
        """Universal mode should include TCP and UDP."""
        config = NetShieldConfig(mode=MODE_UNIVERSAL)
        
        with patch('netshield.shield.engine.PYDIVERT_AVAILABLE', True):
            with patch('netshield.shield.engine.pydivert'):
                from netshield.shield.engine import ShieldEngine
                engine = ShieldEngine(config, mock_logger)
                filter_str = engine.build_filter()
        
        assert "inbound" in filter_str
        assert "tcp" in filter_str
        assert "udp" in filter_str


class TestDropStrategy:
    """DROP strategy tests (no sleep)."""
    
    def test_process_returns_drop_when_throttled(self, engine_no_pydivert):
        """Should return True (DROP) when bucket empty."""
        # Exhaust bucket
        engine_no_pydivert.bucket.consume(
            int(engine_no_pydivert.config.burst_size_mb * 1024 * 1024)
        )
        
        # Create mock packet
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 1000
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        should_drop = engine_no_pydivert._process_packet_fast(mock_packet, 1000)
        
        assert should_drop is True
    
    def test_process_returns_allow_when_ok(self, engine_no_pydivert):
        """Should return False (ALLOW) when bucket has tokens."""
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        should_drop = engine_no_pydivert._process_packet_fast(mock_packet, 100)
        
        assert should_drop is False
    
    def test_no_sleep_in_process(self, engine_no_pydivert):
        """Processing should be fast (no sleep)."""
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        start = time.perf_counter()
        for _ in range(1000):
            engine_no_pydivert._process_packet_fast(mock_packet, 100)
        elapsed = time.perf_counter() - start
        
        # 1000 packets should complete in under 1 second (no sleep)
        assert elapsed < 1.0


class TestProtocolTracking:
    """Protocol separation tests."""
    
    def test_udp_tracked_separately(self, engine_no_pydivert):
        """UDP packets should be tracked under 'udp' key."""
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        engine_no_pydivert._process_packet_fast(mock_packet, 100)
        
        assert engine_no_pydivert.proto_stats['udp'].packets == 1
    
    def test_tcp_tracked_separately(self, engine_no_pydivert):
        """TCP packets should be tracked under 'tcp' key."""
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 443
        mock_packet.udp = False  # TCP
        
        engine_no_pydivert._process_packet_fast(mock_packet, 100)
        
        assert engine_no_pydivert.proto_stats['tcp'].packets == 1
    
    def test_protocol_drop_tracked(self, engine_no_pydivert):
        """Dropped packets should be tracked per protocol."""
        # Mock bucket to always return "not allowed" (drop)
        engine_no_pydivert.bucket.consume = MagicMock(return_value=(False, 0.1))
        
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 1000
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        engine_no_pydivert._process_packet_fast(mock_packet, 1000)
        
        assert engine_no_pydivert.proto_stats['udp'].dropped == 1


class TestIPTracking:
    """Lightweight IP tracking tests."""
    
    def test_ip_stats_created(self, engine_no_pydivert):
        """New IP should create stats entry."""
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "1.2.3.4"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        engine_no_pydivert._process_packet_fast(mock_packet, 100)
        
        assert "1.2.3.4" in engine_no_pydivert.ip_stats
        assert engine_no_pydivert.ip_stats["1.2.3.4"].packets == 1
    
    def test_ip_stats_accumulated(self, engine_no_pydivert):
        """Multiple packets from same IP should accumulate."""
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "1.2.3.4"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        for _ in range(10):
            engine_no_pydivert._process_packet_fast(mock_packet, 100)
        
        assert engine_no_pydivert.ip_stats["1.2.3.4"].packets == 10
        assert engine_no_pydivert.ip_stats["1.2.3.4"].bytes == 1000


class TestFloodMode:
    """Flood detection tests."""
    
    def test_flood_mode_off_by_default(self, engine_no_pydivert):
        """Flood mode should be off initially."""
        assert engine_no_pydivert.flood_mode is False
    
    def test_flood_threshold_set(self, engine_no_pydivert):
        """Flood threshold should be 80% of max bandwidth."""
        expected = engine_no_pydivert.config.max_bandwidth_mbps * 0.8
        assert engine_no_pydivert.flood_threshold_mbps == expected


class TestStats:
    """Statistics gathering tests."""
    
    def test_get_stats_returns_protocols(self, engine_no_pydivert):
        """Stats should include protocol breakdown."""
        stats = engine_no_pydivert._get_stats()
        
        assert 'udp_packets' in stats
        assert 'udp_dropped' in stats
        assert 'tcp_packets' in stats
        assert 'tcp_dropped' in stats
    
    def test_get_stats_includes_flood_mode(self, engine_no_pydivert):
        """Stats should include flood mode flag."""
        stats = engine_no_pydivert._get_stats()
        
        assert 'flood_mode' in stats


class TestSessionSummary:
    """Session summary tests."""
    
    def test_summary_includes_protocols(self, engine_no_pydivert):
        """Summary should include protocol breakdown."""
        # Add some data
        mock_packet = MagicMock()
        mock_packet.raw = b'x' * 100
        mock_packet.src_addr = "8.8.8.8"
        mock_packet.src_port = 5055
        mock_packet.udp = True
        
        engine_no_pydivert._process_packet_fast(mock_packet, 100)
        
        summary = engine_no_pydivert.get_session_summary()
        
        assert 'protocols' in summary
        assert 'udp' in summary['protocols']
    
    def test_summary_includes_top_offenders(self, engine_no_pydivert):
        """Summary should include top offenders list."""
        summary = engine_no_pydivert.get_session_summary()
        
        assert 'top_offenders' in summary


class TestEngineImportError:
    """Import error handling tests."""
    
    def test_no_pydivert_raises(self, test_config, mock_logger):
        """Missing pydivert should raise ImportError."""
        with patch('netshield.shield.engine.PYDIVERT_AVAILABLE', False):
            from netshield.shield.engine import ShieldEngine
            with pytest.raises(ImportError):
                ShieldEngine(test_config, mock_logger)
