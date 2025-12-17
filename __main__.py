"""
NetShield — Main Entry Point
=============================
Unified Protection & Intelligence System

Run with: python -m netshield

Security Fixes Applied:
  All 12 vulnerabilities addressed in modular architecture.
"""

import sys
import signal
import argparse
import logging

from .config import (
    NetShieldConfig, 
    load_config,
    MODE_VRCHAT, 
    MODE_UNIVERSAL, 
    MODE_CUSTOM,
    DEFAULT_MODE,
    MIN_BANDWIDTH_MBPS,
    MAX_BANDWIDTH_MBPS,
)
from .shield import ShieldEngine
from .loggers import EventLogger
from .utils import Console


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )


def validate_args(args) -> list[str]:
    """
    Validate CLI arguments.
    
    Security Fix #5: Bounds checking on all numeric inputs.
    """
    errors = []
    
    if args.limit < MIN_BANDWIDTH_MBPS or args.limit > MAX_BANDWIDTH_MBPS:
        errors.append(
            f"--limit must be between {MIN_BANDWIDTH_MBPS} and {MAX_BANDWIDTH_MBPS}"
        )
    
    if args.burst < 1.0 or args.burst > 100.0:
        errors.append("--burst must be between 1.0 and 100.0")
    
    if args.burst > args.limit:
        errors.append("--burst cannot exceed --limit")
    
    return errors


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='netshield',
        description="NetShield — Unified Protection & Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m netshield                     # VRChat mode (default)
  python -m netshield --mode universal    # All inbound traffic
  python -m netshield --limit 30          # 30 MB/s limit
  python -m netshield --config my.yaml    # Custom config file

Security Notes:
  - Requires administrator privileges (WinDivert driver)
  - Set NETSHIELD_LOG_SECRET env var for log integrity
        """
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=[MODE_VRCHAT, MODE_UNIVERSAL, MODE_CUSTOM],
        default=DEFAULT_MODE,
        help=f'Operation mode (default: {DEFAULT_MODE})'
    )
    
    parser.add_argument(
        '--limit', '-l',
        type=float,
        default=50.0,
        help='Max bandwidth in MB/s (default: 50.0)'
    )
    
    parser.add_argument(
        '--burst', '-b',
        type=float,
        default=10.0,
        help='Burst bucket size in MB (default: 10.0)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default=None,
        help='Path to config file (YAML or JSON)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--integrity',
        action='store_true',
        help='Enable log integrity checks (HMAC)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Validate arguments (Fix #5)
    validation_errors = validate_args(args)
    if validation_errors:
        for error in validation_errors:
            Console.print_error(error)
        sys.exit(1)
    
    # Load config
    if args.config:
        from pathlib import Path
        config = load_config(Path(args.config))
    else:
        config = NetShieldConfig()
    
    # Override with CLI args
    config.mode = args.mode
    config.max_bandwidth_mbps = args.limit
    config.burst_size_mb = args.burst
    config.log_integrity = args.integrity
    
    # Validate config
    config_errors = config.validate()
    if config_errors:
        for error in config_errors:
            Console.print_error(error)
        sys.exit(1)
    
    # Initialize components
    logger = EventLogger(config.log_dir, enable_integrity=config.log_integrity)
    
    try:
        engine = ShieldEngine(config, logger)
    except ImportError as e:
        Console.print_error(str(e))
        sys.exit(1)
    
    # Signal handler
    def signal_handler(sig, frame):
        Console.print_info("Ctrl+C received, shutting down...")
        engine.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Print banner and config
    Console.print_banner()
    Console.print_config(
        config.mode,
        config.max_bandwidth_mbps,
        config.burst_size_mb,
        str(config.log_dir.absolute())
    )
    
    # Run engine
    try:
        engine.run(stats_callback=Console.print_stats)
    except PermissionError:
        Console.print_error("Administrator privileges required!")
        Console.print_error("Run from an elevated command prompt.")
        sys.exit(1)
    except Exception as e:
        Console.print_error(f"Unexpected error: {e}")
        raise
    finally:
        # Print summary
        summary = engine.get_session_summary()
        Console.print_summary(summary)
        
        # Cleanup
        logger.stop()


if __name__ == "__main__":
    main()
