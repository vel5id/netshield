"""
Console Output Utilities
========================
Formatted console output with colors and progress bars.
"""

import sys


class Console:
    """
    Console output helper with ANSI colors.
    """
    
    # ANSI color codes
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    
    # Status indicators
    OK = f"{GREEN}[OK]{RESET}"
    HIGH = f"{YELLOW}[HIGH]{RESET}"
    THROTTLE = f"{RED}[THROTTLE]{RESET}"
    ALERT = f"{RED}[!]{RESET}"
    INFO = f"{BLUE}[*]{RESET}"
    
    @classmethod
    def supports_color(cls) -> bool:
        """Check if terminal supports color."""
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    
    @classmethod
    def print_banner(cls):
        """Print the NetShield ASCII banner."""
        banner = """
  ███╗   ██╗███████╗████████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║ ╚████║███████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝"""
        print("=" * 75)
        print(f"{cls.CYAN}{banner}{cls.RESET}")
        print("=" * 75)
    
    @classmethod
    def print_config(cls, mode: str, limit: float, burst: float, log_dir: str):
        """Print configuration info."""
        print(f"  Mode: {cls.BOLD}{mode.upper()}{cls.RESET}")
        print(f"  Limit: {limit} MB/s | Burst: {burst} MB")
        print(f"  Logs: {log_dir}")
        print("=" * 75)
        print(f"{cls.INFO} Starting... Press Ctrl+C to stop.\n")
    
    @classmethod
    def progress_bar(cls, value: float, max_value: float, width: int = 25) -> str:
        """Create a progress bar string."""
        if max_value <= 0:
            ratio = 0
        else:
            ratio = min(value / max_value, 1.0)
        
        filled = int(ratio * width)
        bar = "█" * filled + "░" * (width - filled)
        return bar
    
    @classmethod
    def format_stats(cls, stats: dict) -> str:
        """Format stats for display with protocol breakdown."""
        speed = stats.get('speed_mbps', 0)
        max_bw = stats.get('max_bandwidth', 50)
        flood_mode = stats.get('flood_mode', False)
        
        # Status based on speed + flood mode
        if flood_mode:
            status = f"{cls.RED}[FLOOD]{cls.RESET}"
        elif speed > max_bw * 0.9:
            status = cls.THROTTLE
        elif speed > max_bw * 0.5:
            status = cls.HIGH
        else:
            status = cls.OK
        
        bar = cls.progress_bar(speed, max_bw)
        
        # Protocol breakdown (v2)
        udp_pkts = stats.get('udp_packets', 0)
        udp_drop = stats.get('udp_dropped', 0)
        tcp_pkts = stats.get('tcp_packets', 0)
        
        # Dropped indicator
        dropped = stats.get('dropped', 0)
        if dropped > 0:
            drop_str = f"{cls.RED}↓{dropped}{cls.RESET}"
        else:
            drop_str = f"{cls.GREEN}↓0{cls.RESET}"
        
        return (
            f"\r{status} {speed:6.2f}/{max_bw:.0f} MB/s [{bar}] "
            f"| UDP:{udp_pkts}({udp_drop}) TCP:{tcp_pkts} | {drop_str} | IPs:{stats.get('unique_ips', 0)}  "
        )
    
    @classmethod
    def print_stats(cls, stats: dict):
        """Print stats line (overwrites previous)."""
        line = cls.format_stats(stats)
        print(line, end="", flush=True)
    
    @classmethod
    def print_summary(cls, summary: dict):
        """Print session summary with protocol breakdown."""
        stats = summary.get('stats', {})
        protocols = summary.get('protocols', {})
        top_offenders = summary.get('top_offenders', [])
        
        print("\n\n" + "=" * 75)
        print(f"  {cls.BOLD}SESSION SUMMARY{cls.RESET}")
        print("=" * 75)
        print(f"  Total Traffic:    {stats.get('total_mb', 0):.2f} MB")
        print(f"  Dropped:          {stats.get('dropped', 0)} packets ({stats.get('dropped_mb', 0):.2f} MB)")
        print(f"  Unique IPs:       {stats.get('unique_ips', 0)}")
        
        # Protocol breakdown
        print(f"\n  {cls.BOLD}PROTOCOL BREAKDOWN:{cls.RESET}")
        for proto, ps in protocols.items():
            dropped_pct = (ps['dropped'] / max(ps['packets'], 1)) * 100
            print(f"    {proto.upper():4}: {ps['packets']:8} pkts | {ps['dropped']:6} dropped ({dropped_pct:.1f}%)")
        
        # Top offenders
        if top_offenders:
            print(f"\n  {cls.RED}⚠ TOP OFFENDERS:{cls.RESET}")
            for item in top_offenders[:5]:
                proto = item.get('protocol', 'unk').upper()
                print(f"    • [{proto}] {item['ip']:15} - {item['dropped']} dropped / {item['packets']} total")
        
        print("=" * 75)
    
    @classmethod
    def print_error(cls, message: str):
        """Print error message."""
        print(f"\n{cls.ALERT} {cls.RED}{message}{cls.RESET}")
    
    @classmethod
    def print_info(cls, message: str):
        """Print info message."""
        print(f"{cls.INFO} {message}")
