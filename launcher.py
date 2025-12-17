"""
NetShield Launcher — Privilege Separation
==========================================
Launches the separated service/worker architecture:

    1. Admin Service (elevated) — minimal WinDivert code
    2. User Worker (standard) — ML/Intel analysis
    3. GUI (optional) — Electron dashboard

Security Architecture:
    ┌─────────────────┐     ┌─────────────────┐
    │  Service.py     │     │  Worker.py      │
    │  (Admin)        │────▶│  (User)         │
    │                 │ IPC │                 │
    │  WinDivert only │     │  ML + Intel     │
    └─────────────────┘     └─────────────────┘
                                    │
                                    ▼ WebSocket
                            ┌─────────────────┐
                            │  GUI (Electron) │
                            └─────────────────┘
"""

import subprocess
import time
import os
import sys
import signal
import ctypes
from pathlib import Path

# Configuration
REPO_ROOT = Path(__file__).parent.absolute()
GUI_DIR = None

# Try to find GUI directory
for path in [REPO_ROOT / "gui", REPO_ROOT.parent / "netshield-gui"]:
    if path.is_dir():
        GUI_DIR = path
        break


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def request_admin():
    """Request elevation via UAC."""
    if is_admin():
        return True
    
    print("[*] Requesting administrator privileges...")
    try:
        # Re-launch with elevation
        ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            sys.executable,
            f'"{__file__}"',
            None, 
            1  # SW_SHOWNORMAL
        )
        return False  # Current process should exit
    except Exception as e:
        print(f"[!] Failed to elevate: {e}")
        return False


def main():
    """Launch NetShield with privilege separation."""
    print("=" * 60)
    print("  NetShield Launcher — Privilege Separation Mode")
    print("=" * 60)
    print(f"  Root: {REPO_ROOT}")
    print(f"  GUI:  {GUI_DIR or 'Not found'}")
    print(f"  Admin: {'Yes' if is_admin() else 'No'}")
    print("=" * 60)
    
    processes = []
    service_process = None
    worker_process = None
    gui_process = None
    
    try:
        # =====================================================================
        # 1. Start Admin Service (requires elevation)
        # =====================================================================
        print("\n[1/3] Starting Admin Service...")
        
        if is_admin():
            # Already admin — start service directly
            service_process = subprocess.Popen(
                [sys.executable, "-m", "netshield.service"],
                cwd=str(REPO_ROOT),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(service_process)
            print("[+] Service started (PID: {})".format(service_process.pid))
        else:
            # Need to elevate for service
            print("[*] Service requires admin — launching elevated...")
            # Use runas to start service in elevated console
            os.system(
                f'start "NetShield Service" /MIN powershell -Command "'
                f"Start-Process python -ArgumentList '-m netshield.service' "
                f"-WorkingDirectory '{REPO_ROOT}' -Verb RunAs\""
            )
            print("[+] Service launched in elevated window")
        
        # Wait for service to initialize
        print("[*] Waiting for service to initialize...")
        time.sleep(3)
        
        # =====================================================================
        # 2. Start User Worker (no admin needed)
        # =====================================================================
        print("\n[2/3] Starting Worker (user-space)...")
        
        worker_process = subprocess.Popen(
            [sys.executable, "-m", "netshield.worker"],
            cwd=str(REPO_ROOT),
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        processes.append(worker_process)
        print("[+] Worker started (PID: {})".format(worker_process.pid))
        
        # Wait for connection
        time.sleep(2)
        
        # =====================================================================
        # 3. Start GUI (optional)
        # =====================================================================
        if GUI_DIR:
            print("\n[3/3] Starting GUI (Electron)...")
            npm_cmd = "npm.cmd" if os.name == 'nt' else "npm"
            
            gui_process = subprocess.Popen(
                [npm_cmd, "run", "dev"],
                cwd=str(GUI_DIR),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(gui_process)
            print("[+] GUI started (PID: {})".format(gui_process.pid))
        else:
            print("\n[3/3] Skipping GUI (directory not found)")
        
        # =====================================================================
        # Monitor
        # =====================================================================
        print("\n" + "=" * 60)
        print("  NetShield is running!")
        print("  Press Ctrl+C to stop all services")
        print("=" * 60)
        
        # Monitor processes
        while True:
            time.sleep(2)
            
            # Check worker
            if worker_process and worker_process.poll() is not None:
                print("[!] Worker exited!")
                break
            
            # Check GUI
            if gui_process and gui_process.poll() is not None:
                print("[!] GUI exited (continuing without GUI)")
                gui_process = None
    
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C received — stopping services...")
    
    except Exception as e:
        print(f"\n[!] Error: {e}")
    
    finally:
        # =====================================================================
        # Cleanup
        # =====================================================================
        print("\n[*] Stopping all processes...")
        
        for p in processes:
            try:
                if p.poll() is None:
                    p.terminate()
                    print(f"    Terminated PID {p.pid}")
            except Exception as e:
                print(f"    Error stopping {p.pid}: {e}")
        
        # Give time to terminate
        time.sleep(1)
        
        # Force kill if needed
        for p in processes:
            try:
                if p.poll() is None:
                    p.kill()
                    print(f"    Force killed PID {p.pid}")
            except:
                pass
        
        print("\n[*] NetShield stopped.")
        print("[*] Note: Admin service may still be running in elevated window.")
        print("    Close it manually if needed.")


if __name__ == "__main__":
    main()

