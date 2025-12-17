import subprocess
import time
import os
import sys
import signal

# Configuration
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# Try to find GUI directory (either nested 'gui' or sibling 'netshield-gui')
POSSIBLE_GUI_PATHS = [
    os.path.join(REPO_ROOT, "gui"),
    os.path.join(REPO_ROOT, "..", "netshield-gui")
]

GUI_DIR = None
for path in POSSIBLE_GUI_PATHS:
    if os.path.isdir(path):
        GUI_DIR = os.path.abspath(path)
        break

def main():
    print(f"[*] Root Directory: {REPO_ROOT}")
    if GUI_DIR:
        print(f"[*] GUI Directory:  {GUI_DIR}")
    else:
        print("[!] Warning: GUI directory not found!")
    
    print("\n[*] Starting NetShield Integrated Environment...")

    processes = []

    try:
        # 1. Start Backend
        print("[*] Launching Backend (Python)...")
        # Run module 'netshield' from the current directory
        backend = subprocess.Popen([sys.executable, "-m", "netshield"], cwd=REPO_ROOT)
        processes.append(backend)

        # 2. Start Frontend
        if GUI_DIR:
            print("[*] Launching Frontend (Vite/Electron)...")
            # npm run dev
            # On Windows, npm is a batch file, so shell=True is often needed or explicitly calling npm.cmd
            npm_cmd = "npm.cmd" if os.name == 'nt' else "npm"
            frontend = subprocess.Popen([npm_cmd, "run", "dev"], cwd=GUI_DIR)
            processes.append(frontend)
        else:
            print("[!] Skipping Frontend launch (dir not found)")

        print("\n[+] NetShield is running!")
        print("[*] Press Ctrl+C to stop all services.\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping services...")
        for p in processes:
            try:
                # Try graceful termination first
                p.terminate()
            except:
                pass
        
        # Give them a moment to die
        time.sleep(1)
        
        # Force kill if needed
        for p in processes:
            if p.poll() is None:
                p.kill()
        
        print("[*] All stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
