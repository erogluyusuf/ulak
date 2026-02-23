import sys
import os
import threading
import time
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

def start_dashboard():

    print("[INFO] Launching Dashboard Backend...")
    app_path = os.path.join(BASE_DIR, "dashboard", "app.py")

    subprocess.run([sys.executable, app_path])

def start_ebpf_handler():

    print("[INFO] Activating eBPF Kernel Hooks...")
    handler_path = os.path.join(BASE_DIR, "ebpf", "handler.py")

    subprocess.run([sys.executable, handler_path])

def main():
    print("=" * 60)
    print(f"{'ULAK AI - SYSTEM SERVICE ORCHESTRATOR':^60}")
    print("=" * 60)

    dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
    dashboard_thread.start()

    time.sleep(2)

    try:
        start_ebpf_handler()
    except KeyboardInterrupt:
        print("\n[INFO] ULAK is stopping...")
        sys.exit(0)

if __name__ == "__main__":
    main()
