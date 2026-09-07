"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Native Desktop Application Launcher
"""

import os
import sys
import time
import threading
import webbrowser
from api.server import start_public_server

def run_server():
    start_public_server(host="127.0.0.1", port=8000)

def main():
    print("=" * 70)
    print("🚀 Launching QI-CTD Cyber Threat Detection Desktop Application...")
    print("=" * 70)

    # Start backend server in a background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    time.sleep(1.0)
    app_url = "http://127.0.0.1:8000/"
    print(f"Opening Native Application Window at: {app_url}")

    # Open system browser in app mode (Edge / Chrome)
    try:
        # Try launching Chrome or Edge in standalone app-window mode
        edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

        if os.path.exists(edge_path):
            os.system(f'start "" "{edge_path}" --app={app_url}')
        elif os.path.exists(chrome_path):
            os.system(f'start "" "{chrome_path}" --app={app_url}')
        else:
            webbrowser.open(app_url)
    except Exception:
        webbrowser.open(app_url)

    print("\n✓ QI-CTD Desktop App is running!")
    print("Press Ctrl+C in this terminal to close the application.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting QI-CTD Desktop Application. Goodbye!")

if __name__ == "__main__":
    main()
