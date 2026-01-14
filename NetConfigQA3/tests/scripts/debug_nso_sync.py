
import sys
import json
import logging
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))

from clients.nso import NSOClient
from config.settings import settings

logging.basicConfig(level=logging.INFO)

def debug_sync():
    client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    device = "P1"
    print(f"Debugging sync-from for {device}...")
    
    # Manual sync-from to see raw output
    path = f"tailf-ncs:devices/device={device}/sync-from"
    # We use _request directly to get raw response if possible, 
    # but _run_action processes it. Let's use _run_action but print result.
    
    try:
        response = client._request("POST", path)
        print("\n=== Raw Sync-from Response ===")
        print(json.dumps(response, indent=2, ensure_ascii=False))
        print("==============================\n")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    debug_sync()
