import os
import logging
from agent.clients.batfish import BatfishClient

logging.basicConfig(level=logging.INFO)

def debug_batfish():
    client = BatfishClient(host=os.getenv("BATFISH_HOST", "localhost"))
    if not client.is_available:
        print("Batfish not available")
        return

    client.load_snapshot("Research_Institute_Internal_DC")
    bf = client._builder.bf
    
    print("\n--- OSPF Session Compatibility ---")
    try:
        ospf = bf.q.ospfSessionCompatibility().answer().frame()
        print(f"Columns: {ospf.columns.tolist()}")
        print(f"Head:\n{ospf.head()}")
    except Exception as e:
        print(f"Failed: {e}")

    print("\n--- BGP Session Status ---")
    try:
        bgp = bf.q.bgpSessionStatus().answer().frame()
        print(f"Columns: {bgp.columns.tolist()}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    debug_batfish()
