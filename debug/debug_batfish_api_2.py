
import sys
from pathlib import Path
import pandas as pd
from pybatfish.client.session import Session

def get_batfish_session(snapshot_dir: str):
    bf = Session(host="localhost")
    bf.set_network("generate_dataset_network")
    bf.init_snapshot(snapshot_dir, name="dataset_snapshot", overwrite=True)
    return bf

def main():
    lab_path = Path("Data/Pnetlab/Research_Institute_Internal_DC")
    bf = get_batfish_session(str(lab_path))
    
    # 1. Check available questions (clean print)
    print("\n--- Available Questions (bf.q) ---")
    questions = sorted([q for q in dir(bf.q) if not q.startswith("_")])
    for q in questions:
        if "vrf" in q.lower():
            print(f"Found VRF question: {q}")
    
    # 2. Check OSPF columns cleanly
    print("\n--- OSPF Interface Columns ---")
    try:
        ospf_iface = bf.q.ospfInterfaceConfiguration(nodes="p1").answer().frame()
        print(ospf_iface.columns.tolist())
        # Print first row as dictionary to see actual values
        if not ospf_iface.empty:
            print(ospf_iface.iloc[0].to_dict())
    except Exception as e:
        print(f"OSPF Error: {e}")

    # 3. Check BGP Process Configuration for VRF details
    print("\n--- BGP Process Config Columns ---")
    try:
        bgp_proc = bf.q.bgpProcessConfiguration(nodes="pe1").answer().frame()
        print(bgp_proc.columns.tolist())
        # Check if VRF details are here
        if not bgp_proc.empty:
            print(bgp_proc.iloc[0].to_dict())
    except Exception as e:
        print(f"BGP Proc Error: {e}")

if __name__ == "__main__":
    main()
