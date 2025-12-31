
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
    
    # 1. Check available questions
    print("\n--- Available Questions (bf.q) ---")
    questions = [q for q in dir(bf.q) if not q.startswith("_")]
    print(", ".join(questions))
    
    # 2. Check OSPF columns
    print("\n--- OSPF Interface Columns ---")
    try:
        ospf_iface = bf.q.ospfInterfaceConfiguration(nodes="p1").answer().frame()
        print(ospf_iface.columns.tolist())
    except Exception as e:
        print(f"OSPF Error: {e}")

    # 3. Try to find VRF info in other tables if vrfProperties is missing
    print("\n--- Node Properties Columns (Checking for VRF info) ---")
    try:
        node_props = bf.q.nodeProperties(nodes="pe1").answer().frame()
        print([c for c in node_props.columns if "VRF" in c or "vrf" in c])
    except Exception as e:
        print(f"NodeProps Error: {e}")

if __name__ == "__main__":
    main()
