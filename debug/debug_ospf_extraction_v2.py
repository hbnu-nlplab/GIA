
import sys
from pathlib import Path
import pandas as pd
from pybatfish.client.session import Session

def get_batfish_session(snapshot_dir: str):
    bf = Session(host="localhost")
    bf.set_network("generate_dataset_network_debug_v2") # Unique name
    bf.init_snapshot(snapshot_dir, name="dataset_snapshot_debug", overwrite=True)
    return bf

def main():
    lab_path = Path("Data/Pnetlab/Research_Institute_Internal_DC")
    print(f"Initializing Batfish with snapshot: {lab_path}")
    bf = get_batfish_session(str(lab_path))
    
    print("Fetching OSPF Interface Configuration...")
    try:
        ospf_iface_df = bf.q.ospfInterfaceConfiguration().answer().frame()
        
        print(f"DataFrame Shape: {ospf_iface_df.shape}")
        print(f"DataFrame Columns: {ospf_iface_df.columns.tolist()}")
        
        if not ospf_iface_df.empty:
            print("\nFirst 5 rows:")
            print(ospf_iface_df.head().to_string())
            
            hostname = "p1"
            if "Node" in ospf_iface_df.columns:
                node_ospf_if = ospf_iface_df[ospf_iface_df["Node"] == hostname]
                print(f"\n--- Debugging OSPF for {hostname} ---")
                print(f"Found {len(node_ospf_if)} rows for {hostname}")
                print(node_ospf_if.to_string())
            else:
               print("Node column missing!")
        else:
            print("OSPF Interface DataFrame is EMPTY.")
            
            # Check init issues
            print("\n--- Init Issues ---")
            issues = bf.q.initIssues().answer().frame()
            print(issues.to_string())

    except Exception as e:
        print(f"EXCEPTION: {e}")

if __name__ == "__main__":
    main()
