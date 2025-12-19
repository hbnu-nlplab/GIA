
import sys
from pathlib import Path
import pandas as pd
from pybatfish.client.session import Session

def get_batfish_session(snapshot_dir: str):
    bf = Session(host="localhost")
    bf.set_network("generate_dataset_network_debug_v3")
    bf.init_snapshot(snapshot_dir, name="dataset_snapshot_debug", overwrite=True)
    return bf

def main():
    lab_path = Path("Data/Pnetlab/Research_Institute_Internal_DC")
    bf = get_batfish_session(str(lab_path))
    
    print("Fetching OSPF Interface Configuration...")
    try:
        ospf_iface_df = bf.q.ospfInterfaceConfiguration().answer().frame()
        
        # Ensure Interface hostname extraction if Node missing
        if "Node" not in ospf_iface_df.columns and "Interface" in ospf_iface_df.columns:
            ospf_iface_df["Node"] = ospf_iface_df["Interface"].apply(lambda x: x.hostname)
            
        hostname = "p2"
        if "Node" in ospf_iface_df.columns:
            node_ospf_if = ospf_iface_df[ospf_iface_df["Node"] == hostname]
            print(f"\n--- Debugging OSPF for {hostname} ---")
            if not node_ospf_if.empty:
                for idx, row in node_ospf_if.iterrows():
                    print(f"\nRow {idx}:")
                    print(row.to_string())
            else:
                print("No OSPF rows for p2")
        else:
           print("Node column missing!")

    except Exception as e:
        print(f"EXCEPTION: {e}")

if __name__ == "__main__":
    main()
