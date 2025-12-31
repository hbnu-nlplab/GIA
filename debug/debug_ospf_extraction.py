
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
    
    print("Fetching OSPF Interface Configuration...")
    ospf_iface_df = bf.q.ospfInterfaceConfiguration().answer().frame()
    
    hostname = "p1"
    print(f"\n--- Debugging OSPF for {hostname} ---")
    
    if not ospf_iface_df.empty and "Node" in ospf_iface_df.columns:
        node_ospf_if = ospf_iface_df[ospf_iface_df["Node"] == hostname]
        print(f"Found {len(node_ospf_if)} rows for {hostname}")
        
        for idx, row in node_ospf_if.iterrows():
            iface = row["Interface"].interface
            enabled = row.get("OSPF_Enabled")
            area_name = row.get("OSPF_Area_Name")
            area_id = row.get("OSPF_Area")
            
            print(f"Iface: {iface}")
            print(f"  Enabled: {enabled} (Type: {type(enabled)})")
            print(f"  Area Name: {area_name}")
            print(f"  Area ID: {area_id}")
            
            # Replicating logic
            if enabled:
                area = str(area_name or area_id)
                print(f"  -> Extracted Area: {area}")
            else:
                print(f"  -> OSPF not enabled")
    else:
        print("OSPF DataFrame empty or missing Node column")

if __name__ == "__main__":
    main()
