
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
    
    print("\n--- BGP Process Config Columns ---")
    try:
        bgp_proc = bf.q.bgpProcessConfiguration(nodes="pe1").answer().frame()
        print(bgp_proc.columns.tolist())
        if not bgp_proc.empty:
            print(bgp_proc[['Node', 'VRF']].to_dict(orient='records'))
            # Check for any column resembling Route Distinguisher
            rd_cols = [c for c in bgp_proc.columns if "Route_Distinguisher" in c or "RD" in c]
            print(f"Potential RD Columns: {rd_cols}")
    except Exception as e:
        print(f"BGP Proc Error: {e}")

if __name__ == "__main__":
    main()
