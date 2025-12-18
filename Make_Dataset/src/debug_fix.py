
import sys
from pathlib import Path
import logging

try:
    from core.batfish_builder import BatfishBuilder
except ImportError:
    # Add src directory to path if needed
    sys.path.append(str(Path(__file__).parent))
    from core.batfish_builder import BatfishBuilder

logging.basicConfig(level=logging.ERROR)

def test_traceroute_fix():
    snapshot_path = "C:/Users/Yujin/CodeSpace/GIA/Data/Pnetlab/Research_Institute_Internal_DC"
    
    # Initialize Batfish
    print(f"Initializing Batfish with snapshot: {snapshot_path}")
    bf = BatfishBuilder(snapshot_path=snapshot_path)
    if not bf.initialize():
        print("Failed to initialize Batfish")
        return

    # Test case from user: leaf1 to p4 (10.0.0.5)
    src_node = "leaf1"
    dst_ip = "10.0.0.5"
    dst_name = "p4" 
    
    print(f"\nRunning FIXED traceroute from {src_node} to {dst_ip} (target: {dst_name})")
    
    try:
        # Manually inspect what traceroute_path would see
        from pybatfish.datamodel import HeaderConstraints
        result = bf.bf.q.traceroute(
            startLocation=src_node,
            headers=HeaderConstraints(dstIps=dst_ip)
        ).answer().frame()
        
        if result.empty:
            print("Result is empty")
        else:
            traces = result['Traces'].iloc[0]
            if traces:
                trace = traces[0]
                disposition = getattr(trace, 'disposition', 'UNKNOWN')
                print(f"DEBUG: Trace 0 Disposition: '{disposition}'")
                
                path = []
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    node_name = getattr(node, 'hostname', str(node))
                    print(f"DEBUG: Hop: {node_name}")
                    path.append(node_name)
                    
                print(f"DEBUG: Current Path: {path}")
                print(f"DEBUG: Target Name: {dst_name}")
                
                # Replicate logic
                if dst_name and path[-1] != dst_name:
                    if disposition in ['DELIVERED_TO_SUBNET', 'ACCEPTED', 'EXITS_NETWORK', 'INSUFFICIENT_INFO']:
                        print("DEBUG: Condition met, appending target.")
                    else:
                        print(f"DEBUG: Condition NOT met. Disposition '{disposition}' not in allowed list.")
                else:
                    print("DEBUG: Path ends with target or target empty.")

        # Call the modified traceroute_path
        answer_type, path_str = bf.traceroute_path(src_node, dst_ip, target_name=dst_name)
        print(f"Result Path: {path_str}")
            
    except Exception as e:
        print(f"Error running traceroute_path: {e}")

if __name__ == "__main__":
    test_traceroute_fix()
