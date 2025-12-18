
import sys
from pathlib import Path
import logging

try:
    from core.batfish_builder import BatfishBuilder
except ImportError:
    # Add src directory to path if needed
    sys.path.append(str(Path(__file__).parent))
    from core.batfish_builder import BatfishBuilder

logging.basicConfig(level=logging.ERROR) # Reduce log noise

def test_traceroute():
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
    
    print(f"\nRunning traceroute from {src_node} to {dst_ip}")
    
    # Run raw traceroute
    try:
        from pybatfish.datamodel import HeaderConstraints
        result = bf.bf.q.traceroute(
            startLocation=src_node,
            headers=HeaderConstraints(dstIps=dst_ip)
        ).answer().frame()
        
        if result.empty:
            print("Result is empty")
        else:
            traces = result['Traces'].iloc[0]
            for i, trace in enumerate(traces):
                print(f"Trace {i} Disposition: {trace.disposition}")
                path = []
                for hop in trace.hops:
                    node = getattr(hop, 'node', None)
                    node_name = getattr(node, 'hostname', str(node))
                    path.append(node_name)
                    
                    # Print steps for the last hop to see why it stops
                    if hop == trace.hops[-1]:
                        print(f"  Last Hop ({node_name}) Steps:")
                        for step in hop.steps:
                            if step.action in ['DROPPED', 'DENIED', 'NO_ROUTE', 'FORWARDED', 'TRANSMITTED']:
                                print(f"    - {step.action} {step.detail.get('routes', [{}])[0].get('network', 'N/A') if hasattr(step.detail, 'get') else ''}")

                print(f"Path: {' -> '.join(path)}")
                
    except Exception as e:
        print(f"Error running raw traceroute: {e}")

if __name__ == "__main__":
    test_traceroute()
