
import os
import sys
import json
from pathlib import Path

# 프로젝트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.pnetlab import PnetlabClient
from config.settings import settings

def debug():
    client = PnetlabClient(settings.pnetlab.base_url)
    topology = client.get_session_topology()
    
    print("RAW TOPOLOGY KEYS:", topology.keys())
    if "data" in topology:
        print("DATA KEYS:", topology["data"].keys())
        nodes = topology["data"].get("nodes", {})
        print(f"FOUND {len(nodes)} NODES")
        if nodes:
            first_node_id = list(nodes.keys())[0]
            print(f"FIRST NODE ({first_node_id}) SAMPLE:")
            print(json.dumps(nodes[first_node_id], indent=2))

if __name__ == "__main__":
    debug()
