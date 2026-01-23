
import os
import sys
import logging
import json
import time
from pathlib import Path

# 프로젝트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.pnetlab import PnetlabClient
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_connections():
    client = PnetlabClient(settings.pnetlab.base_url)
    
    # 1. 토폴로지 가져오기
    topology = client.get_session_topology()
    nodes = client.get_nodes_from_topology(topology)
    networks = topology.get("data", {}).get("networks", {})
    
    # 2. Mgmt-Cloud (pnet2) 찾기
    mgmt_net_id = None
    for net_id, net in networks.items():
        if net.get("type") == "pnet2" or net.get("name") == "Mgmt-Cloud":
            mgmt_net_id = int(net_id)
            logger.info(f"Found Management Network: {net.get('name')} (ID: {mgmt_net_id})")
            break
            
    if not mgmt_net_id:
        logger.error("Management network (pnet2) not found!")
        return

    # 3. 모든 노드 Gi0/0 (ID 0) 연결
    for node in nodes:
        node_id = int(node["id"])
        name = node["name"]
        
        # 노드가 실행 중이면 중지해야 연결 가능할 수 있음
        status = node.get("status")
        was_running = False
        if status == 2: # Running
            logger.info(f"Stopping node {name} (ID: {node_id}) before connecting...")
            client.stop_node(node_id)
            was_running = True
            time.sleep(2)
            
        logger.info(f"Connecting {name} Gi0/0 to Network {mgmt_net_id}...")
        res = client.connect_node_interface(node_id, 0, mgmt_net_id)
        
        if was_running:
            logger.info(f"Starting node {name} again...")
            client.start_node(node_id)
            
    logger.info("Connection fix complete!")

if __name__ == "__main__":
    fix_connections()
