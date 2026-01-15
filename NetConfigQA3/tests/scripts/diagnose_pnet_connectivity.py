
import os
import sys
import logging
import json
from pathlib import Path

# 프로젝트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.pnetlab import PnetlabClient
from config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def diagnose_topology():
    client = PnetlabClient(settings.pnetlab.base_url)
    
    # 세션 기반으로 토폴로지 가져오기
    logger.info("Retrieving topology...")
    topology = client.get_session_topology()
    
    if "data" not in topology:
        logger.error(f"Failed to get topology: {topology}")
        return

    nodes = topology["data"].get("nodes", {})
    networks = topology["data"].get("networks", {})
    
    logger.info(f"Summary: {len(nodes)} nodes, {len(networks)} networks found.")
    
    # 네트워크 상세 정보 출력 (특히 pnet2 관련)
    logger.info("\n--- Networks ---")
    pnet2_network_id = None
    for net_id, net in networks.items():
        logger.info(f"ID {net_id}: {net.get('name')} (Type: {net.get('type')})")
        if net.get('type') == 'pnet2':
            pnet2_network_id = int(net_id)
            logger.info(f"  >>> Found pnet2 network ID: {pnet2_network_id}")

    # 노드와 인터페이스 연결 상태 확인
    logger.info("\n--- Nodes & Interfaces ---")
    reachable_nodes = []
    unconnected_nodes = []
    
    for node_id, node in nodes.items():
        name = node.get("name")
        logger.info(f"Node {node_id}: {name}")
        
        # 실제 인터페이스 연결 확인
        # PNETLab API의 nodes 데이터 구조에서 인터페이스를 찾아야 함
        # 보통 get_session_topology의 결과에 인터페이스 정보가 포함됨
        
        interfaces = node.get("interfaces", {})
        mgmt_connected = False
        
        for if_id, if_data in interfaces.items():
            net_id = if_data.get("network_id")
            if net_id:
                logger.info(f"  Interface {if_id}: Connected to Network ID {net_id}")
                if pnet2_network_id is not None and int(net_id) == pnet2_network_id:
                    mgmt_connected = True
            else:
                logger.info(f"  Interface {if_id}: Disconnected")
                
        if mgmt_connected:
            reachable_nodes.append(name)
        else:
            unconnected_nodes.append(name)

    logger.info("\n--- Diagnosis Summary ---")
    logger.info(f"Nodes connected to PNET2: {reachable_nodes}")
    logger.info(f"Nodes NOT connected to PNET2: {unconnected_nodes}")
    
    if not pnet2_network_id:
        logger.warning("WARNING: No network of type 'pnet2' found in current lab session!")

if __name__ == "__main__":
    diagnose_topology()
