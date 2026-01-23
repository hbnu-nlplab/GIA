"""
PNETLab API 기능 테스트

이 스크립트는 다음 항목을 테스트합니다:
1. 인증 (쿠키 기반)
2. 토폴로지 조회
3. 노드 상태 확인
4. 인터페이스 연결 상태 확인
"""
import logging
import sys
import os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from clients.pnetlab import PnetlabClient
from config.settings import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("test_pnetlab_api")

# Cookies from browser
COOKIES = {
    "privacy": "true",
    "token": "a8c9a13f-518f-4f82-9b0f-40c8b9772ce3",
    "XSRF-TOKEN": "eyJpdiI6IjBGK3RUOEMyVXo4cmc0bU5STVZvaXc9PSIsInZhbHVlIjoiMGhKeklMcUxIQTVNcmR6SmJhUHhZOHVyYkswT2F6WTVCbnIyYnpaSUk5SHQ2d2NCVnl6Mk5uUVlRMGUwNzh2eSIsIm1hYyI6ImFkZWFjNWUwNWY0YjI1Y2M5OGFmMDQ3NDliYTcwZTAwNTUzYTQ3MDY3YzMxYzNkZGRhNGJmNTE5MmU4YjY3NzYifQ%3D%3D",
    "_session": "eyJpdiI6ImRHbFpWUlY2RWJvSnEwWGJKNlVJWFE9PSIsInZhbHVlIjoia0x2TXFZdWk4V3p6amwxSFo0ZlIydHd2SE43ZDh1eXJwR0U1VVVEQXh5YkFTbGNsNGhaVkloRTB2NHlURGQ3KyIsIm1hYyI6Ijk1OWRmMzkzZTM5Yzc0YTVhMTkyYmE3OWU0M2I0YWU2ODAzMDRlOGUyZWNiMWFjZWUzYzM0OWViNjQ0OTM4NDgifQ%3D%3D"
}

def test_authentication():
    """테스트 1: 인증 확인"""
    logger.info("=" * 50)
    logger.info("TEST 1: 인증 (쿠키 기반)")
    
    client = PnetlabClient(settings.pnetlab.base_url)
    client.set_session_from_browser(COOKIES['token'], COOKIES['_session'], COOKIES['XSRF-TOKEN'])
    
    # 인증 확인: /api/labs/session/info 호출
    resp = client.session.get(f"{client.base_url}/api/labs/session/info")
    if resp.status_code == 200:
        data = resp.json()
        logger.info(f"✅ 인증 성공 - Lab: {data.get('data', {}).get('name', 'Unknown')}")
        return client, True
    else:
        logger.error(f"❌ 인증 실패: {resp.status_code}")
        return client, False

def test_topology_retrieval(client):
    """테스트 2: 토폴로지 조회"""
    logger.info("=" * 50)
    logger.info("TEST 2: 토폴로지 조회")
    
    topology = client.get_session_topology()
    if "error" not in topology:
        networks = topology.get("data", {}).get("networks", {})
        logger.info(f"✅ 네트워크 수: {len(networks)}")
        for net_id, net_info in networks.items():
            logger.info(f"   - ID {net_id}: {net_info.get('name')} ({net_info.get('type')})")
        return topology, True
    else:
        logger.error(f"❌ 토폴로지 조회 실패: {topology.get('error')}")
        return None, False

def test_node_status(client, topology):
    """테스트 3: 노드 상태 확인"""
    logger.info("=" * 50)
    logger.info("TEST 3: 노드 상태 확인")
    
    nodes = client.get_nodes_from_topology(topology)
    if nodes:
        logger.info(f"✅ 노드 수: {len(nodes)}")
        for node in nodes[:5]:  # 처음 5개만 표시
            status_map = {0: "Stopped", 2: "Running", 1: "Starting"}
            status = status_map.get(node.get('status'), 'Unknown')
            logger.info(f"   - {node.get('name')}: {status}")
        return nodes, True
    else:
        logger.error("❌ 노드 목록 비어있음")
        return [], False

def test_interface_connections(client):
    """테스트 4: 인터페이스 연결 상태 확인"""
    logger.info("=" * 50)
    logger.info("TEST 4: 인터페이스 연결 상태")
    
    # GET /api/labs/session/nodes to check ethernets
    resp = client.session.get(f"{client.base_url}/api/labs/session/nodes")
    if resp.status_code != 200:
        logger.error(f"❌ 노드 정보 조회 실패: {resp.status_code}")
        return False
    
    data = resp.json().get("data", {})
    connected_count = 0
    total_checked = 0
    
    for node_id, node_info in data.items():
        name = node_info.get("name", f"Node_{node_id}")
        ethernets = node_info.get("ethernets", {})
        
        # Check Gi0/0 (interface 0)
        iface_0 = ethernets.get("0", {})
        net_id = iface_0.get("network_id", 0)
        
        if net_id > 0:
            connected_count += 1
            logger.info(f"   ✅ {name} Gi0/0 → Network {net_id}")
        else:
            logger.warning(f"   ⚠️ {name} Gi0/0 → Not Connected")
        
        total_checked += 1
    
    logger.info(f"결과: {connected_count}/{total_checked} 노드 연결됨")
    return connected_count == total_checked

def main():
    logger.info("PNETLab API 기능 테스트 시작")
    logger.info("=" * 50)
    
    # Test 1: Authentication
    client, auth_ok = test_authentication()
    if not auth_ok:
        logger.error("인증 실패로 테스트 중단")
        return 1
    
    # Test 2: Topology
    topology, topo_ok = test_topology_retrieval(client)
    if not topo_ok:
        logger.error("토폴로지 조회 실패로 테스트 중단")
        return 1
    
    # Test 3: Node Status
    nodes, nodes_ok = test_node_status(client, topology)
    
    # Test 4: Interface Connections
    connections_ok = test_interface_connections(client)
    
    # Summary
    logger.info("=" * 50)
    logger.info("테스트 요약")
    logger.info(f"  인증: {'✅' if auth_ok else '❌'}")
    logger.info(f"  토폴로지: {'✅' if topo_ok else '❌'}")
    logger.info(f"  노드 상태: {'✅' if nodes_ok else '❌'}")
    logger.info(f"  인터페이스 연결: {'✅' if connections_ok else '❌'}")
    
    if auth_ok and topo_ok and nodes_ok and connections_ok:
        logger.info("🎉 모든 테스트 통과!")
        return 0
    else:
        logger.warning("⚠️ 일부 테스트 실패")
        return 1

if __name__ == "__main__":
    exit(main())
