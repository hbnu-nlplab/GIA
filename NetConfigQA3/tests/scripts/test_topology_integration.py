"""
PNETLab 토폴로지 관리 통합 테스트 (수정됨)

핵심 변경: 생성 후 토폴로지 조회하여 실제 노드 ID 확인

시나리오:
1. 장비 6개 생성 (vIOS10-15)
2. vIOS14, 15 삭제
3. 클라우드 2개 생성 (CloudA, CloudB)
4. vIOS10, 12 → CloudA 연결
5. vIOS11, 13 → CloudB 연결
6. vIOS12, 13 연결 해제

각 단계마다 30초 대기
"""
import logging
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from clients.pnetlab import PnetlabClient
from config.settings import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("topology_integration_test")



WAIT_TIME = 30  # 각 단계 사이 대기 시간 (초)

def wait_step(step_name):
    """단계 사이 대기"""
    logger.info(f"--- {step_name} 완료. {WAIT_TIME}초 대기 중... ---")
    time.sleep(WAIT_TIME)

def get_node_by_name(client, name):
    """토폴로지에서 이름으로 노드 찾기"""
    topology = client.get_session_topology()
    nodes = client.get_nodes_from_topology(topology)
    for n in nodes:
        if n.get("name") == name:
            return n
    return None

def get_network_by_name(client, name):
    """토폴로지에서 이름으로 네트워크 찾기"""
    topology = client.get_session_topology()
    networks = topology.get("data", {}).get("networks", {})
    for net_id, net_info in networks.items():
        if net_info.get("name") == name:
            return {"id": int(net_id), **net_info}
    return None

def main():
    logger.info("=" * 70)
    logger.info("PNETLab 토폴로지 관리 통합 테스트")
    logger.info("=" * 70)
    
    # 클라이언트 초기화
    client = PnetlabClient(settings.pnetlab.base_url)
    
    if not client.is_authenticated:
        if settings.pnetlab.jwt_token:
            client.set_session_from_browser(
                token=settings.pnetlab.jwt_token,
                session=settings.pnetlab.session,
                xsrf=settings.pnetlab.xsrf_token
            )
        else:
            logger.warning("No cookies found in settings! Check .env (PNETLAB_JWT_TOKEN, etc)")
    
    # ========== STEP 1: 장비 6개 생성 ==========
    logger.info("\n" + "=" * 70)
    logger.info("STEP 1: 장비 6개 생성 (vIOS10-15)")
    logger.info("=" * 70)
    
    node_names = [f"vIOS{i}" for i in range(10, 16)]
    for i, name in enumerate(node_names):
        logger.info(f"\n--- 장비 {name} 생성 중... ---")
        result = client.add_node(
            name=name,
            template="vios",
            left=100 + i * 120,
            top=500
        )
        if "error" not in result:
            logger.info(f"✅ {name} 생성됨")
        else:
            logger.error(f"❌ {name} 생성 실패: {result.get('error')}")
            logger.error(f"❌ {name} 생성 실패: {result.get('error')}")
    
    # 생성 확인 후 시작
    logger.info("모든 장비 시작 요청...")
    for name in node_names:
        node = get_node_by_name(client, name)
        if node:
            node_id = int(node["id"])
            logger.info(f"Starting node {name} (ID: {node_id})...")
            if client.start_node(node_id):
                logger.info(f"✅ {name} 시작됨")
            else:
                logger.error(f"❌ {name} 시작 실패")
        else:
            logger.error(f"❌ {name} 찾을 수 없음")

    wait_step("STEP 1")
    
    # ========== STEP 2: vIOS14, 15 삭제 ==========
    logger.info("\n" + "=" * 70)
    logger.info("STEP 2: vIOS14, 15 삭제")
    logger.info("=" * 70)
    
    for name in ["vIOS14", "vIOS15"]:
        node = get_node_by_name(client, name)
        if node:
            node_id = int(node["id"])
            logger.info(f"\n--- {name} (ID: {node_id}) 삭제 중... ---")
            
            # Stop if running
            logger.info("Stopping node...")
            client.stop_node(node_id)
            
            if client.delete_node(node_id):
                logger.info(f"✅ {name} 삭제됨")
            else:
                logger.error(f"❌ {name} 삭제 실패")
        else:
            logger.error(f"❌ {name} 찾을 수 없음")
    
    wait_step("STEP 2")
    
    # ========== STEP 3: 클라우드 2개 생성 ==========
    logger.info("\n" + "=" * 70)
    logger.info("STEP 3: 클라우드 2개 생성 (CloudA, CloudB)")
    logger.info("=" * 70)
    
    for i, cloud_name in enumerate(["CloudA", "CloudB"]):
        logger.info(f"\n--- {cloud_name} 생성 중... ---")
        result = client.add_network(
            name=cloud_name,
            net_type="pnet2",
            left=300 + i * 300,
            top=150
        )
        if "error" not in result:
            logger.info(f"✅ {cloud_name} 생성됨")
        else:
            logger.error(f"❌ {cloud_name} 생성 실패: {result.get('error')}")
    
    wait_step("STEP 3")
    
    # ========== STEP 4: vIOS10, 12 → CloudA 연결 ==========
    logger.info("\n" + "=" * 70)
    logger.info("STEP 4: vIOS10, 12 → CloudA 연결")
    logger.info("=" * 70)
    
    cloud_a = get_network_by_name(client, "CloudA")
    if cloud_a:
        for name in ["vIOS10", "vIOS12"]:
            node = get_node_by_name(client, name)
            if node:
                node_id = int(node["id"])
                logger.info(f"\n--- {name} (ID: {node_id}) → CloudA (ID: {cloud_a['id']}) 연결 중... ---")
                if client.connect_node_interface(node_id, 0, cloud_a["id"]):
                    logger.info(f"✅ {name} → CloudA 연결됨")
                else:
                    logger.error(f"❌ {name} 연결 실패")
            else:
                logger.error(f"❌ {name} 찾을 수 없음")
    else:
        logger.error("❌ CloudA 찾을 수 없음")
    
    wait_step("STEP 4")
    
    # ========== STEP 5: vIOS11, 13 → CloudB 연결 ==========
    logger.info("\n" + "=" * 70)
    logger.info("STEP 5: vIOS11, 13 → CloudB 연결")
    logger.info("=" * 70)
    
    cloud_b = get_network_by_name(client, "CloudB")
    if cloud_b:
        for name in ["vIOS11", "vIOS13"]:
            node = get_node_by_name(client, name)
            if node:
                node_id = int(node["id"])
                logger.info(f"\n--- {name} (ID: {node_id}) → CloudB (ID: {cloud_b['id']}) 연결 중... ---")
                if client.connect_node_interface(node_id, 0, cloud_b["id"]):
                    logger.info(f"✅ {name} → CloudB 연결됨")
                else:
                    logger.error(f"❌ {name} 연결 실패")
            else:
                logger.error(f"❌ {name} 찾을 수 없음")
    else:
        logger.error("❌ CloudB 찾을 수 없음")
    
    wait_step("STEP 5")
    
    # ========== STEP 6: vIOS12, 13 연결 해제 ==========
    logger.info("\n" + "=" * 70)
    logger.info("STEP 6: vIOS12, 13 연결 해제")
    logger.info("=" * 70)
    
    for name in ["vIOS12", "vIOS13"]:
        node = get_node_by_name(client, name)
        if node:
            node_id = int(node["id"])
            logger.info(f"\n--- {name} (ID: {node_id}) 연결 해제 중... ---")
            if client.connect_node_interface(node_id, 0, 0):  # network_id=0 = disconnect
                logger.info(f"✅ {name} 연결 해제됨")
            else:
                logger.error(f"❌ {name} 연결 해제 실패")
        else:
            logger.error(f"❌ {name} 찾을 수 없음")
    
    # ========== 최종 요약 ==========
    logger.info("\n" + "=" * 70)
    logger.info("통합 테스트 완료!")
    logger.info("=" * 70)
    logger.info("\nPNETLab UI에서 토폴로지를 확인하세요:")
    logger.info("  - vIOS10, vIOS11, vIOS12, vIOS13 존재")
    logger.info("  - vIOS14, vIOS15 삭제됨")
    logger.info("  - CloudA, CloudB 존재")
    logger.info("  - vIOS10 → CloudA 연결")
    logger.info("  - vIOS11 → CloudB 연결")
    logger.info("  - vIOS12, vIOS13 연결 해제 상태")

if __name__ == "__main__":
    main()
