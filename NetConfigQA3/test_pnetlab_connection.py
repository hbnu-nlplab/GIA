"""
PNETLab 연결 테스트 스크립트
JWT 토큰으로 인증하고 Lab 토폴로지를 가져옵니다.
"""

import sys
import os
import logging

# 상위 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 로깅 설정 - DEBUG 레벨로 자세한 정보 확인
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from clients.pnetlab import PnetlabClient
from config.settings import settings
import json


def test_authentication():
    """인증 테스트"""
    print("=" * 60)
    print("1. PNETLab 인증 테스트")
    print("=" * 60)
    
    client = PnetlabClient(settings.pnetlab.base_url)
    
    if client.is_authenticated:
        print("✅ JWT 토큰 인증 성공!")
        print(f"   Base URL: {client.base_url}")
        return client
    else:
        print("❌ 인증 실패")
        print("   .env 파일에 PNETLAB_JWT_TOKEN이 설정되어 있는지 확인하세요.")
        return None


def test_topology(client: PnetlabClient):
    """토폴로지 조회 테스트"""
    print("\n" + "=" * 60)
    print("2. Lab 토폴로지 조회 테스트")
    print("=" * 60)
    
    try:
        topology = client.get_session_topology()
        
        if 'error' in topology:
            print(f"❌ 토폴로지 조회 실패: {topology['error']}")
            return None
        
        print("✅ 토폴로지 조회 성공!")
        print(f"   Lab 이름: {topology.get('name', 'N/A')}")
        print(f"   Lab 경로: {topology.get('path', 'N/A')}")
        
        return topology
        
    except Exception as e:
        print(f"❌ 에러 발생: {e}")
        return None


def test_nodes(client: PnetlabClient, topology: dict):
    """노드 정보 파싱 테스트"""
    print("\n" + "=" * 60)
    print("3. 노드 정보 파싱 테스트")
    print("=" * 60)
    
    try:
        nodes = client.get_nodes_from_topology(topology)
        
        print(f"✅ 총 {len(nodes)}개 노드 발견\n")
        
        for idx, node in enumerate(nodes, 1):
            print(f"  [{idx}] {node['name']}")
            print(f"      - Type: {node['type']}")
            print(f"      - Template: {node['template']}")
            print(f"      - Console: {node.get('console', 'N/A')}")
            print()
        
        return nodes
        
    except Exception as e:
        print(f"❌ 노드 파싱 실패: {e}")
        return []


def test_full_workflow():
    """전체 워크플로우 테스트"""
    print("\n" + "🔬 PNETLab 연결 테스트 시작\n")
    
    # 1. 인증
    client = test_authentication()
    if not client:
        return False
    
    # 2. 토폴로지 조회
    topology = test_topology(client)
    if not topology:
        return False
    
    # 3. 노드 파싱
    nodes = test_nodes(client, topology)
    if not nodes:
        return False
    
    # 4. 결과 요약
    print("=" * 60)
    print("✅ 모든 테스트 통과!")
    print("=" * 60)
    print(f"   - 인증: OK")
    print(f"   - 토폴로지 조회: OK")
    print(f"   - 노드 파싱: OK ({len(nodes)}개)")
    print()
    print("다음 단계: Inventory Builder 구현")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    success = test_full_workflow()
    sys.exit(0 if success else 1)

