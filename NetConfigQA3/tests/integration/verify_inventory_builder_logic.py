from pathlib import Path
"""
Inventory Builder 테스트
PNETLab 토폴로지를 device_info.json으로 변환합니다.
"""

import sys
import os
import logging

sys.path.insert(0, str(Path(__file__).parents[2]))

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from clients.pnetlab import PnetlabClient
from inventory.builder import InventoryBuilder, build_inventory_from_pnetlab
from config.settings import settings
import json


def test_inventory_builder():
    """전체 워크플로우 테스트"""
    print("\n" + "=" * 60)
    print("🏗️  Inventory Builder 테스트")
    print("=" * 60)
    
    # 1. PNETLab에서 토폴로지 가져오기
    print("\n[1/3] PNETLab 토폴로지 조회...")
    client = PnetlabClient(settings.pnetlab.base_url)
    
    if not client.is_authenticated:
        print("❌ 인증 실패 - .env 파일 확인 필요")
        return False
    
    topology = client.get_session_topology()
    if 'error' in topology:
        print(f"❌ 토폴로지 조회 실패: {topology['error']}")
        return False
    
    # 디버깅: Lab 정보 확인
    print(f"\n[디버그] Topology 메타데이터:")
    if 'data' in topology:
        data = topology['data']
        print(f"   - name: {data.get('name', 'N/A')}")
        print(f"   - path: {data.get('path', 'N/A')}")
        print(f"   - author: {data.get('author', 'N/A')}")
        
        # 전체 키 출력
        print(f"\n   전체 키: {list(data.keys())[:10]}")
        
        # Lab 관련 필드 찾기
        lab_fields = [k for k in data.keys() if 'lab' in k.lower() or 'name' in k.lower() or 'path' in k.lower()]
        if lab_fields:
            print(f"   Lab 관련 필드:")
            for field in lab_fields:
                print(f"      - {field}: {data.get(field)}")
    
    nodes = client.get_nodes_from_topology(topology)
    print(f"✅ {len(nodes)}개 노드 발견")
    
    # Lab 이름 추출
    data = topology.get('data', {})
    labinfo = data.get('labinfo', {})
    
    # labinfo에서 name 또는 filename 추출
    lab_name = labinfo.get('name') or labinfo.get('filename', '').replace('.unl', '')
    
    # fallback: 다른 필드 시도
    if not lab_name:
        lab_name = data.get('name') or data.get('path', '').replace('/', '').replace('.unl', '')
    
    # 최종 fallback
    if not lab_name:
        lab_name = "default_lab"
    
    print(f"   Lab 이름: {lab_name}")
    
    # 디버깅: 노드 상세 정보 출력
    print("\n[디버그] 노드 상세 정보:")
    for node in nodes:
        print(f"  - {node['name']}: status={node['status']}, url='{node['url']}', telnet_port={node['telnet_port']}")
    
    # Console Link API로 telnet 포트 가져오기
    if nodes and nodes[0]['url'] == 'guacamole':
        print("\n[디버그] Guacamole 모드 감지! Console Link API로 telnet 포트 조회...")
        telnet_ports = {}  # node_id -> telnet_port 매핑
        
        for node in nodes[:3]:  # 처음 3개만 테스트
            console_link = client.get_console_link(int(node['id']))
            if 'error' not in console_link and 'data' in console_link:
                guac_link = console_link['data']
                print(f"  - {node['name']} (id={node['id']}): {guac_link[:80]}...")
                
                # Base64 디코딩으로 telnet 포트 추출
                port = client.extract_telnet_port_from_guacamole(guac_link)
                if port:
                    print(f"    ✅ Telnet 포트 발견: {port}")
                    telnet_ports[node['id']] = port
                    node['telnet_port'] = port  # 노드 정보 업데이트
                else:
                    print(f"    ❌ 포트 추출 실패")
            else:
                print(f"  - {node['name']}: API 호출 실패")
        
        # 모든 노드에 대해 포트 조회
        if telnet_ports:
            print(f"\n✅ {len(telnet_ports)}개 노드의 telnet 포트 추출 성공!")
            print("   나머지 노드들도 조회 중...")
            for node in nodes[3:]:
                console_link = client.get_console_link(int(node['id']))
                if 'error' not in console_link and 'data' in console_link:
                    port = client.extract_telnet_port_from_guacamole(console_link['data'])
                    if port:
                        telnet_ports[node['id']] = port
                        node['telnet_port'] = port
            
            print(f"   총 {len(telnet_ports)}/{len(nodes)}개 포트 추출 완료")
    
    # 노드 상태 API 호출
    print("\n[디버그] 노드 상태 API 호출...")
    status_result = client.get_nodes_status()
    if 'error' not in status_result:
        print(f"✅ 노드 상태 조회 성공")
        print(f"   응답 키: {list(status_result.keys())}")
        if 'data' in status_result:
            print(f"   데이터: {json.dumps(status_result['data'], indent=2)[:500]}")
    else:
        print(f"⚠️  노드 상태 조회 실패: {status_result['error']}")
    
    # 2. Inventory Builder로 변환
    print("\n[2/3] device_info.json 형식으로 변환...")
    print(f"   Device Group: {lab_name}")
    
    builder = InventoryBuilder(
        pnetlab_vm_ip=settings.pnetlab.base_url.split('//')[1].split(':')[0],
        lab_name=lab_name  # 실제 Lab 이름 사용!
    )
    
    for node in nodes:
        builder.add_node(node)
    
    inventory = builder.build()
    print(f"✅ 인벤토리 생성 완료")
    print(f"   - Global Settings: ✓")
    print(f"   - Devices: {len(inventory.devices)}개")
    
    # 3. 결과 출력
    print("\n[3/3] 생성된 인벤토리:")
    print("=" * 60)
    print(inventory.to_json())
    print("=" * 60)
    
    # 4. 파일로 저장 (옵션)
    output_path = "device_info_generated.json"
    inventory.save(output_path)
    print(f"\n✅ 인벤토리 파일 저장: {output_path}")
    
    # 5. 기존 device_info.json과 비교
    print("\n" + "=" * 60)
    print("📊 기존 파일과 비교")
    print("=" * 60)
    
    existing_path = "Data/Pnetlab/Research_Institute_Internal_DC/device_info.json"
    if os.path.exists(existing_path):
        with open(existing_path, 'r', encoding='utf-8') as f:
            existing = json.load(f)
        
        print(f"기존 장비 수: {len(existing.get('devices', []))}")
        print(f"새로 생성된 장비 수: {len(inventory.devices)}")
        
        # 장비 이름 비교
        existing_names = {d['name'] for d in existing.get('devices', [])}
        new_names = {d.name for d in inventory.devices}
        
        if existing_names == new_names:
            print("✅ 장비 목록 일치")
        else:
            print(f"⚠️  장비 목록 차이:")
            print(f"   - 기존에만 있음: {existing_names - new_names}")
            print(f"   - 새로 추가됨: {new_names - existing_names}")
    
    print("\n" + "=" * 60)
    print("✅ 테스트 완료!")
    print("=" * 60)
    print("\n다음 단계:")
    print("1. Telnet 포트 정보 보완 (PNETLab API에서 추출)")
    print("2. NSO 자동 등록 구현")
    print("3. Agent 도구 통합")
    
    return True


if __name__ == "__main__":
    success = test_inventory_builder()
    sys.exit(0 if success else 1)

