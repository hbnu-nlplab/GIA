#!/usr/bin/env python3
"""
End-to-End NSO Integration Test

통합 워크플로우:
1. PNETLab 토폴로지 조회
2. 모든 장비 시작
3. SSH 설정 (Day0)
4. NSO 등록
5. Sync 검증

사용법:
    python3 test_end_to_end.py
    python3 test_end_to_end.py --skip-ssh  # SSH 이미 설정된 경우
"""

import asyncio
import logging
import sys
import argparse
from pathlib import Path

# 프로젝트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from clients.pnetlab import PnetlabClient
from clients.nso import NSOClient
from config.settings import settings
from inventory.builder import InventoryBuilder

# 기존 legacy 모듈 재사용
from tests.legacy.ssh_enabler import SSHEnabler
from tests.legacy.nso_onboarder import NSOOnboarder

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("e2e_test")


def print_banner(msg: str):
    """배너 출력"""
    print(f"\n{'='*70}")
    print(f"  {msg}")
    print(f"{'='*70}\n")


async def run_end_to_end_test(skip_ssh: bool = False, device_filter: str = None):
    """
    End-to-End 통합 테스트 실행
    
    Args:
        skip_ssh: SSH 설정 스킵 여부
        device_filter: 장비 이름 필터 (예: "vIOS" - vIOS로 시작하는 장비만)
    """
    print_banner("PNETLab → NSO End-to-End Integration Test")
    
    # ========== 1. 클라이언트 초기화 ==========
    logger.info("[1/6] 클라이언트 초기화...")
    
    pnetlab = PnetlabClient(settings.pnetlab.base_url)
    
    # 쿠키 인증 확인
    if not pnetlab._is_authenticated:
        logger.error("❌ PNETLab 인증 실패! .env에 PNETLAB_COOKIES 설정 필요")
        return {"status": "failed", "error": "PNETLab not authenticated"}
    
    nso = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    logger.info(f"  - PNETLab: {settings.pnetlab.base_url}")
    logger.info(f"  - NSO: {settings.nso.base_url}")
    
    # ========== 2. 토폴로지 조회 ==========
    logger.info("\n[2/6] PNETLab 토폴로지 조회...")
    
    topology = pnetlab.get_session_topology()
    if "error" in topology:
        logger.error(f"❌ 토폴로지 조회 실패: {topology['error']}")
        return {"status": "failed", "error": topology["error"]}
    
    nodes = pnetlab.get_nodes_from_topology(topology)
    
    # 필터 적용
    if device_filter:
        nodes = [n for n in nodes if device_filter in n["name"]]
        logger.info(f"  - 필터 적용: '{device_filter}' → {len(nodes)}개 장비")
    else:
        logger.info(f"  - 발견된 장비: {len(nodes)}개")
    
    if not nodes:
        logger.error("❌ 장비가 없습니다")
        return {"status": "failed", "error": "No devices found"}
    
    for n in nodes[:5]:
        logger.info(f"    • {n['name']} (ID: {n['id']}, Status: {n.get('status')})")
    if len(nodes) > 5:
        logger.info(f"    ... 외 {len(nodes) - 5}개")
    
    # ========== 3. 모든 장비 시작 ==========
    logger.info("\n[3/6] 장비 시작...")
    
    started = []
    already_running = []
    failed_start = []
    
    for node in nodes:
        name = node["name"]
        node_id = int(node["id"])
        status = node.get("status", 0)
        
        if status == 2:  # 이미 실행 중
            already_running.append(name)
        else:
            if pnetlab.start_node(node_id):
                started.append(name)
            else:
                failed_start.append(name)
    
    logger.info(f"  ✅ 시작됨: {len(started)}개")
    logger.info(f"  ℹ️  이미 실행 중: {len(already_running)}개")
    if failed_start:
        logger.warning(f"  ❌ 시작 실패: {failed_start}")
    
    # 장비 부팅 대기 (Status Polling)
    if started or already_running:
        logger.info(f"  ⏳ 장비 부팅 확인 중... (최대 60초)")
        
        all_running = False
        for _ in range(12):  # 5초 * 12회 = 60초
            status_data = pnetlab.get_nodes_status()
            if "error" in status_data:
                logger.warning("  ⚠️  상태 조회 실패, 재시도...")
            else:
                # { "node_id": status_code, ... }
                # status: 2 = Running
                running_count = 0
                target_nodes = started + already_running
                
                for node in nodes:
                    if node["name"] in target_nodes:
                        nid = str(node["id"])
                        if str(status_data.get(nid, 0)) == "2":
                            running_count += 1
                
                if running_count == len(target_nodes):
                    logger.info(f"  ✅ 모든 대상 장비({running_count}개) 실행 중 확인 완료")
                    all_running = True
                    break
                else:
                    logger.debug(f"  ... {running_count}/{len(target_nodes)} 실행 중")
            
            await asyncio.sleep(5)
        
        if not all_running:
            logger.warning("  ⚠️  일부 장비가 아직 실행 상태(2)가 아닐 수 있습니다.")
        
        # 부팅 안정화 추가 대기
        logger.info("  ⏳ OS 부팅 안정화 대기 (15초)...")
        await asyncio.sleep(15)
    
    # ========== 4. 인벤토리 생성 ==========
    logger.info("\n[4/6] 인벤토리 생성...")
    
    # Lab 이름 추출
    lab_info = topology.get("data", {}).get("labinfo", {})
    lab_name = lab_info.get("name") or "default_lab"
    
    # VM IP 추출
    from urllib.parse import urlparse
    pnetlab_vm_ip = urlparse(settings.pnetlab.base_url).hostname
    
    # 빌더로 인벤토리 생성
    builder = InventoryBuilder(pnetlab_vm_ip=pnetlab_vm_ip, lab_name=lab_name)
    
    # Telnet 포트 추출 (Guacamole)
    for node in nodes:
        node_id = int(node.get("id", 0))
        if node_id > 0:
            console_link = pnetlab.get_console_link(node_id)
            if "data" in console_link:
                port = pnetlab.extract_telnet_port_from_guacamole(console_link["data"])
                if port:
                    node["telnet_port"] = port
        builder.add_node(node)
    
    inventory = builder.build()
    inventory_dict = inventory.to_dict()

    # 인벤토리 파일 저장 (사용자 확인용)
    import json
    inventory_file = Path(__file__).parent.parent.parent / "device_info_generated.json"
    with open(inventory_file, 'w', encoding='utf-8') as f:
        json.dump(inventory_dict, f, indent=2, ensure_ascii=False)
    logger.info(f"  ✅ 인벤토리 파일 저장: {inventory_file}")
    
    logger.info(f"  ✅ 인벤토리 생성: {len(inventory.devices)}개 장비")
    
    # ========== 5. SSH 설정 ==========
    ssh_results = {"success": [], "failed": []}
    
    if not skip_ssh:
        logger.info("\n[5/6] SSH 설정 (Day0)...")
        
        enabler = SSHEnabler(inventory_dict)
        ssh_results = await enabler.configure_all_devices()
        
        logger.info(f"  ✅ SSH 성공: {len(ssh_results['success'])}개")
        if ssh_results["failed"]:
            logger.warning(f"  ❌ SSH 실패: {ssh_results['failed']}")
    else:
        logger.info("\n[5/6] SSH 설정 스킵 (--skip-ssh)")
        ssh_results["success"] = [d.name for d in inventory.devices]
    
    # ========== 6. NSO 등록 ==========
    logger.info("\n[6/6] NSO 등록 및 동기화...")
    
    onboarder = NSOOnboarder(inventory_dict, nso_client=nso)
    nso_results = onboarder.register_all_devices()
    
    logger.info(f"  ✅ 등록 성공: {len(nso_results['registered'])}개")
    logger.info(f"  ✅ Sync 성공: {len(nso_results['synced'])}개")
    
    if nso_results["failed_register"]:
        logger.warning(f"  ❌ 등록 실패: {nso_results['failed_register']}")
    if nso_results["failed_sync"]:
        logger.warning(f"  ❌ Sync 실패: {nso_results['failed_sync']}")
    
    # ========== 최종 결과 ==========
    total = len(nodes)
    synced = len(nso_results['synced'])
    
    if synced == total:
        status = "SUCCESS"
        icon = "✅"
    elif synced > 0:
        status = "PARTIAL"
        icon = "⚠️"
    else:
        status = "FAILED"
        icon = "❌"
    
    print_banner(f"{icon} End-to-End Test: {status}")
    
    print(f"Lab: {lab_name}")
    print(f"장비 수: {total}")
    print(f"시작: {len(started) + len(already_running)}/{total}")
    print(f"SSH: {len(ssh_results['success'])}/{total}")
    print(f"NSO 등록: {len(nso_results['registered'])}/{total}")
    print(f"NSO Sync: {synced}/{total}")
    
    return {
        "status": status.lower(),
        "lab_name": lab_name,
        "total": total,
        "started": len(started) + len(already_running),
        "ssh": ssh_results,
        "nso": nso_results
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="End-to-End NSO Integration Test")
    parser.add_argument("--skip-ssh", action="store_true", help="SSH 설정 스킵")
    parser.add_argument("--filter", type=str, default=None, help="장비 이름 필터 (예: vIOS)")
    args = parser.parse_args()
    
    result = asyncio.run(run_end_to_end_test(
        skip_ssh=args.skip_ssh,
        device_filter=args.filter
    ))
    
    print(f"\n최종 결과: {result['status']}")
