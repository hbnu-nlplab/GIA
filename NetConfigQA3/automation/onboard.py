"""
Auto Onboard - 통합 워크플로우

PNETLab Lab을 NSO에 완전 자동으로 등록하는 통합 워크플로우

워크플로우:
1. PNETLab Topology 조회
2. Inventory 생성
3. SSH 설정 (Day0)
4. NSO 등록
5. 검증
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def _extract_host_from_base_url(base_url: str) -> str:
    """
    http(s)://host[:port] 형태에서 host만 추출합니다.
    """
    try:
        parsed = urlparse(base_url)
        return parsed.hostname or base_url
    except Exception:
        return base_url


async def auto_onboard_lab(
    pnetlab_client,
    nso_client,
    lab_name: Optional[str] = None,
    skip_ssh: bool = False,
    save_inventory: bool = True
) -> Dict[str, Any]:
    """
    PNETLab Lab을 NSO에 자동 등록
    
    Args:
        pnetlab_client: PNETLabClient 인스턴스
        nso_client: NSOClient 인스턴스
        lab_name: Lab 이름 (None이면 자동 감지)
        skip_ssh: SSH 설정 스킵 여부 (이미 설정된 경우)
        save_inventory: Inventory 파일 저장 여부
        
    Returns:
        {
            "lab_name": "PH1_L3VPN_GOLDEN",
            "total_devices": 6,
            "ssh_results": {"success": [...], "failed": [...]},
            "nso_results": {"registered": [...], "synced": [...], ...},
            "verify_results": {"in_sync": [...], "out_of_sync": [...]},
            "status": "completed" | "partial" | "failed"
        }
    """
    from .ssh_enabler import SSHEnabler
    from .nso_onboarder import NSOOnboarder
    
    logger.info(f"\n{'='*70}")
    logger.info("자동 온보딩 시작")
    logger.info(f"{'='*70}\n")
    
    try:
        # 1. PNETLab Topology 조회
        logger.info(f"[1/5] PNETLab Topology 조회 중...")
        topology = pnetlab_client.get_session_topology()

        if not isinstance(topology, dict):
            logger.error("❌ Topology 조회 실패 (응답 형식이 dict가 아님)")
            return {"status": "failed", "error": f"Invalid topology response type: {type(topology)}"}

        if topology.get("error") == "Not authenticated":
            logger.error("❌ PNETLab 인증 실패: PNETLAB_COOKIES가 설정되지 않았거나 유효하지 않습니다.")
            return {
                "status": "failed",
                "error": (
                    "PNETLab not authenticated. "
                    "브라우저에서 쿠키를 복사해 `NetConfigQA3/config/.env`에 `PNETLAB_COOKIES=...`로 설정한 뒤 다시 실행하세요."
                ),
            }

        if topology.get("error"):
            logger.error(f"❌ Topology 조회 실패: {topology.get('error')}")
            return {"status": "failed", "error": str(topology)}

        if "data" not in topology:
            logger.error("❌ Topology 조회 실패: 'data' 필드가 없습니다.")
            return {"status": "failed", "error": f"Topology missing 'data': {topology}"}

        logger.info("✅ Topology 조회 성공")
        
        # 2. Inventory 생성 (Guacamole에서 Telnet 포트 추출 포함)
        logger.info(f"\n[2/5] Inventory 생성 중...")
        pnetlab_vm_ip = _extract_host_from_base_url(getattr(pnetlab_client, "base_url", ""))
        
        # 노드 목록 추출
        nodes = pnetlab_client.get_nodes_from_topology(topology)
        logger.info(f"  - {len(nodes)}개 노드 발견")
        
        # Guacamole Console Link에서 Telnet 포트 추출
        if nodes and nodes[0].get('url') == 'guacamole':
            logger.info("  - Guacamole 모드 감지! Console Link에서 Telnet 포트 추출 중...")
            for node in nodes:
                try:
                    node_id = int(node.get('id', 0))
                    if node_id > 0:
                        console_link = pnetlab_client.get_console_link(node_id)
                        if 'error' not in console_link and 'data' in console_link:
                            port = pnetlab_client.extract_telnet_port_from_guacamole(console_link['data'])
                            if port:
                                node['telnet_port'] = port
                                logger.debug(f"    {node['name']}: telnet_port={port}")
                except Exception as e:
                    logger.warning(f"    {node.get('name', 'unknown')}: 포트 추출 실패 - {e}")
            
            ports_found = sum(1 for n in nodes if n.get('telnet_port', 0) > 0)
            logger.info(f"  - Telnet 포트 추출: {ports_found}/{len(nodes)}")
        
        # Lab 이름 추출
        data = topology.get('data', {})
        labinfo = data.get('labinfo', {})
        detected_lab_name = lab_name or labinfo.get('name') or labinfo.get('filename', '').replace('.unl', '') or data.get('name') or "default"
        
        # InventoryBuilder로 생성
        from inventory.builder import InventoryBuilder
        builder = InventoryBuilder(pnetlab_vm_ip=pnetlab_vm_ip, lab_name=detected_lab_name)
        for node in nodes:
            builder.add_node(node)
        inventory = builder.build()
        
        if not inventory or not inventory.devices:
            logger.error("❌ Inventory 생성 실패")
            return {
                "status": "failed",
                "error": "Failed to build inventory"
            }
        
        detected_lab_name = inventory.global_settings.nso_authgroup
        device_count = len(inventory.devices)
        
        logger.info(f"✅ Inventory 생성 완료")
        logger.info(f"  - Lab 이름: {detected_lab_name}")
        logger.info(f"  - 장비 수: {device_count}")
        
        # Inventory 저장
        if save_inventory:
            inventory_dict = inventory.to_dict()
            
            # 파일 저장
            import json
            inventory_file = Path(__file__).parent.parent / "device_info_generated.json"
            with open(inventory_file, 'w', encoding='utf-8') as f:
                json.dump(inventory_dict, f, indent=2, ensure_ascii=False)
            logger.info(f"  - Inventory 저장: {inventory_file}")
        else:
            inventory_dict = inventory.to_dict()
        
        # 3. SSH 설정 (선택적)
        ssh_results = {"success": [], "failed": []}
        
        if not skip_ssh:
            logger.info(f"\n[3/5] SSH 설정 시작... ({device_count}개 장비)")
            logger.info(f"  ⚡ 병렬 처리 모드")
            
            ssh_enabler = SSHEnabler(inventory_dict)
            ssh_results = await ssh_enabler.configure_all_devices()
            
            logger.info(f"\n✅ SSH 설정 완료")
            logger.info(f"  - 성공: {len(ssh_results['success'])}/{device_count}")
            logger.info(f"  - 실패: {len(ssh_results['failed'])}/{device_count}")
            
            # SSH 실패한 장비가 있으면 경고
            if ssh_results['failed']:
                logger.warning(f"  ⚠️  SSH 설정 실패 장비: {', '.join(ssh_results['failed'])}")
                logger.warning(f"  이 장비들은 NSO 등록에서 실패할 수 있습니다.")
        else:
            logger.info(f"\n[3/5] SSH 설정 스킵 (--skip-ssh)")
            logger.info(f"  ℹ️  장비에 SSH가 이미 설정되어 있어야 합니다.")
        
        # 4. NSO 등록
        logger.info(f"\n[4/5] NSO 등록 시작...")
        
        nso_onboarder = NSOOnboarder(inventory_dict, nso_client=nso_client)
        nso_results = nso_onboarder.register_all_devices()
        
        logger.info(f"\n✅ NSO 등록 완료")
        logger.info(f"  - 등록 성공: {len(nso_results['registered'])}/{device_count}")
        logger.info(f"  - Sync 성공: {len(nso_results['synced'])}/{len(nso_results['registered'])}")
        
        # 5. 검증
        logger.info(f"\n[5/5] 연결 검증...")
        
        verify_results = nso_onboarder.verify_all()
        
        logger.info(f"\n✅ 검증 완료")
        logger.info(f"  - In-sync: {len(verify_results['in_sync'])}/{device_count}")
        
        # 최종 상태 결정
        if len(nso_results['synced']) == device_count:
            status = "completed"
            status_icon = "✅"
        elif len(nso_results['synced']) > 0:
            status = "partial"
            status_icon = "⚠️"
        else:
            status = "failed"
            status_icon = "❌"
        
        # 최종 결과
        logger.info(f"\n{'='*70}")
        logger.info(f"{status_icon} 자동 온보딩 {status.upper()}")
        logger.info(f"{'='*70}")
        logger.info(f"Lab: {detected_lab_name}")
        logger.info(f"총 장비: {device_count}")
        logger.info(f"SSH 성공: {len(ssh_results['success'])}")
        logger.info(f"NSO 등록: {len(nso_results['registered'])}")
        logger.info(f"NSO Sync: {len(nso_results['synced'])}")
        logger.info(f"검증 성공: {len(verify_results['in_sync'])}")
        logger.info(f"{'='*70}\n")
        
        return {
            "lab_name": detected_lab_name,
            "total_devices": device_count,
            "ssh_results": ssh_results,
            "nso_results": nso_results,
            "verify_results": verify_results,
            "status": status
        }
        
    except Exception as e:
        logger.error(f"\n❌ 자동 온보딩 중 예외 발생: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        return {
            "status": "failed",
            "error": str(e)
        }


# 헬퍼 함수
def print_onboard_summary(result: Dict[str, Any]):
    """
    온보딩 결과를 사용자 친화적으로 출력
    
    Args:
        result: auto_onboard_lab() 반환값
    """
    print("\n" + "="*70)
    print("자동 온보딩 결과 요약")
    print("="*70)
    
    if result.get("status") == "failed":
        print(f"\n[실패] {result.get('error', 'Unknown error')}")
        return
    
    lab_name = result.get("lab_name", "Unknown")
    total = result.get("total_devices", 0)
    
    print(f"\nLab 이름: {lab_name}")
    print(f"총 장비 수: {total}")
    
    # SSH 결과
    ssh = result.get("ssh_results", {})
    if ssh:
        print(f"\nSSH 설정:")
        print(f"  성공: {len(ssh.get('success', []))}/{total}")
        if ssh.get('success'):
            print(f"     {', '.join(ssh['success'])}")
        if ssh.get('failed'):
            print(f"  실패: {len(ssh['failed'])}/{total}")
            print(f"     {', '.join(ssh['failed'])}")
    
    # NSO 결과
    nso = result.get("nso_results", {})
    print(f"\nNSO 등록:")
    print(f"  등록: {len(nso.get('registered', []))}/{total}")
    print(f"  Sync: {len(nso.get('synced', []))}/{len(nso.get('registered', []))}")
    
    if nso.get('synced'):
        print(f"     {', '.join(nso['synced'])}")
    
    if nso.get('failed_register'):
        print(f"  등록 실패: {', '.join(nso['failed_register'])}")
    if nso.get('failed_sync'):
        print(f"  Sync 실패: {', '.join(nso['failed_sync'])}")
    
    # 검증 결과
    verify = result.get("verify_results", {})
    print(f"\n✓ 검증:")
    print(f"  In-sync: {len(verify.get('in_sync', []))}/{total}")
    if verify.get('in_sync'):
        print(f"     {', '.join(verify['in_sync'])}")
    if verify.get('out_of_sync'):
        print(f"  Out-of-sync: {', '.join(verify['out_of_sync'])}")
    
    # 최종 상태
    status = result.get("status", "unknown")
    print(f"\n{'='*70}")
    if status == "completed":
        print("모든 장비가 성공적으로 등록되었습니다.")
    elif status == "partial":
        print("일부 장비만 등록되었습니다. 실패한 장비를 확인하세요.")
    else:
        print("온보딩에 실패했습니다.")
    print("="*70 + "\n")


# 테스트 코드
if __name__ == "__main__":
    import sys
    from pathlib import Path
    
    # 상위 디렉토리 추가
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from clients.pnetlab import PnetlabClient
    from clients.nso import NSOClient
    from config.settings import settings
    
    # 로깅 설정
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=== 자동 온보딩 테스트 ===\n")
    
    # 클라이언트 생성
    pnetlab_client = PnetlabClient(
        base_url=settings.pnetlab.base_url,
        username=settings.pnetlab.username,
        password=settings.pnetlab.password,
        timeout=settings.pnetlab.timeout
    )
    
    nso_client = NSOClient(
        base_url=settings.nso.base_url,
        username=settings.nso.username,
        password=settings.nso.password
    )
    
    # 온보딩 실행
    result = asyncio.run(auto_onboard_lab(
        pnetlab_client=pnetlab_client,
        nso_client=nso_client,
        skip_ssh=False  # SSH 설정 포함
    ))
    
    # 결과 출력
    print_onboard_summary(result)
