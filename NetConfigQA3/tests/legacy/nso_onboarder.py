from pathlib import Path
"""
NSO Onboarder - NSO 장비 등록 자동화

NSO RESTCONF API를 사용하여 네트워크 장비를 자동으로 등록합니다.
(기존 Docker CLI 방식에서 RESTCONF 방식으로 변경됨)

주요 기능:
- Authgroup 생성
- 장비 등록
- SSH 호스트 키 가져오기
- Sync-from 실행
"""

import logging
import time
from typing import Dict, List, Any, Optional

# NSOClient 임포트 (경로 주의)
try:
    from clients.nso import NSOClient
except ImportError:
    # 단독 실행 시 경로 문제 해결을 위한 처리
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from clients.nso import NSOClient

logger = logging.getLogger(__name__)


class NSOOnboarder:
    """
    RESTCONF를 통한 NSO 장비 등록 자동화
    """
    
    def __init__(self,
                 inventory: Dict[str, Any],
                 nso_client: Optional[NSOClient] = None,
                 max_retries: int = 2):
        """
        Args:
            inventory: device_info.json 형식의 인벤토리
            nso_client: NSOClient 인스턴스 (없으면 생성 시도)
            max_retries: 실패 시 재시도 횟수
        """
        self.global_settings = inventory['global_settings']
        self.devices = inventory['devices']
        self.max_retries = max_retries
        
        # NSO Client 설정
        if nso_client:
            self.client = nso_client
        else:
            # Client가 없으면 설정에서 생성
            # settings.py가 없는 경우를 대비한 안전장치 필요
            from config.settings import settings
            self.client = NSOClient(
                base_url=settings.nso.base_url,
                username=settings.nso.username,
                password=settings.nso.password,
                timeout=settings.nso.timeout
            )
            
        logger.info(f"NSOOnboarder 초기화: {len(self.devices)}개 장비")
        logger.info(f"Target NSO: {self.client.base_url}")
        logger.info(f"Authgroup: {self.global_settings.get('nso_authgroup', 'default')}")
    
    def create_authgroup(self) -> bool:
        """Authgroup 생성"""
        group = self.global_settings.get('nso_authgroup', 'default')
        username = self.global_settings.get('nso_username', 'admin')
        password = self.global_settings.get('nso_password', 'admin')
        
        logger.info(f"\n{'='*60}")
        logger.info(f"[AUTH] authgroup '{group}' 확인/생성")
        logger.info(f"{'='*60}")
        
        if self.client.create_authgroup(group, username, password):
            logger.info(f"  ✅ authgroup '{group}' 준비 완료")
            return True
        else:
            logger.error(f"  ❌ authgroup '{group}' 생성 실패")
            return False
    
    def register_device(self, device: Dict[str, Any], retry_count: int = 0) -> bool:
        """단일 장비 등록 (등록 + 키 fetch)"""
        device_name = device['name']
        oob_ip = device['oob_ip']
        
        logger.info(f"\n{'='*60}")
        logger.info(f"[NSO] {device_name} ({oob_ip}) 등록 시작")
        if retry_count > 0:
            logger.info(f"[재시도] {retry_count}/{self.max_retries}")
        logger.info(f"{'='*60}")
        
        try:
            # 1. 등록 정보 준비
            reg_info = {
                "name": device_name,
                "oob_ip": oob_ip,
                "port": 22,
                "authgroup": self.global_settings.get('nso_authgroup', 'default'),
                "ned_id": self.global_settings.get('nso_ned_id', 'cisco-ios-cli-6.110')
            }
            
            # 2. 장비 등록 요청
            logger.info(f"[1/2] 장비 등록 중...")
            if not self.client.register_device(reg_info):
                raise Exception("등록 API 호출 실패")
            
            logger.info(f"  ✅ 장비 등록 완료")
            
            # 3. SSH 키 가져오기
            logger.info(f"\n[2/2] SSH 호스트 키 가져오는 중...")
            if self.client.fetch_host_keys(device_name):
                logger.info(f"  ✅ SSH 키 가져오기 성공")
            else:
                logger.warning(f"  ⚠️  SSH 키 가져오기 실패 (나중에 sync-from에서 문제될 수 있음)")
            
            return True
            
        except Exception as e:
            logger.error(f"\n❌ [ERROR] 장비 등록 중 예외 발생: {e}")
            
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (3초)")
                time.sleep(3)
                return self.register_device(device, retry_count + 1)
            
            return False
    
    def sync_from(self, device_name: str, retry_count: int = 0) -> bool:
        """장비 동기화 test"""
        logger.info(f"\n[SYNC] {device_name} 동기화 중...")
        
        try:
            if self.client.sync_from(device_name):
                logger.info(f"  ✅ {device_name} 동기화 성공!")
                return True
            else:
                raise Exception("Sync-from 결과 False")
                
        except Exception as e:
            logger.error(f"  ❌ {device_name} 동기화 실패: {e}")
            
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (5초)")
                time.sleep(5)
                return self.sync_from(device_name, retry_count + 1)
            
            return False

    def register_all_devices(self) -> Dict[str, List[str]]:
        """모든 장비 등록 및 동기화"""
        logger.info(f"\n{'='*70}")
        logger.info(f"NSO 장비 등록 시작: {len(self.devices)}개 장비 (RESTCONF)")
        logger.info(f"{'='*70}\n")
        
        # 1. Authgroup 생성
        if not self.create_authgroup():
            logger.warning("Authgroup 생성 실패. 등록이 실패할 수 있습니다.")
        
        registered = []
        failed_register = []
        synced = []
        failed_sync = []
        
        # 2. 각 장비 등록
        for i, device in enumerate(self.devices, 1):
            device_name = device['name']
            logger.info(f"\n진행: {i}/{len(self.devices)}")
            
            # 등록
            if self.register_device(device):
                # sync-from 시도
                if self.sync_from(device_name):
                    registered.append(device_name)
                    synced.append(device_name)
                    logger.info(f"  ✅ {device_name} 등록 및 Sync 완료 (SSH)")
                else:
                    # SSH Sync 실패 -> Telnet Fallback 시도 (No route 등으로 인한 실패 시)
                    logger.warning(f"  ⚠️  SSH Sync 실패. Telnet(Console) 모드로 전환 시도...")
                    if self._fallback_to_telnet(device):
                        registered.append(device_name)
                        synced.append(device_name)
                        logger.info(f"  ✅ {device_name} 등록 및 Sync 완료 (Telnet Fallback)")
                    else:
                        registered.append(device_name) # 등록은 되었으나 Sync 실패
                        failed_sync.append(device_name)
            else:
                failed_register.append(device_name)
        
        # 최종 결과
        logger.info(f"\n{'='*70}")
        logger.info(f"NSO 등록 완료")
        logger.info(f"{'='*70}")
        logger.info(f"✅ 등록 성공: {len(registered)}/{len(self.devices)}")
        logger.info(f"✅ Sync 성공: {len(synced)}/{len(registered) if registered else 0}")
        logger.info(f"❌ 등록 실패: {len(failed_register)}/{len(self.devices)}")
        logger.info(f"❌ Sync 실패: {len(failed_sync)}/{len(registered) if registered else 0}")
        
        return {
            "registered": registered,
            "synced": synced,
            "failed_register": failed_register,
            "failed_sync": failed_sync
        }

    def _fallback_to_telnet(self, device: Dict[str, Any]) -> bool:
        """SSH 실패 시 Telnet(Console Proxy)으로 재등록 및 Sync 시도"""
        device_name = device['name']
        pnetlab_ip = self.global_settings.get('pnetlab_vm_ip')
        telnet_port = device.get('telnet_port')
        
        if not pnetlab_ip or not telnet_port:
            logger.error(f"  ❌ Telnet 정보 부족 (IP: {pnetlab_ip}, Port: {telnet_port})")
            return False
            
        logger.info(f"  [Fallback] {device_name} -> Telnet Mode ({pnetlab_ip}:{telnet_port}) 변경 중...")
        
        try:
            # 1. Telnet 정보로 재등록 (Overwrite)
            reg_info = {
                "name": device_name,
                "oob_ip": pnetlab_ip,  # PNETLab 서버 IP
                "port": telnet_port,   # Console Port
                "authgroup": self.global_settings.get('nso_authgroup', 'default'),
                "ned_id": self.global_settings.get('nso_ned_id', 'cisco-ios-cli-6.110'),
                "protocol": "telnet"   # 프로토콜 변경
            }
            
            if not self.client.register_device(reg_info):
                logger.error("  ❌ Telnet 모드 등록 실패")
                return False
                
            # 2. Sync-from 재시도
            logger.info("  [Fallback] Telnet Sync-from 시도...")
            # 약간의 딜레이
            time.sleep(2)
            if self.client.sync_from(device_name):
                logger.info(f"  ✅ Telnet Sync 성공!")
                return True
            else:
                logger.error("  ❌ Telnet Sync 실패")
                return False
                
        except Exception as e:
            logger.error(f"  ❌ Fallback 중 에러: {e}")
            return False
    
    def verify_connectivity(self, device_name: str) -> bool:
        """연결 검증 (check-sync)"""
        logger.info(f"[VERIFY] {device_name} 연결 검증 중...")
        return self.client.check_sync(device_name)
    
    def verify_all(self) -> Dict[str, List[str]]:
        """모든 장비 검증"""
        logger.info(f"\n{'='*70}")
        logger.info(f"연결 검증 시작")
        logger.info(f"{'='*70}\n")
        
        in_sync = []
        out_of_sync = []
        
        for device in self.devices:
            device_name = device['name']
            if self.verify_connectivity(device_name):
                in_sync.append(device_name)
                logger.info(f"  ✅ {device_name} in-sync")
            else:
                out_of_sync.append(device_name)
                logger.warning(f"  ⚠️  {device_name} out-of-sync")
        
        return {
            "in_sync": in_sync,
            "out_of_sync": out_of_sync
        }


if __name__ == "__main__":
    import sys
    import json
    from pathlib import Path
    
    # 로깅 설정
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # device_info_generated.json 로드
    config_file = Path(__file__).parent.parent / "device_info_generated.json"
    
    if not config_file.exists():
        print(f"[!] 설정 파일을 찾을 수 없습니다: {config_file}")
        sys.exit(1)
    
    with open(config_file, 'r', encoding='utf-8') as f:
        inventory = json.load(f)
    
    print("=== NSO Onboarder 테스트 (Remote) ===\n")
    
    # 여기서는 자동으로 settings에서 NSOClient를 생성하게 됨
    onboarder = NSOOnboarder(inventory)
    results = onboarder.register_all_devices()
    
    print(f"\n최종 결과:")
    print(f"  등록 성공: {results['registered']}")
    print(f"  동기화 성공: {results['synced']}")
