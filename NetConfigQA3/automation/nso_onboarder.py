"""
NSO Onboarder - NSO 장비 등록 자동화

Docker CLI 방식을 사용하여 NSO에 네트워크 장비를 자동으로 등록합니다.
(기존 Make_Dataset/src/2-NSO_Register.py 리팩토링)

주요 기능:
- NCS 데몬 시작/확인
- Authgroup 생성
- 장비 등록
- SSH 호스트 키 가져오기
- Sync-from 실행
"""

import logging
import subprocess
import time
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class NSOOnboarder:
    """
    Docker CLI를 통한 NSO 장비 등록 자동화
    
    NSO가 Docker 컨테이너(cisco-nso-dev)에서 실행 중이어야 합니다.
    """
    
    # Docker 컨테이너 이름
    DOCKER_CONTAINER = "cisco-nso-dev"
    
    # NCS 환경 설정 명령어
    NCS_ENV_CMD = "cd ~/ncs-instance && source ~/nso-6.6/ncsrc"
    
    def __init__(self,
                 inventory: Dict[str, Any],
                 max_retries: int = 2,
                 docker_container: str = None):
        """
        Args:
            inventory: device_info.json 형식의 인벤토리
            max_retries: 실패 시 재시도 횟수
            docker_container: Docker 컨테이너 이름 (기본: cisco-nso-dev)
        """
        self.global_settings = inventory['global_settings']
        self.devices = inventory['devices']
        self.max_retries = max_retries
        self.docker_container = docker_container or self.DOCKER_CONTAINER
        
        logger.info(f"NSOOnboarder 초기화: {len(self.devices)}개 장비")
        logger.info(f"Authgroup: {self.global_settings.get('nso_authgroup', 'default')}")
        logger.info(f"NED ID: {self.global_settings.get('nso_ned_id', 'cisco-ios-cli-6.110')}")
        logger.info(f"Docker 컨테이너: {self.docker_container}")
    
    def _run_docker_cmd(self, bash_script: str) -> subprocess.CompletedProcess:
        """
        Docker 컨테이너에서 bash 명령어 실행
        
        Args:
            bash_script: 실행할 bash 스크립트
            
        Returns:
            subprocess.CompletedProcess
        """
        cmd = ["docker", "exec", self.docker_container, "bash", "-c", bash_script]
        logger.debug(f"Docker CMD: {bash_script[:100]}...")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result
    
    def _run_nso_cmd(self, ncs_command: str) -> subprocess.CompletedProcess:
        """
        NSO CLI 단일 명령어 실행
        
        Args:
            ncs_command: NCS CLI 명령어
            
        Returns:
            subprocess.CompletedProcess
        """
        bash_script = f'{self.NCS_ENV_CMD} && echo "{ncs_command}" | ncs_cli -C -u admin'
        return self._run_docker_cmd(bash_script)
    
    def _run_nso_cmds(self, commands: List[str]) -> subprocess.CompletedProcess:
        """
        NSO CLI 여러 명령어를 하나의 세션에서 실행
        
        Args:
            commands: NCS CLI 명령어 리스트
            
        Returns:
            subprocess.CompletedProcess
        """
        combined_cmds = "\\n".join(commands)
        bash_script = f'{self.NCS_ENV_CMD} && echo -e "{combined_cmds}" | ncs_cli -C -u admin'
        return self._run_docker_cmd(bash_script)
    
    def check_docker_container(self) -> bool:
        """
        Docker 컨테이너가 실행 중인지 확인
        
        Returns:
            실행 중이면 True
        """
        logger.info(f"Docker 컨테이너 '{self.docker_container}' 상태 확인...")
        
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.docker_container],
            capture_output=True, text=True
        )
        
        if result.returncode == 0 and "true" in result.stdout.lower():
            logger.info(f"  ✅ 컨테이너 실행 중")
            return True
        else:
            logger.error(f"  ❌ 컨테이너가 실행 중이 아닙니다!")
            logger.error(f"  다음 명령어로 컨테이너를 시작하세요:")
            logger.error(f"    docker start {self.docker_container}")
            return False
    
    def start_ncs(self) -> bool:
        """
        NSO 데몬(ncs) 시작
        
        Returns:
            성공 여부
        """
        logger.info(f"\n{'='*60}")
        logger.info("NCS 데몬 시작")
        logger.info(f"{'='*60}")
        
        # 1. Docker 컨테이너 확인
        if not self.check_docker_container():
            return False
        
        # 2. NCS 상태 확인
        logger.info("\n[1/3] NCS 상태 확인 중...")
        check_script = f"{self.NCS_ENV_CMD} && ncs --status"
        result = self._run_docker_cmd(check_script)
        
        if "running" in result.stdout.lower():
            logger.info("  ✅ NCS가 이미 실행 중입니다.")
            return True
        
        logger.info("  ℹ️  NCS가 실행 중이 아닙니다. 시작합니다...")
        
        # 3. NCS 시작
        logger.info("\n[2/3] NCS 시작 중...")
        start_script = f"{self.NCS_ENV_CMD} && ncs"
        result = self._run_docker_cmd(start_script)
        
        if result.returncode == 0:
            logger.info("  ✅ NCS 시작 명령 실행 성공")
        else:
            logger.warning(f"  ⚠️  NCS 시작 중 경고: {result.stderr[:200] if result.stderr else 'N/A'}")
        
        # 4. NCS 초기화 대기
        logger.info("\n[3/3] NCS 초기화 대기 중...")
        max_wait = 10
        for i in range(max_wait):
            time.sleep(2)
            result = self._run_docker_cmd(check_script)
            
            if "running" in result.stdout.lower():
                logger.info(f"  ✅ NCS가 성공적으로 시작되었습니다! (시도 {i+1}/{max_wait})")
                return True
            
            logger.info(f"  ⏳ NCS 시작 대기 중... ({i+1}/{max_wait})")
        
        logger.error("  ❌ NCS 시작 시간 초과")
        return False
    
    def create_authgroup(self) -> bool:
        """
        NSO authgroup 생성
        
        Returns:
            성공 여부
        """
        authgroup = self.global_settings.get('nso_authgroup', 'default')
        username = self.global_settings.get('nso_username', 'admin')
        password = self.global_settings.get('nso_password', 'admin')
        
        logger.info(f"\n{'='*60}")
        logger.info(f"[AUTH] authgroup '{authgroup}' 생성")
        logger.info(f"{'='*60}")
        
        commands = [
            "config",
            f"devices authgroups group {authgroup} default-map remote-name {username}",
            f"devices authgroups group {authgroup} default-map remote-password {password}",
            "commit",
            "exit"
        ]
        
        result = self._run_nso_cmds(commands)
        
        if "Commit complete" in result.stdout or "No modifications" in result.stdout:
            logger.info(f"  ✅ authgroup '{authgroup}' 생성 완료")
            return True
        else:
            logger.info(f"  ℹ️  authgroup 설정 결과: {result.stdout[:200] if result.stdout else 'N/A'}")
            return True  # 이미 존재할 수 있음
    
    def register_device(self, device: Dict[str, Any], retry_count: int = 0) -> bool:
        """
        단일 장비를 NSO에 등록
        
        Args:
            device: 장비 정보 딕셔너리
            retry_count: 현재 재시도 횟수
            
        Returns:
            성공 여부
        """
        device_name = device['name']
        oob_ip = device['oob_ip']
        
        logger.info(f"\n{'='*60}")
        logger.info(f"[NSO] {device_name} ({oob_ip}) 등록 시작")
        if retry_count > 0:
            logger.info(f"[재시도] {retry_count}/{self.max_retries}")
        logger.info(f"{'='*60}")
        
        authgroup = self.global_settings.get('nso_authgroup', 'default')
        ned_id = self.global_settings.get('nso_ned_id', 'cisco-ios-cli-6.110')
        
        logger.info(f"[등록 정보]")
        logger.info(f"  - 장비명: {device_name}")
        logger.info(f"  - IP: {oob_ip}")
        logger.info(f"  - Authgroup: {authgroup}")
        logger.info(f"  - NED ID: {ned_id}")
        
        try:
            # 1. 기본 설정
            logger.info(f"\n[1/3] NSO 장비 등록 중...")
            
            commands = [
                "config",
                f"devices device {device_name} address {oob_ip}",
                f"devices device {device_name} port 22",
                f"devices device {device_name} authgroup {authgroup}",
                f"devices device {device_name} device-type cli ned-id {ned_id}",
                f"devices device {device_name} state admin-state unlocked",
                # SSH 알고리즘 설정
                f"devices device {device_name} ssh-algorithms cipher aes128-cbc",
                f"devices device {device_name} ssh-algorithms cipher 3des-cbc",
                f"devices device {device_name} ssh-algorithms cipher aes256-cbc",
                f"devices device {device_name} ssh-algorithms cipher aes128-ctr",
                f"devices device {device_name} ssh-algorithms cipher aes192-ctr",
                f"devices device {device_name} ssh-algorithms cipher aes256-ctr",
                f"devices device {device_name} ssh-algorithms kex diffie-hellman-group-exchange-sha1",
                f"devices device {device_name} ssh-algorithms mac hmac-sha1",
                f"devices device {device_name} ssh-algorithms public-key ssh-rsa",
            ]
            
            # Device Group 설정 (있는 경우)
            if 'device_group' in device:
                group = device['device_group']
                logger.info(f"  - Device Group: {group}")
                commands.append(f"devices device-group {group} device-name {device_name}")
            
            commands.extend(["commit", "exit"])
            
            result = self._run_nso_cmds(commands)
            
            if "Commit complete" in result.stdout or "No modifications" in result.stdout:
                logger.info(f"  ✅ 장비 등록 완료")
            elif result.returncode == 0:
                logger.info(f"  ✅ 장비 등록 완료")
            else:
                logger.warning(f"  ⚠️  설정 적용 결과: {result.stdout[:200] if result.stdout else 'N/A'}")
            
            time.sleep(1)
            
            # 2. SSH 호스트 키 가져오기
            logger.info(f"\n[2/3] SSH 호스트 키 가져오는 중...")
            result = self._run_nso_cmd(f"devices device {device_name} ssh fetch-host-keys")
            
            if "fingerprint" in result.stdout:
                logger.info(f"  ✅ SSH 키 가져오기 성공")
            elif "result" in result.stdout:
                logger.info(f"  ✅ SSH 키 가져오기 완료")
            else:
                logger.warning(f"  ⚠️  SSH 키 결과: {result.stdout[:200] if result.stdout else 'N/A'}")
            
            return True
            
        except Exception as e:
            logger.error(f"\n❌ [ERROR] 장비 등록 중 예외 발생: {e}")
            
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (3초)")
                time.sleep(3)
                return self.register_device(device, retry_count + 1)
            
            return False
    
    def sync_from(self, device_name: str, retry_count: int = 0) -> bool:
        """
        장비로부터 설정 동기화 (sync-from)
        
        Args:
            device_name: 장비명
            retry_count: 재시도 횟수
            
        Returns:
            성공 여부
        """
        logger.info(f"\n[SYNC] {device_name} 동기화 중...")
        
        try:
            result = self._run_nso_cmd(f"devices device {device_name} sync-from")
            
            if "result true" in result.stdout:
                logger.info(f"  ✅ {device_name} 동기화 성공!")
                return True
            else:
                logger.error(f"  ❌ {device_name} 동기화 실패")
                logger.debug(f"  결과: {result.stdout[:300] if result.stdout else 'N/A'}")
                
                if retry_count < self.max_retries:
                    logger.info(f"재시도 대기 중... (5초)")
                    time.sleep(5)
                    return self.sync_from(device_name, retry_count + 1)
                
                return False
                
        except Exception as e:
            logger.error(f"  ❌ {device_name} 동기화 중 예외: {e}")
            
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (5초)")
                time.sleep(5)
                return self.sync_from(device_name, retry_count + 1)
            
            return False
    
    def register_all_devices(self) -> Dict[str, List[str]]:
        """
        모든 장비를 NSO에 등록하고 동기화
        
        Returns:
            {
                "registered": ["P1", "P2", ...],
                "synced": ["P1", "P2", ...],
                "failed_register": ["P3", ...],
                "failed_sync": ["P4", ...]
            }
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"NSO 장비 등록 시작: {len(self.devices)}개 장비")
        logger.info(f"{'='*70}\n")
        
        # 1. NCS 데몬 시작
        if not self.start_ncs():
            logger.error("❌ NCS를 시작할 수 없습니다. 등록을 중단합니다.")
            return {
                "registered": [],
                "synced": [],
                "failed_register": [d['name'] for d in self.devices],
                "failed_sync": []
            }
        
        # 2. Authgroup 생성
        self.create_authgroup()
        
        registered = []
        failed_register = []
        synced = []
        failed_sync = []
        
        # 3. 각 장비 등록
        for i, device in enumerate(self.devices, 1):
            device_name = device['name']
            logger.info(f"\n진행: {i}/{len(self.devices)}")
            
            # 등록
            if self.register_device(device):
                registered.append(device_name)
                logger.info(f"✅ {device_name} 등록 완료")
                
                # sync-from
                if self.sync_from(device_name):
                    synced.append(device_name)
                    logger.info(f"✅ {device_name} sync-from 완료")
                else:
                    failed_sync.append(device_name)
                    logger.error(f"❌ {device_name} sync-from 실패")
            else:
                failed_register.append(device_name)
                logger.error(f"❌ {device_name} 등록 실패")
        
        # 최종 결과
        logger.info(f"\n{'='*70}")
        logger.info(f"NSO 등록 완료")
        logger.info(f"{'='*70}")
        logger.info(f"✅ 등록 성공: {len(registered)}/{len(self.devices)}")
        logger.info(f"✅ Sync 성공: {len(synced)}/{len(registered) if registered else 0}")
        logger.info(f"❌ 등록 실패: {len(failed_register)}/{len(self.devices)}")
        logger.info(f"❌ Sync 실패: {len(failed_sync)}/{len(registered) if registered else 0}")
        
        if registered:
            logger.info(f"\n등록된 장비: {', '.join(registered)}")
        if synced:
            logger.info(f"동기화된 장비: {', '.join(synced)}")
        if failed_register:
            logger.warning(f"\n등록 실패: {', '.join(failed_register)}")
        if failed_sync:
            logger.warning(f"동기화 실패: {', '.join(failed_sync)}")
        
        return {
            "registered": registered,
            "synced": synced,
            "failed_register": failed_register,
            "failed_sync": failed_sync
        }
    
    def verify_connectivity(self, device_name: str) -> bool:
        """
        장비 연결 검증 (check-sync)
        
        Args:
            device_name: 장비명
            
        Returns:
            연결 성공 여부
        """
        logger.info(f"[VERIFY] {device_name} 연결 검증 중...")
        
        try:
            result = self._run_nso_cmd(f"devices device {device_name} check-sync")
            
            if "in-sync" in result.stdout:
                logger.info(f"  ✅ {device_name} 연결 정상 (in-sync)")
                return True
            else:
                logger.warning(f"  ⚠️  {device_name} out-of-sync 또는 연결 불가")
                return False
                
        except Exception as e:
            logger.error(f"  ❌ {device_name} 검증 실패: {e}")
            return False
    
    def verify_all(self) -> Dict[str, List[str]]:
        """
        모든 장비 연결 검증
        
        Returns:
            {
                "in_sync": ["P1", "P2", ...],
                "out_of_sync": ["P3", ...]
            }
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"연결 검증 시작")
        logger.info(f"{'='*70}\n")
        
        in_sync = []
        out_of_sync = []
        
        for device in self.devices:
            device_name = device['name']
            if self.verify_connectivity(device_name):
                in_sync.append(device_name)
            else:
                out_of_sync.append(device_name)
        
        logger.info(f"\n{'='*70}")
        logger.info(f"검증 완료")
        logger.info(f"{'='*70}")
        logger.info(f"✅ In-sync: {len(in_sync)}/{len(self.devices)}")
        logger.info(f"⚠️  Out-of-sync: {len(out_of_sync)}/{len(self.devices)}")
        
        if in_sync:
            logger.info(f"\nIn-sync 장비: {', '.join(in_sync)}")
        if out_of_sync:
            logger.warning(f"\nOut-of-sync 장비: {', '.join(out_of_sync)}")
        
        return {
            "in_sync": in_sync,
            "out_of_sync": out_of_sync
        }


# 테스트 코드
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
        print("먼저 test_inventory_builder.py를 실행하세요.")
        sys.exit(1)
    
    with open(config_file, 'r', encoding='utf-8') as f:
        inventory = json.load(f)
    
    print("=== NSO Onboarder 테스트 ===\n")
    
    onboarder = NSOOnboarder(inventory)
    results = onboarder.register_all_devices()
    
    print(f"\n최종 결과:")
    print(f"  등록 성공: {results['registered']}")
    print(f"  동기화 성공: {results['synced']}")
    print(f"  등록 실패: {results['failed_register']}")
    print(f"  동기화 실패: {results['failed_sync']}")
