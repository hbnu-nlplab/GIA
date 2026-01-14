from pathlib import Path
"""
SSH Enabler - Day0 SSH 설정 자동화

PNETLab 네트워크 장비에 Telnet으로 접속하여 SSH를 활성화하고 초기 설정을 수행합니다.

기존 Make_Dataset/src/1-SSH_Enable.py를 리팩토링:
- 구조화된 로깅
- 재시도 로직
- 병렬 처리 (asyncio.gather)
- 에러 핸들링 개선
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
import telnetlib3

logger = logging.getLogger(__name__)


class SSHEnabler:
    """
    Telnet을 통한 Cisco IOS 장비 SSH 설정 자동화
    
    주요 기능:
    1. Telnet 접속
    2. Enable 모드 진입
    3. 호스트네임 설정
    4. OOB 인터페이스 IP 설정
    5. Default Route 설정
    6. SSH 도메인 및 RSA 키 생성
    7. 관리자 계정 생성
    8. VTY SSH 설정
    9. 설정 저장
    """
    
    def __init__(self, 
                 inventory: Dict[str, Any],
                 max_retries: int = 2,
                 connection_timeout: int = 10):
        """
        Args:
            inventory: device_info.json 형식의 인벤토리
            max_retries: 연결 실패 시 재시도 횟수
            connection_timeout: Telnet 연결 타임아웃 (초)
        """
        self.global_settings = inventory['global_settings']
        self.devices = inventory['devices']
        self.max_retries = max_retries
        self.connection_timeout = connection_timeout
        
        logger.info(f"SSHEnabler 초기화: {len(self.devices)}개 장비")
        logger.info(f"PNETLab VM IP: {self.global_settings['pnetlab_vm_ip']}")
    
    async def _send_command(self, 
                           writer, 
                           reader,
                           cmd: str, 
                           sleep_time: float = 1.0,
                           debug_msg: str = "") -> str:
        """
        명령어 전송 및 응답 수신
        
        Args:
            writer: Telnet writer
            reader: Telnet reader
            cmd: 전송할 명령어
            sleep_time: 명령 실행 대기 시간
            debug_msg: 디버그 메시지
            
        Returns:
            응답 텍스트
        """
        if debug_msg:
            logger.debug(f"  [CMD] {debug_msg}: {cmd}")
        
        # 명령어 전송
        writer.write(cmd + "\r\n")
        
        # 장비 처리 대기
        await asyncio.sleep(sleep_time)
        
        # 응답 읽기
        response = ""
        try:
            response = await asyncio.wait_for(reader.read(4096), timeout=0.5)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"  [응답 읽기 예외] {e}")
        
        return response
    
    async def enable_ssh_via_telnet(self, 
                                    device: Dict[str, Any],
                                    retry_count: int = 0) -> bool:
        """
        단일 장비에 SSH 설정 수행
        
        Args:
            device: 장비 정보 딕셔너리
            retry_count: 현재 재시도 횟수
            
        Returns:
            성공 여부
        """
        device_name = device['name']
        oob_ip = device['oob_ip']
        
        logger.info(f"\n{'='*60}")
        logger.info(f"[Telnet] {device_name} ({oob_ip}) 설정 시작")
        if retry_count > 0:
            logger.info(f"[재시도] {retry_count}/{self.max_retries}")
        logger.info(f"{'='*60}")
        
        host = self.global_settings['pnetlab_vm_ip']
        port = device['telnet_port']
        
        logger.info(f"[접속 정보]")
        logger.info(f"  - PNETLab VM IP: {host}")
        logger.info(f"  - Telnet Port: {port}")
        logger.info(f"  - 장비 OOB IP: {oob_ip}")
        
        # Telnet 연결
        try:
            logger.debug(f"Telnet 연결 시도... (timeout={self.connection_timeout}초)")
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port),
                timeout=self.connection_timeout
            )
            logger.info(f"✅ Telnet 접속 성공: {host}:{port}")
        except asyncio.TimeoutError:
            logger.error(f"❌ Telnet 접속 타임아웃: {host}:{port}")
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (5초)")
                await asyncio.sleep(5)
                return await self.enable_ssh_via_telnet(device, retry_count + 1)
            return False
        except Exception as e:
            logger.error(f"❌ Telnet 접속 실패: {e}")
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (5초)")
                await asyncio.sleep(5)
                return await self.enable_ssh_via_telnet(device, retry_count + 1)
            return False
        
        # SSH 설정 수행
        try:
            # 1. 초기 진입
            logger.info(f"\n[1/11] 세션 초기화...")
            writer.write("\r\n\r\n")
            await asyncio.sleep(1)
            
            # 2. Enable 모드
            logger.info(f"[2/11] Enable 모드 진입...")
            await self._send_command(writer, reader, "enable", debug_msg="Enable")
            if self.global_settings.get('enable_password'):
                await self._send_command(
                    writer, reader,
                    self.global_settings['enable_password'],
                    debug_msg="Password"
                )
            
            # 3. Config 모드
            logger.info(f"[3/11] 설정 모드 진입...")
            await self._send_command(writer, reader, "conf t", debug_msg="Config Terminal")
            await self._send_command(writer, reader, "no ip domain-lookup", debug_msg="No Domain Lookup")
            
            # 4. 호스트네임
            logger.info(f"[4/11] 호스트네임 설정: {device_name}")
            await self._send_command(
                writer, reader,
                f"hostname {device_name}",
                debug_msg="Hostname"
            )
            
            # 5. OOB 인터페이스 설정
            logger.info(f"[5/11] OOB 인터페이스 설정...")
            oob_intf = device['oob_intf']
            await self._send_command(
                writer, reader,
                f"interface {oob_intf}",
                debug_msg=f"Interface {oob_intf}"
            )
            await self._send_command(
                writer, reader,
                f"ip address {oob_ip} 255.255.255.0",
                debug_msg="IP Address"
            )
            await self._send_command(
                writer, reader,
                "no shutdown",
                sleep_time=2.0,
                debug_msg="No Shutdown"
            )
            await self._send_command(writer, reader, "exit", debug_msg="Exit Interface")
            
            # 6. 라우팅 설정
            logger.info(f"[6/11] 기본 경로 설정...")
            gateway = self.global_settings['gateway_ip']
            await self._send_command(
                writer, reader,
                f"ip route 0.0.0.0 0.0.0.0 {gateway}",
                debug_msg=f"Default Route -> {gateway}"
            )
            
            # 7. SSH 도메인 설정
            logger.info(f"[7/11] SSH 도메인 설정...")
            domain = self.global_settings['domain_name']
            await self._send_command(
                writer, reader,
                f"ip domain-name {domain}",
                debug_msg=f"Domain Name {domain}"
            )
            
            # 8. RSA 키 생성
            logger.info(f"[8/11] RSA 키 생성 (시간 소요됨)...")
            await self._send_command(
                writer, reader,
                "crypto key zeroize rsa",
                sleep_time=2.0,
                debug_msg="기존 키 삭제"
            )
            # 확인 질문에 yes 입력
            writer.write("yes\r\n")
            await asyncio.sleep(1)
            
            # 키 생성
            writer.write("crypto key generate rsa general-keys modulus 2048\r\n")
            logger.info("  [대기] 키 생성 중... (10초)")
            await asyncio.sleep(10)
            
            # 9. 관리자 계정
            logger.info(f"[9/11] 관리자 계정 생성...")
            admin_pw = self.global_settings['admin_password']
            await self._send_command(
                writer, reader,
                f"username admin privilege 15 secret {admin_pw}",
                debug_msg="Admin User"
            )
            
            # 10. VTY (SSH) 설정
            logger.info(f"[10/11] VTY(SSH) 설정...")
            await self._send_command(writer, reader, "line vty 0 4", debug_msg="Line VTY 0 4")
            await self._send_command(writer, reader, "transport input ssh", debug_msg="Transport Input SSH")
            await self._send_command(writer, reader, "login local", debug_msg="Login Local")
            await self._send_command(writer, reader, "exit", debug_msg="Exit VTY")
            await self._send_command(writer, reader, "ip ssh version 2", debug_msg="SSH Version 2")
            
            # 11. 저장
            logger.info(f"[11/11] 설정 저장...")
            await self._send_command(writer, reader, "end", debug_msg="End Config")
            await self._send_command(
                writer, reader,
                "write memory",
                sleep_time=3.0,
                debug_msg="Write Memory"
            )
            
            logger.info(f"\n✅ [SUCCESS] {device_name} 설정 완료")
            
            # 연결 종료
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except Exception as e:
            logger.error(f"\n❌ [ERROR] 설정 중 예외 발생: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            
            # 재시도
            if retry_count < self.max_retries:
                logger.info(f"재시도 대기 중... (5초)")
                await asyncio.sleep(5)
                return await self.enable_ssh_via_telnet(device, retry_count + 1)
            
            return False
    
    async def configure_all_devices(self) -> Dict[str, List[str]]:
        """
        모든 장비에 대해 SSH 설정 병렬 실행
        
        Returns:
            {
                "success": ["P1", "P2", ...],
                "failed": ["P3", ...]
            }
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"SSH 설정 시작: {len(self.devices)}개 장비 (병렬 처리)")
        logger.info(f"{'='*70}\n")
        
        # 모든 장비에 대해 병렬 실행
        tasks = [
            self.enable_ssh_via_telnet(device)
            for device in self.devices
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 결과 분류
        success = []
        failed = []
        
        for device, result in zip(self.devices, results):
            device_name = device['name']
            if isinstance(result, Exception):
                logger.error(f"❌ {device_name}: 예외 발생 - {result}")
                failed.append(device_name)
            elif result is True:
                success.append(device_name)
            else:
                failed.append(device_name)
        
        # 최종 결과
        logger.info(f"\n{'='*70}")
        logger.info(f"SSH 설정 완료")
        logger.info(f"{'='*70}")
        logger.info(f"✅ 성공: {len(success)}/{len(self.devices)}")
        logger.info(f"❌ 실패: {len(failed)}/{len(self.devices)}")
        
        if success:
            logger.info(f"\n성공한 장비: {', '.join(success)}")
        if failed:
            logger.warning(f"\n실패한 장비: {', '.join(failed)}")
        
        return {
            "success": success,
            "failed": failed
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
        print(f"❌ 설정 파일을 찾을 수 없습니다: {config_file}")
        print("먼저 test_inventory_builder.py를 실행하세요.")
        sys.exit(1)
    
    with open(config_file, 'r', encoding='utf-8') as f:
        inventory = json.load(f)
    
    print("=== SSH Enabler 테스트 ===\n")
    
    enabler = SSHEnabler(inventory)
    results = asyncio.run(enabler.configure_all_devices())
    
    print(f"\n최종 결과:")
    print(f"  성공: {results['success']}")
    print(f"  실패: {results['failed']}")
