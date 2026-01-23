
import json
import asyncio
import telnetlib3
import time
import sys
import logging
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))

from config.settings import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("enable_ssh")

class SSHEnabler:
    def __init__(self):
        self.device_info_path = Path(__file__).parents[2] / "device_info_generated.json"
        
        if not self.device_info_path.exists():
            logger.error(f"Config file not found: {self.device_info_path}")
            sys.exit(1)
            
        with open(self.device_info_path, 'r') as f:
            self.config = json.load(f)
            
        self.global_settings = self.config['global_settings']
        self.devices = self.config['devices']
        self.pnetlab_vm_ip = self.global_settings['pnetlab_vm_ip']

    async def enable_ssh_via_telnet(self, device):
        """Telnet으로 접속하여 SSH 활성화 및 초기 설정 수행"""
        logger.info(f"{'='*60}")
        logger.info(f"[Telnet] {device['name']} ({device['telnet_port']}) 설정 시작")
        logger.info(f"{'='*60}")

        host = self.pnetlab_vm_ip
        port = device['telnet_port']
        # Use the OOB IP specifically defined in the JSON configuration
        device_mgmt_ip = device.get('oob_ip')
        if not device_mgmt_ip:
            logger.warning(f"No oob_ip found for {device['name']}, skipping...")
            return False
            
        logger.info(f"Setting up {device['name']} with Management IP: {device_mgmt_ip}")
        
        try:
            logger.info(f"Connecting to {host}:{port}...")
            # 타임아웃 10초
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port), timeout=10
            )
            logger.info("Telnet 접속 성공")
        except Exception as e:
            logger.error(f"Telnet 접속 실패: {e}")
            return False

        async def send_cmd(cmd, sleep_time=1.0, debug_msg=""):
            if debug_msg:
                logger.info(f"  [CMD] {debug_msg}: {cmd}")
            writer.write(cmd + "\r\n")
            await asyncio.sleep(sleep_time)
            try:
                # Read output to flush buffer
                await asyncio.wait_for(reader.read(1024), timeout=0.1)
            except:
                pass

        try:
            # 1. 초기 진입
            logger.info("[1/10] 세션 초기화...")
            writer.write("\r\n\r\n")
            await asyncio.sleep(1)

            # 2. Enable 모드
            logger.info("[2/10] Enable 모드 진입...")
            await send_cmd("enable", debug_msg="Enable")
            
            # 3. Config 모드
            logger.info("[3/10] 설정 모드 진입...")
            await send_cmd("conf t", debug_msg="Config Terminal")
            await send_cmd("no ip domain-lookup", debug_msg="No Domain Lookup")
            await send_cmd(f"hostname {device['name']}", debug_msg=f"Hostname {device['name']}")

            # 4. Mgmt 인터페이스 설정 (e0/0 assuming standard IOSv/IOL)
            # Adjust interface name based on typical images. Usually GigabitEthernet0/0 or Ethernet0/0.
            # Safety: try both commonly found Mgmt interfaces
            logger.info("[4/10] 인터페이스 설정...")
            await send_cmd("interface Ethernet0/0", debug_msg="Int Et0/0")
            await send_cmd(f"ip address {device_mgmt_ip} 255.255.255.0", debug_msg=f"IP {device_mgmt_ip}")
            await send_cmd("no shutdown", debug_msg="No Shut")
            await send_cmd("exit")
            # Just in case it's Gi0/0
            await send_cmd("interface GigabitEthernet0/0", debug_msg="Int Gi0/0")
            await send_cmd(f"ip address {device_mgmt_ip} 255.255.255.0", debug_msg=f"IP {device_mgmt_ip}")
            await send_cmd("no shutdown", debug_msg="No Shut", sleep_time=2.0)
            await send_cmd("exit")

            # 5. Domain Name
            logger.info("[5/10] 도메인 설정...")
            await send_cmd("ip domain-name example.com", debug_msg="Domain Name")

            # 6. Crypto Key (this takes time)
            logger.info("[6/10] RSA 키 생성 (10초 대기)...")
            await send_cmd("crypto key zeroize rsa", debug_msg="Zeroize")
            writer.write("yes\r\n") 
            await asyncio.sleep(1)
            writer.write("crypto key generate rsa general-keys modulus 2048\r\n")
            # give enough time
            await asyncio.sleep(10)

            # 7. User Admin
            logger.info("[7/10] Admin 계정 생성...")
            # Use default user/pass 'admin'/'admin' or from config
            user = self.global_settings.get('device_username', 'admin')
            pw = self.global_settings.get('device_password', 'admin')
            await send_cmd(f"username {user} privilege 15 secret {pw}", debug_msg=f"User {user}")

            # 8. VTY SSH
            logger.info("[8/10] VTY SSH 활성화...")
            await send_cmd("line vty 0 4", debug_msg="Line VTY")
            await send_cmd("transport input ssh", debug_msg="Transport SSH")
            await send_cmd("login local", debug_msg="Login Local")
            await send_cmd("exit")
            
            # 9. SSH Version 2
            await send_cmd("ip ssh version 2", debug_msg="SSH v2")

            # 10. Save
            logger.info("[9/10] 저장...")
            await send_cmd("end")
            await send_cmd("write memory", debug_msg="Wrist", sleep_time=5.0)

            logger.info(f"[SUCCESS] {device['name']} SSH Enabled.")
            writer.close()
            await writer.wait_closed()
            return True

        except Exception as e:
            logger.error(f"[ERROR] 설정 중 예외: {e}")
            return False

    async def run(self):
        print("\n=== SSH 활성화 작업 시작 (병렬 실행) ===")
        tasks = []
        for device in self.devices:
            # 병렬 실행을 위해 태스크 리스트에 추가
            tasks.append(self.enable_ssh_via_telnet(device))
        
        # 모든 태스크 병렬 실행
        await asyncio.gather(*tasks)
        print("=== 작업 종료 ===")

if __name__ == "__main__":
    enabler = SSHEnabler()
    asyncio.run(enabler.run())
