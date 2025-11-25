import json
import asyncio
import telnetlib3
import time
import subprocess
import sys
import os

# 설정 파일 경로
CONFIG_FILE = r"c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\L2VPN\device_info.json"

class DeviceManager:
    def __init__(self, config_file):
        print(f"[DEBUG] 설정 파일 로드 중: {config_file}")
        self.config = self.load_config(config_file)
        self.global_settings = self.config['global_settings']
        print(f"[DEBUG] 로드된 장비 수: {len(self.config['devices'])}")
        print(f"[DEBUG] Pnetlab VM IP: {self.global_settings['pnetlab_vm_ip']}")

    def load_config(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    async def enable_ssh_via_telnet(self, device):
        """Telnet으로 접속하여 SSH 활성화 및 초기 설정 수행"""
        print(f"\n{'='*60}")
        print(f"[Telnet] {device['name']} ({device['oob_ip']}) 설정 시작")
        print(f"{'='*60}")

        host = self.global_settings['pnetlab_vm_ip']
        port = device['telnet_port']

        print(f"[DEBUG] 접속 정보:")
        print(f"  - Pnetlab VM IP: {host}")
        print(f"  - Telnet Port: {port}")
        print(f"  - 장비 OOB IP: {device['oob_ip']}")
        print(f"  - Gateway: {self.global_settings['gateway_ip']}")

        try:
            print(f"[DEBUG] Telnet 연결 시도 중... (timeout=10초)")
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port), timeout=10
            )
            print(f"[OK] Telnet 접속 성공: {host}:{port}")
        except Exception as e:
            print(f"[FAIL] Telnet 접속 실패: {e}")
            print(f"[DEBUG] Pnetlab VM이 실행 중인지, 장비가 시작되었는지 확인하세요.")
            return False

        # 명령어 전송 헬퍼
        async def send_cmd(cmd, sleep_time=0.5, debug_msg=""):
            if debug_msg:
                print(f"  [CMD] {debug_msg}: {cmd}")
            writer.write(cmd.encode('ascii') + b"\n")
            await asyncio.sleep(sleep_time)
            try:
                # 간단하게 응답을 읽어보기
                if debug_msg:
                    print(f"    [CMD] {cmd} sent")
            except:
                pass

        try:
            print(f"\n[1/10] 초기 프롬프트 확인 중...")
            writer.write(b"\n\n")
            await asyncio.sleep(1)

            print(f"[2/10] Enable 모드 진입 중...")
            await send_cmd("enable", debug_msg="Enable 명령")
            await send_cmd(self.global_settings['enable_password'], debug_msg="Enable 비밀번호")

            print(f"[3/10] 설정 모드 진입 및 기본 설정...")
            await send_cmd("conf t", debug_msg="Config 모드")
            await send_cmd("no ip domain-lookup", debug_msg="Domain lookup 비활성화")

            print(f"[4/10] 호스트네임 설정: {device['name']}")
            await send_cmd(f"hostname {device['name']}", debug_msg="Hostname")

            print(f"[5/10] OOB 인터페이스 설정 (Ethernet0/0)...")
            await send_cmd("interface Ethernet0/0", debug_msg="Interface 진입")
            await send_cmd(f"ip address {device['oob_ip']} 255.255.255.0", debug_msg="IP 주소")
            await send_cmd("no shutdown", debug_msg="Interface 활성화")
            await send_cmd("exit", debug_msg="Interface 나가기")

            print(f"[6/10] 기본 경로 설정...")
            gateway = self.global_settings['gateway_ip']
            await send_cmd(f"ip route 0.0.0.0 0.0.0.0 {gateway}", debug_msg=f"Default route to {gateway}")

            print(f"[7/10] SSH 도메인 설정...")
            domain = self.global_settings['domain_name']
            await send_cmd(f"ip domain-name {domain}", debug_msg="Domain name")

            print(f"[8/10] RSA 키 생성 중... (1024 bit)")
            writer.write(b"crypto key generate rsa general-keys modulus 1024\n")
            await asyncio.sleep(2)
            # RSA 키 생성은 좀 더 기다려야 함
            await asyncio.sleep(3)

            print(f"[9/10] 관리자 계정 생성...")
            admin_pw = self.global_settings['admin_password']
            await send_cmd(f"username admin privilege 15 secret {admin_pw}", debug_msg="Admin 계정")

            print(f"[10/10] VTY 라인 설정 (SSH만 허용)...")
            await send_cmd("line vty 0 4", debug_msg="VTY 라인")
            await send_cmd("transport input ssh", debug_msg="SSH만 허용")
            await send_cmd("login local", debug_msg="로컬 인증")
            await send_cmd("exit", debug_msg="VTY 나가기")

            print(f"\n[저장] 설정 저장 중...")
            await send_cmd("end", debug_msg="설정 모드 종료")
            await send_cmd("write memory", debug_msg="설정 저장", sleep_time=2)

            print(f"\n[SUCCESS] {device['name']} Telnet 설정 완료!")
            writer.close()
            await writer.wait_closed()
            return True

        except Exception as e:
            print(f"\n[ERROR] 설정 중 오류 발생: {e}")
            print(f"[DEBUG] 오류 타입: {type(e).__name__}")
            import traceback
            print(f"[DEBUG] 상세 오류:\n{traceback.format_exc()}")
            writer.close()
            await writer.wait_closed()
            return False

    def run_nso_cmd(self, cmd_input):
        """NSO CLI 명령어 실행"""
        full_cmd = f'docker exec cisco-nso-dev bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && echo \\"{cmd_input}\\" | ncs_cli -C -u admin"'
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
        return result

    def register_to_nso(self, device):
        """NSO에 장비 등록 및 동기화"""
        print(f"\n{'='*60}")
        print(f"[NSO] {device['name']} ({device['oob_ip']}) 등록 시작")
        print(f"{'='*60}")
        
        name = device['name']
        ip = device['oob_ip']
        authgroup = self.global_settings['nso_authgroup']
        ned_id = self.global_settings['nso_ned_id']
        
        print(f"[DEBUG] NSO 등록 정보:")
        print(f"  - 장비명: {name}")
        print(f"  - IP: {ip}")
        print(f"  - Authgroup: {authgroup}")
        print(f"  - NED ID: {ned_id}")
        
        # 1. 기본 설정
        cmds = [
            f"config",
            f"devices device {name} address {ip}",
            f"devices device {name} port 22",
            f"devices device {name} authgroup {authgroup}",
            f"devices device {name} device-type cli ned-id {ned_id}",
            f"devices device {name} state admin-state unlocked",
            # SSH 알고리즘 설정
            f"devices device {name} ssh-algorithms cipher aes128-cbc",
            f"devices device {name} ssh-algorithms cipher 3des-cbc",
            f"devices device {name} ssh-algorithms cipher aes256-cbc",
            f"devices device {name} ssh-algorithms kex diffie-hellman-group14-sha1",
            f"devices device {name} ssh-algorithms mac hmac-sha1",
            f"devices device {name} ssh-algorithms public-key ssh-rsa",
            f"commit",
            f"exit"
        ]
        
        print(f"\n[1/3] NSO 설정 적용 중... ({len(cmds)}개 명령)")
        for i, cmd in enumerate(cmds, 1):
            print(f"  [{i}/{len(cmds)}] {cmd[:50]}...")
            res = self.run_nso_cmd(cmd)
            if res.returncode != 0:
                print(f"    [WARNING] 명령 실행 오류: {res.stderr[:100]}")
            
        # 2. SSH 호스트 키 가져오기
        print(f"\n[2/3] SSH 호스트 키 가져오는 중...")
        res = self.run_nso_cmd(f"devices device {name} ssh fetch-host-keys")
        print(f"  [DEBUG] 명령 실행 결과:")
        print(f"    - Return code: {res.returncode}")
        print(f"    - Stdout: {res.stdout[:200]}")
        if res.stderr:
            print(f"    - Stderr: {res.stderr[:200]}")
        
        if "result updated" in res.stdout or "result true" in res.stdout:
            print(f"  [OK] SSH 키 가져오기 성공")
        else:
            print(f"  [FAIL] SSH 키 가져오기 실패")

        # 3. Sync-from
        print(f"\n[3/3] 장비 동기화(sync-from) 중...")
        res = self.run_nso_cmd(f"devices device {name} sync-from")
        print(f"  [DEBUG] 명령 실행 결과:")
        print(f"    - Return code: {res.returncode}")
        print(f"    - Stdout: {res.stdout[:200]}")
        if res.stderr:
            print(f"    - Stderr: {res.stderr[:200]}")
            
        if "result true" in res.stdout:
            print(f"  [OK] 동기화 성공!")
        else:
            print(f"  [FAIL] 동기화 실패")

    async def run(self):
        print("\n" + "="*60)
        print("=== Pnetlab 장비 자동화 시작 ===")
        print("="*60)

        # 1단계: 모든 장비의 SSH 활성화
        print(f"\n{'#'*60}")
        print("[1단계] 모든 장비 SSH 활성화 시작")
        print(f"{'#'*60}")
        successful_devices = []

        for i, device in enumerate(self.config['devices'], 1):
            print(f"\n진행: {i}/{len(self.config['devices'])}")
            if await self.enable_ssh_via_telnet(device):
                successful_devices.append(device)
                print(f"[OK] {device['name']} 성공")
            else:
                print(f"[FAIL] {device['name']} 실패")

        # SSH 서비스가 완전히 올라올 때까지 대기
        if successful_devices:
            print(f"\n{'='*60}")
            print(f"모든 장비 SSH 활성화 완료!")
            print(f"성공: {len(successful_devices)}/{len(self.config['devices'])}")
            print(f"SSH 서비스 안정화를 위해 5초 대기 중...")
            print(f"{'='*60}")
            await asyncio.sleep(5)
        else:
            print(f"\n[WARNING] SSH 활성화에 성공한 장비가 없습니다.")
            return

        # 2단계: 성공한 장비들만 NSO 등록
        print(f"\n{'#'*60}")
        print("[2단계] NSO 등록 시작")
        print(f"{'#'*60}")
        for i, device in enumerate(successful_devices, 1):
            print(f"\n진행: {i}/{len(successful_devices)}")
            self.register_to_nso(device)

        print(f"\n{'='*60}")
        print(f"=== 모든 작업 완료 ===")
        print(f"총 {len(self.config['devices'])}개 중 {len(successful_devices)}개 장비 처리 성공")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    print("[DEBUG] 스크립트 시작")
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERROR] 오류: 설정 파일을 찾을 수 없습니다. {CONFIG_FILE}")
        sys.exit(1)

    print(f"[OK] 설정 파일 확인: {CONFIG_FILE}")
    manager = DeviceManager(CONFIG_FILE)
    asyncio.run(manager.run())
    print("[DEBUG] 스크립트 종료")
