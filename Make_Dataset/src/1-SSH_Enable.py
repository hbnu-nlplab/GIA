import json
import asyncio
import telnetlib3
import time
import sys
import os

# 설정 파일 경로 (사용자 환경에 맞게 수정 필요)
# 실제 경로를 확인해주세요. 예: ./device_info.json
CONFIG_FILE = r"c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\L2VPN\device_info.json"

class SSHEnabler:
    def __init__(self, config_file):
        print(f"[DEBUG] 설정 파일 로드 중: {config_file}")
        self.config = self.load_config(config_file)
        self.global_settings = self.config['global_settings']
        print(f"[DEBUG] 로드된 장비 수: {len(self.config['devices'])}")
        print(f"[DEBUG] Pnetlab VM IP: {self.global_settings['pnetlab_vm_ip']}")

    def load_config(self, filepath):
        # 인코딩 문제 방지를 위해 utf-8 명시
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

        try:
            print(f"[DEBUG] Telnet 연결 시도 중... (timeout=10초)")
            # 연결 타임아웃 설정
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port), timeout=10
            )
            print(f"[OK] Telnet 접속 성공: {host}:{port}")
        except Exception as e:
            print(f"[FAIL] Telnet 접속 실패: {e}")
            return False

        # 명령어 전송 헬퍼 함수
        async def send_cmd(cmd, sleep_time=1.0, debug_msg=""):
            if debug_msg:
                print(f"  [CMD] {debug_msg}: {cmd}")
            
            # 명령어 뒤에 개행 문자 추가하여 전송
            writer.write(cmd + "\r\n")
            
            # 장비가 처리할 시간을 줌 (기본 1초로 증가)
            await asyncio.sleep(sleep_time)
            
            # 응답 읽기 (버퍼 비우기 용도 및 디버깅)
            try:
                # 너무 많이 읽으려다 멈추지 않게 타임아웃 설정
                data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                # print(f"    [Response] {data}") # 필요시 주석 해제하여 응답 확인
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        try:
            # 1. 초기 진입 (엔터 몇 번 쳐서 프롬프트 확인)
            print(f"\n[1/11] 세션 초기화...")
            writer.write("\r\n\r\n")
            await asyncio.sleep(1)

            # 2. Enable 모드
            print(f"[2/11] Enable 모드 진입...")
            await send_cmd("enable", debug_msg="Enable")
            # 비밀번호가 설정된 경우에만 전송
            if self.global_settings.get('enable_password'):
                await send_cmd(self.global_settings['enable_password'], debug_msg="Password")

            # 3. Config 모드
            print(f"[3/11] 설정 모드 진입...")
            await send_cmd("conf t", debug_msg="Config Terminal")
            await send_cmd("no ip domain-lookup", debug_msg="No Domain Lookup")

            # 4. 호스트네임
            print(f"[4/11] 호스트네임 설정: {device['name']}")
            await send_cmd(f"hostname {device['name']}", debug_msg="Hostname")

            # 5. OOB 인터페이스 설정
            print(f"[5/11] OOB 인터페이스 설정...")
            await send_cmd("interface Ethernet0/0", debug_msg="Interface Eth0/0")
            await send_cmd(f"ip address {device['oob_ip']} 255.255.255.0", debug_msg="IP Address")
            await send_cmd("no shutdown", debug_msg="No Shutdown", sleep_time=2.0) # 인터페이스 켜지는 시간 대기
            await send_cmd("exit", debug_msg="Exit Interface")

            # 6. 라우팅 설정
            print(f"[6/11] 기본 경로 설정...")
            gateway = self.global_settings['gateway_ip']
            await send_cmd(f"ip route 0.0.0.0 0.0.0.0 {gateway}", debug_msg=f"Default Route -> {gateway}")

            # 7. SSH 도메인 설정
            print(f"[7/11] SSH 도메인 설정...")
            domain = self.global_settings['domain_name']
            await send_cmd(f"ip domain-name {domain}", debug_msg=f"Domain Name {domain}")

            # 8. RSA 키 생성 (중요: 기존 키 삭제 후 재생성)
            print(f"[8/11] RSA 키 생성 (시간 소요됨)...")
            await send_cmd("crypto key zeroize rsa", debug_msg="기존 키 삭제", sleep_time=2.0)
            # 확인 질문(yes/no)이 나올 수 있으므로 'yes' 입력 시도 (안 나오면 무시됨)
            writer.write("yes\r\n") 
            await asyncio.sleep(1)
            
            # 키 생성 명령
            writer.write("crypto key generate rsa general-keys modulus 1024\r\n")
            print("  [WAIT] 키 생성 중... (10초 대기)")
            await asyncio.sleep(10) # 넉넉하게 대기

            # 9. 관리자 계정
            print(f"[9/11] 관리자 계정 생성...")
            admin_pw = self.global_settings['admin_password']
            # 비밀번호 평문 저장 방지용 secret 사용 권장하지만 여기선 일단 입력받은대로
            await send_cmd(f"username admin privilege 15 secret {admin_pw}", debug_msg="Admin User")

            # 10. VTY (SSH) 설정
            print(f"[10/11] VTY(SSH) 설정...")
            await send_cmd("line vty 0 4", debug_msg="Line VTY 0 4")
            await send_cmd("transport input ssh", debug_msg="Transport Input SSH")
            await send_cmd("login local", debug_msg="Login Local")
            await send_cmd("exit", debug_msg="Exit VTY")
            
            # SSH 버전 2 설정 (호환성)
            await send_cmd("ip ssh version 2", debug_msg="SSH Version 2")

            # 11. 저장
            print(f"[11/11] 설정 저장...")
            await send_cmd("end", debug_msg="End Config")
            await send_cmd("write memory", debug_msg="Write Memory", sleep_time=5.0) # 저장 시간 대기

            print(f"\n[SUCCESS] {device['name']} 설정 완료. 연결 종료.")
            writer.close()
            await writer.wait_closed()
            return True

        except Exception as e:
            print(f"\n[ERROR] 설정 중 예외 발생: {e}")
            import traceback
            traceback.print_exc()
            writer.close()
            await writer.wait_closed()
            return False

    async def run(self):
        print("작업 시작...")
        for device in self.config['devices']:
            await self.enable_ssh_via_telnet(device)
        print("작업 종료.")

# 실행부
if __name__ == "__main__":
    # 설정 파일이 실제로 존재하는지 확인
    if os.path.exists(CONFIG_FILE):
        enabler = SSHEnabler(CONFIG_FILE)
        asyncio.run(enabler.run())
    else:
        print(f"[ERROR] 설정 파일을 찾을 수 없습니다: {CONFIG_FILE}")
        # 테스트용 더미 파일 생성 코드 (필요시 사용)
        # ...