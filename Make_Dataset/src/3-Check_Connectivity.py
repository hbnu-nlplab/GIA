import json
import asyncio
import telnetlib3
import sys
import os

CONFIG_FILE = r"c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\Research_Institute_Internal_DC\device_info.json"

class ConnectivityChecker:
    def __init__(self, config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        self.global_settings = self.config['global_settings']

    async def check_device(self, device):
        host = self.global_settings['pnetlab_vm_ip']
        port = device['telnet_port']
        name = device['name']
        print(f"\n[{name}] Connecting to {host}:{port}...")

        try:
            reader, writer = await asyncio.wait_for(telnetlib3.open_connection(host, port), timeout=5)
            
            # 엔터로 프롬프트 갱신
            writer.write("\r\n")
            await asyncio.sleep(1)
            
            # Enable 모드 (필요시)
            writer.write("enable\r\n")
            await asyncio.sleep(0.5)
            
            # Ping 테스트
            gateway = "10.10.10.1"
            print(f"  > Ping Gateway ({gateway}) 시도 중...")
            writer.write(f"ping {gateway}\r\n")
            
            # 결과 읽기 (최대 5초 대기)
            output = ""
            try:
                # 여러번 읽어서 출력 수집
                for _ in range(10):
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                    output += chunk
                    if "Success rate" in output:
                        break
            except asyncio.TimeoutError:
                pass
            
            # 결과 분석
            if "Success rate is 100 percent" in output: #  !!!!! (5/5)
                print(f"  [SUCCESS] Gateway Ping 성공!")
                result = True
            elif "Success rate is 0 percent" in output: # ..... (0/5)
                print(f"  [FAIL] Gateway Ping 실패 (응답 없음).")
                result = False
            else:
                print(f"  [UNCERTAIN] Ping 결과 불분명:\n{output[:200]}")
                result = False

            writer.close()
            await writer.wait_closed()
            return result

        except Exception as e:
            print(f"  [ERROR] 접속 실패: {e}")
            return False

    async def run(self):
        print("--- Ping Connectivity Check ---")
        # 첫 번째 장비(P1)만 테스트해도 충분함
        device = self.config['devices'][0] 
        success = await self.check_device(device)
        
        if not success:
            print("\n" + "="*50)
            print(" [진단 결과] Pnetlab 연결 문제 발견")
            print("="*50)
            print(" 1. Pnetlab 실험실 내부에 'Cloud' 노드가 없거나")
            print(" 2. Cloud 노드가 OOB 스위치에 연결되지 않았거나")
            print(" 3. Cloud 노드가 'pnet2'가 아닌 다른 인터페이스에 매핑됨")
            print(" -> 해결: Pnetlab 토폴로지에서 Network(Cloud0 또는 Cloud2)를 OOB 스위치에 연결하세요.")
        else:
            print("\n [진단 결과] L2 연결 정상. Tailscale 또는 라우팅 문제일 가능성 있음.")

if __name__ == "__main__":
    checker = ConnectivityChecker(CONFIG_FILE)
    asyncio.run(checker.run())
