import json
import subprocess
import time
import sys
import os

# 설정 파일 경로
SUCCESSFUL_DEVICES_FILE = r"c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\L2VPN\successful_devices.json"

class NSORegistrar:
    def __init__(self, successful_devices_file):
        print(f"[DEBUG] 성공 장비 파일 로드 중: {successful_devices_file}")
        if not os.path.exists(successful_devices_file):
            print(f"[ERROR] 성공 장비 파일을 찾을 수 없습니다: {successful_devices_file}")
            print("[INFO] 먼저 1-SSH_Enable.py를 실행하여 SSH 활성화를 완료하세요.")
            sys.exit(1)

        self.config = self.load_config(successful_devices_file)
        self.global_settings = self.config['global_settings']
        print(f"[DEBUG] 로드된 장비 수: {len(self.config['devices'])}")
        print(f"[DEBUG] Pnetlab VM IP: {self.global_settings['pnetlab_vm_ip']}")

    def load_config(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    def run_nso_cmd(self, cmd_input):
        """NSO CLI 단일 명령어 실행"""
        full_cmd = f'docker exec cisco-nso-dev bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && echo \\"{cmd_input}\\" | ncs_cli -C -u admin"'
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
        return result

    def run_nso_cmds(self, cmds):
        """NSO CLI 여러 명령어를 하나의 세션에서 실행"""
        # 모든 명령어를 줄바꿈으로 연결
        combined_cmds = "\\n".join(cmds)
        full_cmd = f'docker exec cisco-nso-dev bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && echo -e \\"{combined_cmds}\\" | ncs_cli -C -u admin"'
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

        # 1. 기본 설정 - 모든 명령어를 하나의 세션에서 실행
        cmds = [
            "config",
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
            "commit",
            "exit"
        ]

        print(f"\n[1/3] NSO 설정 적용 중... ({len(cmds)}개 명령)")
        res = self.run_nso_cmds(cmds)
        if res.returncode == 0:
            if "Commit complete" in res.stdout or "No modifications" in res.stdout:
                print(f"  [OK] 설정 적용 성공")
            else:
                print(f"  [INFO] 설정 적용 완료")
        else:
            print(f"  [WARNING] 설정 적용 중 오류: {res.stderr[:200]}")

        # 설정이 반영될 시간 대기
        time.sleep(1)

        # 2. SSH 호스트 키 가져오기
        print(f"\n[2/3] SSH 호스트 키 가져오는 중...")
        res = self.run_nso_cmd(f"devices device {name} ssh fetch-host-keys")
        print(f"  [DEBUG] 명령 실행 결과:")
        print(f"    - Stdout: {res.stdout[:200]}")

        # result unchanged, result updated, result new 모두 성공으로 처리
        if "result" in res.stdout and "fingerprint" in res.stdout:
            print(f"  [OK] SSH 키 가져오기 성공")
        elif "result updated" in res.stdout or "result new" in res.stdout:
            print(f"  [OK] SSH 키 가져오기 성공 (새로 업데이트됨)")
        elif "result unchanged" in res.stdout:
            print(f"  [OK] SSH 키 이미 존재함 (변경 없음)")
        else:
            print(f"  [FAIL] SSH 키 가져오기 실패")
            if res.stderr:
                print(f"    - Stderr: {res.stderr[:200]}")

        # 3. Sync-from
        print(f"\n[3/3] 장비 동기화(sync-from) 중...")
        res = self.run_nso_cmd(f"devices device {name} sync-from")
        print(f"  [DEBUG] 명령 실행 결과:")
        print(f"    - Stdout: {res.stdout[:200]}")

        if "result true" in res.stdout:
            print(f"  [OK] 동기화 성공!")
            return True
        else:
            print(f"  [FAIL] 동기화 실패")
            if res.stderr:
                print(f"    - Stderr: {res.stderr[:200]}")
            return False

    def run(self):
        print("\n" + "="*60)
        print("=== NSO 장비 등록 시작 ===")
        print("="*60)

        successful_registrations = 0

        for i, device in enumerate(self.config['devices'], 1):
            print(f"\n진행: {i}/{len(self.config['devices'])}")
            if self.register_to_nso(device):
                successful_registrations += 1
                print(f"[OK] {device['name']} NSO 등록 성공")
            else:
                print(f"[FAIL] {device['name']} NSO 등록 실패")

        print(f"\n{'='*60}")
        print(f"=== NSO 등록 작업 완료 ===")
        print(f"총 {len(self.config['devices'])}개 중 {successful_registrations}개 장비 NSO 등록 성공")
        print(f"{'='*60}\n")

        return successful_registrations

if __name__ == "__main__":
    print("[DEBUG] NSO 등록 스크립트 시작")

    registrar = NSORegistrar(SUCCESSFUL_DEVICES_FILE)
    successful_count = registrar.run()

    if successful_count > 0:
        print(f"[SUCCESS] {successful_count}개 장비가 NSO에 성공적으로 등록되었습니다.")
    else:
        print("[WARNING] NSO 등록에 성공한 장비가 없습니다.")

    print("[DEBUG] NSO 등록 스크립트 종료")