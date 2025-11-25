import subprocess
import sys

# ▼▼▼ 1. 여기에 등록할 장비 목록 (이름, IP)을 수정하세요 ▼▼▼
devices_list = [
    ("CE02", "10.10.10.102"),
    # ("CE03", "10.10.10.103"),
    # ("CE04", "10.10.10.104"),
    # ("P01", "10.10.10.2"),
    # ("PE02", "10.10.10.3"),
]
DEVICE_PORT = 22
DEVICE_AUTHGROUP = "L2VPN"
DEVICE_NED_ID = "cisco-ios-cli-6.110"



def run_cli_command(cmd_input):
    """NSO CLI 명령어 실행 헬퍼 함수 - Docker 컨테이너 내에서 실행"""
    full_cmd = f'docker exec cisco-nso-dev bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && echo \\"{cmd_input}\\" | ncs_cli -C -u admin"'
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    return result

def setup_devices():
    print("--- NSO 장비 자동 등록 스크립트 시작 ---")

    # --- 1단계: NSO CLI를 사용한 장비 설정 추가 ---
    print(f"1. NSO에 {len(devices_list)}개 장비 설정 중...")

    for name, ip in devices_list:
        print(f"\n  [장비 등록] {name} ({ip})")

        # 기본 설정 - 각 명령어를 개별적으로 실행
        print(f"    기본 설정 중...")
        config_cmds = [
            f"config",
            f"devices device {name} address {ip}",
            f"devices device {name} port {DEVICE_PORT}",
            f"devices device {name} authgroup {DEVICE_AUTHGROUP}",
            f"devices device {name} device-type cli ned-id {DEVICE_NED_ID}",
            f"devices device {name} state admin-state unlocked",
            f"commit",
            f"exit"
        ]
        
        for cmd in config_cmds:
            result = run_cli_command(cmd)
            if result.returncode != 0 and "Commit complete" not in result.stdout:
                if "syntax error" not in result.stderr and "error" not in result.stderr.lower():
                    print(f"      {cmd}: 성공")

        # SSH 알고리즘 설정 - cipher, kex, mac, public-key
        print(f"    SSH 알고리즘 설정 중...")
        ssh_cmds = [
            f"config",
            f"devices device {name}",
            f"ssh-algorithms cipher aes128-cbc",
            f"ssh-algorithms cipher 3des-cbc",
            f"ssh-algorithms cipher aes256-cbc",
            f"ssh-algorithms kex diffie-hellman-group14-sha1",
            f"ssh-algorithms mac hmac-sha1",
            f"ssh-algorithms public-key ssh-rsa",
            f"commit",
            f"exit"
        ]
        
        for cmd in ssh_cmds:
            result = run_cli_command(cmd)
            if "Commit complete" in result.stdout:
                print(f"      SSH 알고리즘 설정 완료: 성공")
                break

    print("\n--- 2단계: SSH 키 가져오기 및 동기화 ---")
    for name, ip in devices_list:
        print(f"\n--- {name} ({ip}) 처리 중 ---")

        # 1) SSH 호스트 키 가져오기
        print(f"  [SSH 키] 호스트 키 가져오는 중...")
        result = run_cli_command(f"devices device {name} ssh fetch-host-keys")
        if "result updated" in result.stdout or "result true" in result.stdout:
            print(f"    SSH 호스트 키 가져오기 성공")
        else:
            print(f"    SSH 호스트 키 오류: {result.stdout.strip()}")

        # 2) 장비 설정 동기화
        print(f"  [동기화] 장비 설정 동기화 중...")
        result = run_cli_command(f"devices device {name} sync-from")
        if "result true" in result.stdout:
            print(f"    장비 동기화 성공!")
        else:
            print(f"    장비 동기화 오류: {result.stdout.strip()}")

    print("\n--- 모든 장비 등록 완료 ---")

if __name__ == '__main__':
    setup_devices()
    print("\n--- 모든 장비 등록 완료 ---")