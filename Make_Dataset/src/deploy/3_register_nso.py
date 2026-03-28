#!/usr/bin/env python3
"""
Step 3: NSO Device Registration via RESTCONF
==============================================
모든 장비를 Cisco NSO에 등록하고 sync-from 수행.

전제 조건:
  1. NSO Docker 노드가 PNETLab에서 실행 중
  2. NSO 서비스 시작됨 (telnet으로 접속 후):
     - sudo -i
     - source /home/NSO/nso-5.3/ncsrc
     - cd /home/NSO/ncs-run && ncs
  3. NSO의 eth1이 Cloud0(관리망)에 연결, IP 설정 완료
  4. WSL에서 NSO RESTCONF 접근 가능 (Tailscale 또는 포트포워딩)

사용법:
  # 전체 등록
  python -m deploy.3_register_nso

  # 등록만 (sync-from 제외)
  python -m deploy.3_register_nso --no-sync

  # 특정 장비만
  python -m deploy.3_register_nso --only P1,PE1

  # NSO 상태 확인만
  python -m deploy.3_register_nso --status
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    sys.exit("[ERROR] pip install requests")

from deploy._common import add_common_args, load_and_filter_devices

HEADERS = {
    "Content-Type": "application/yang-data+json",
    "Accept": "application/yang-data+json",
}


class NSORegistrar:
    def __init__(self, base_url: str, username: str, password: str):
        self.base = base_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(HEADERS)
        self.session.verify = False  # self-signed cert

    def check_connection(self) -> bool:
        """NSO 연결 확인."""
        try:
            r = self.session.get(
                f"{self.base}/data/tailf-ncs:devices",
                timeout=10)
            return r.status_code in (200, 201)
        except Exception as e:
            print(f"  [✗] NSO 연결 실패: {e}")
            return False

    def ensure_ssh_rsa(self, nso_container: str = "cisco-nso-dev") -> bool:
        """NSO에 ssh-rsa public-key 알고리즘 설정 (IOS 15.x 호환).

        NSO 6.x는 기본적으로 ssh-rsa를 비활성화하지만,
        IOSv 15.x 장비는 ssh-rsa만 지원하므로 명시적 활성화 필요.
        """
        try:
            result = subprocess.run(
                ["docker", "exec", nso_container, "bash", "-c",
                 "source /root/nso-6.6/ncsrc && cd /root/ncs-instance && "
                 "echo 'configure\n"
                 "set devices global-settings ssh-algorithms public-key [ ssh-rsa ]\n"
                 "commit\n"
                 "end\n"
                 "exit' | ncs_cli -u admin"],
                capture_output=True, text=True, timeout=15)
            return "Commit complete" in result.stdout
        except Exception as e:
            print(f"    [warn] ssh-rsa 설정 실패: {e}")
            return False

    def list_devices(self) -> list[str]:
        """등록된 장비 목록."""
        try:
            r = self.session.get(
                f"{self.base}/data/tailf-ncs:devices/device",
                timeout=10)
            if r.status_code == 200:
                data = r.json()
                devs = data.get("tailf-ncs:device", [])
                return [d["name"] for d in devs]
            return []
        except Exception:
            return []

    def create_authgroup(self, group_name: str, username: str,
                         password: str, enable_password: str = "") -> bool:
        """인증 그룹 생성 (enable password 포함)."""
        default_map = {
            "remote-name": username,
            "remote-password": password,
        }
        # aaa new-model 장비는 enable secret 인증 필요
        if enable_password:
            default_map["remote-secondary-password"] = enable_password
        payload = {
            "tailf-ncs:group": {
                "name": group_name,
                "default-map": default_map,
            }
        }
        r = self.session.patch(
            f"{self.base}/data/tailf-ncs:devices/authgroups",
            json=payload, timeout=10)
        return r.status_code in (200, 201, 204)

    def register_device(self, name: str, ip: str, ned_id: str,
                        authgroup: str, port: int = 22) -> bool:
        """장비 등록."""
        payload = {
            "tailf-ncs:devices": {
                "device": [{
                    "name": name,
                    "address": ip,
                    "port": port,
                    "authgroup": authgroup,
                    "device-type": {
                        "cli": {
                            "ned-id": ned_id,
                            "protocol": "ssh",
                        }
                    },
                    "state": {
                        "admin-state": "unlocked",
                    },
                }]
            }
        }
        r = self.session.patch(
            f"{self.base}/data/tailf-ncs:devices",
            json=payload, timeout=10)
        return r.status_code in (200, 201, 204)

    def fetch_ssh_keys(self, name: str) -> bool:
        """SSH host key 가져오기."""
        try:
            r = self.session.post(
                f"{self.base}/data/tailf-ncs:devices/device={name}/ssh/fetch-host-keys",
                timeout=15)
            return r.status_code in (200, 204)
        except Exception as e:
            print(f"    [warn] fetch-keys {name}: {e}")
            return False

    def sync_from(self, name: str) -> bool:
        """sync-from 수행."""
        try:
            r = self.session.post(
                f"{self.base}/data/tailf-ncs:devices/device={name}/sync-from",
                timeout=120)
            if r.status_code in (200, 204):
                if not r.content:
                    return True
                data = r.json()
                output = data.get("tailf-ncs:output", {})
                result = output.get("result", "")
                # NSO returns bool true or string "true"
                if result is True or result == "true":
                    return True
                info = output.get("info", "")
                if info:
                    print(f"    [warn] {name}: {info[:100]}")
                return False
            print(f"    [warn] sync-from {name}: HTTP {r.status_code}")
            return False
        except Exception as e:
            print(f"    [warn] sync-from {name}: {e}")
            return False

    def device_status(self, name: str) -> str:
        """장비 상태 확인."""
        try:
            r = self.session.get(
                f"{self.base}/data/tailf-ncs:devices/device={name}/state",
                timeout=10)
            if r.status_code == 200:
                data = r.json()
                state = data.get("tailf-ncs:state", {})
                return state.get("oper-state", "unknown")
            return "not-found"
        except Exception as e:
            return f"error({e})"


def main():
    parser = argparse.ArgumentParser(description="Step 3: Register devices in NSO")
    add_common_args(parser)
    parser.add_argument("--no-sync", action="store_true",
                        help="등록만, sync-from 제외")
    parser.add_argument("--status", action="store_true",
                        help="현재 NSO 상태만 확인")
    # NSO 연결 오버라이드 (device_info.json 기본값 사용)
    parser.add_argument("--nso-url", help="NSO RESTCONF URL 오버라이드")
    args = parser.parse_args()

    cfg, devices = load_and_filter_devices(args)
    gs = cfg["global_settings"]

    # NSO 접속 정보: nso_ip (Cloud0 관리망) 우선
    required = ["nso_ip", "nso_username", "nso_password", "nso_authgroup", "nso_ned_id", "admin_password"]
    missing = [k for k in required if k not in gs]
    if missing:
        sys.exit(f"[ERROR] device_info.json에 필수 키 누락: {', '.join(missing)}")

    nso_ip = gs["nso_ip"]
    nso_port = gs.get("nso_port", 8080)
    nso_url = args.nso_url or f"http://{nso_ip}:{nso_port}/restconf"
    nso_user = gs["nso_username"]
    nso_pass = gs["nso_password"]
    authgroup = gs["nso_authgroup"]
    ned_id = gs["nso_ned_id"]
    admin_pw = gs["admin_password"]

    print(f"  [warn] HTTP(평문) 사용 중 — 연구실 내부망 전용", file=sys.stderr)

    print(f"\n{'='*55}")
    print(f"  STEP 3: NSO REGISTRATION — {len(devices)} devices")
    print(f"  NSO URL:    {nso_url}")
    print(f"  Authgroup:  {authgroup}")
    print(f"  NED:        {ned_id}")
    print(f"{'='*55}")

    # ── NSO 연결 ──
    nso = NSORegistrar(nso_url, nso_user, nso_pass)

    print(f"\n--- Phase 0: NSO Connection ---")
    if not nso.check_connection():
        print(f"\n  [!] NSO에 연결할 수 없습니다.")
        print(f"  확인 사항:")
        print(f"    1. NSO Docker 노드가 PNETLab에서 실행 중인지")
        print(f"    2. NSO 서비스가 시작되었는지 (ncs 명령)")
        print(f"    3. NSO RESTCONF가 {nso_url} 에서 접근 가능한지")
        print(f"    4. Tailscale 연결 상태")
        sys.exit(1)
    print(f"  [✓] NSO 연결 성공")

    # ── Status only ──
    if args.status:
        existing = nso.list_devices()
        print(f"\n--- NSO Registered Devices ({len(existing)}) ---")
        for name in existing:
            state = nso.device_status(name)
            print(f"  {name:8s} → {state}")
        return

    # ── Phase 0.5: SSH-RSA 알고리즘 설정 (IOSv 15.x 호환) ──
    nso_container = gs.get("nso_container", "cisco-nso-dev")
    print(f"\n--- Phase 0.5: SSH-RSA Algorithm ---")
    if nso.ensure_ssh_rsa(nso_container):
        print(f"  [✓] ssh-rsa public-key 설정 완료")
    else:
        print(f"  [!] ssh-rsa 설정 실패 (이미 설정되어 있을 수 있음, 계속 진행)")

    # ── Phase 1: Authgroup 생성 ──
    print(f"\n--- Phase 1: Create Authgroup '{authgroup}' ---")
    if nso.create_authgroup(authgroup, gs.get("nso_device_username", gs["nso_username"]), admin_pw, enable_password=admin_pw):
        print(f"  [✓] Authgroup '{authgroup}' 생성/갱신 완료")
    else:
        print(f"  [!] Authgroup 생성 실패 (이미 존재할 수 있음, 계속 진행)")

    # ── Phase 2: 장비 등록 ──
    print(f"\n--- Phase 2: Register Devices ---")
    reg_ok, reg_fail = 0, 0
    for d in devices:
        name = d["name"]
        ip = d["oob_ip"]
        ok = nso.register_device(name, ip, ned_id, authgroup)
        if ok:
            reg_ok += 1
            print(f"  [✓] {name:8s} ({ip}) registered")
        else:
            reg_fail += 1
            print(f"  [✗] {name:8s} ({ip}) FAILED")

    print(f"\n  Registered: {reg_ok}/{len(devices)}")

    # ── Phase 3: SSH Host Keys ──
    print(f"\n--- Phase 3: Fetch SSH Host Keys ---")
    for d in devices:
        name = d["name"]
        ok = nso.fetch_ssh_keys(name)
        icon = "✓" if ok else "✗"
        print(f"  [{icon}] {name:8s} ssh keys")
        time.sleep(0.5)  # NSO 부하 방지

    # ── Phase 4: Sync-from ──
    if not args.no_sync:
        print(f"\n--- Phase 4: Sync-from ---")
        sync_ok, sync_fail = 0, 0
        for d in devices:
            name = d["name"]
            ok = nso.sync_from(name)
            if ok:
                sync_ok += 1
                print(f"  [✓] {name:8s} synced")
            else:
                sync_fail += 1
                print(f"  [✗] {name:8s} sync FAILED")
            time.sleep(1)  # 장비 부하 방지

        print(f"\n  Synced: {sync_ok}/{len(devices)}")

    # ── 완료 ──
    print(f"\n{'='*55}")
    print(f"  NSO REGISTRATION COMPLETE")
    print(f"{'='*55}")
    print(f"\n  NSO WebUI: {nso_url.replace('/restconf','')}")
    print(f"  다음 단계:")
    print(f"    python Make_Dataset/src/main_batfish.py \\")
    print(f"      --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes \\")
    print(f"      --policies Make_Dataset/policies.json")


if __name__ == "__main__":
    main()
