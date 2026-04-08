"""
Lab-B/C/D Config Push via Telnet Console

PNETLab 콘솔 텔넷을 통해 Config Generator가 생성한 .cfg 파일을
각 장비에 자동으로 밀어넣는 스크립트.

사용법:
  # Lab-B (기본)
  python Make_Dataset/src/4-Config_Push_Telnet.py

  # 특정 device_info.json 지정
  python Make_Dataset/src/4-Config_Push_Telnet.py \
    --device-info Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/device_info.json \
    --configs-dir Make_Dataset/config_generator/output/LabB_NCN_Basic_SP_20nodes/configs

  # 특정 장비만
  python Make_Dataset/src/4-Config_Push_Telnet.py --only P1,PE1,Leaf1

  # dry-run (실제 전송 안 함, 파싱만 확인)
  python Make_Dataset/src/4-Config_Push_Telnet.py --dry-run

  # 검증만 (config push 후 OSPF/BGP/MPLS 확인)
  python Make_Dataset/src/4-Config_Push_Telnet.py --verify-only
"""

import json
import asyncio
import argparse
import os
import sys
import re
from pathlib import Path

try:
    import telnetlib3
except ImportError:
    print("[ERROR] telnetlib3가 필요합니다: pip install telnetlib3")
    sys.exit(1)


# ═══════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════
DEFAULT_DEVICE_INFO = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "Data", "Pnetlab", "LabB_NCN_Basic_SP_20nodes", "device_info.json"
)
DEFAULT_CONFIGS_DIR = os.path.join(
    os.path.dirname(__file__), "..",
    "config_generator", "output", "LabB_NCN_Basic_SP_20nodes", "configs"
)

# .cfg 파일에서 건너뛸 라인 패턴
SKIP_PATTERNS = [
    r"^\s*$",                    # 빈 줄
    r"^\s*!",                    # 주석
    r"^version\s+",              # version 15.x
    r"^end\s*$",                 # end
    r"^Building configuration",  # Building configuration...
    r"^Current configuration",   # Current configuration...
    r"^boot-start-marker",       # boot markers
    r"^boot-end-marker",
]
SKIP_RE = [re.compile(p) for p in SKIP_PATTERNS]

# 인터페이스 no shutdown 자동 추가 (config에 없을 경우)
INTF_RE = re.compile(r"^interface\s+(GigabitEthernet|Loopback)", re.IGNORECASE)


def parse_cfg(filepath: str) -> list[str]:
    """Parse .cfg file into list of CLI commands for configure terminal mode."""
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    commands = []
    in_banner = False
    banner_delim = None

    for raw_line in lines:
        line = raw_line.rstrip()

        # Banner 처리 (multi-line)
        if in_banner:
            commands.append(line)
            if banner_delim and banner_delim in line:
                in_banner = False
            continue

        if line.startswith("banner "):
            commands.append(line)
            # 배너 구분자 감지 (예: ^C, ^, #)
            parts = line.split(None, 3)
            if len(parts) >= 3:
                banner_delim = parts[2][0]  # 첫 번째 문자가 구분자
                # 같은 줄에서 닫히면 배너 끝
                if line.count(banner_delim) >= 2:
                    in_banner = False
                else:
                    in_banner = True
            continue

        # 스킵 패턴 체크
        if any(p.match(line) for p in SKIP_RE):
            continue

        # crypto key generate rsa → 자동 응답 필요
        if "crypto key generate rsa" in line:
            # 이미 키가 있을 수 있으므로 yes 응답 + 별도 처리
            commands.append("crypto key generate rsa modulus 2048")
            continue

        commands.append(line)

    return commands


class ConfigPusher:
    def __init__(self, device_info_path: str, configs_dir: str,
                 only: list[str] | None = None, dry_run: bool = False):
        with open(device_info_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)
        self.global_settings = self.config["global_settings"]
        self.devices = self.config["devices"]
        self.configs_dir = Path(configs_dir)
        self.only = set(only) if only else None
        self.dry_run = dry_run
        self.results = {}

    async def send_cmd(self, writer, reader, cmd: str, delay: float = 0.3):
        """Send a command and wait for processing."""
        writer.write(cmd + "\r\n")
        await asyncio.sleep(delay)
        # 버퍼 비우기
        try:
            await asyncio.wait_for(reader.read(4096), timeout=0.3)
        except (asyncio.TimeoutError, Exception):
            pass

    async def push_config(self, device: dict) -> bool:
        """Push .cfg file to a single device via telnet console."""
        name = device["name"]
        host = self.global_settings["pnetlab_vm_ip"]
        port = device["telnet_port"]

        if port == 0:
            print(f"  [{name}] SKIP — telnet_port가 0 (미설정)")
            self.results[name] = "SKIP"
            return False

        # .cfg 파일 찾기
        cfg_path = self.configs_dir / f"{name}.cfg"
        if not cfg_path.exists():
            print(f"  [{name}] SKIP — {cfg_path} 파일 없음")
            self.results[name] = "NO_CFG"
            return False

        commands = parse_cfg(str(cfg_path))
        print(f"  [{name}] {len(commands)} commands from {cfg_path.name}")

        if self.dry_run:
            print(f"  [{name}] DRY-RUN — 전송하지 않음")
            for i, cmd in enumerate(commands[:5]):
                print(f"    {i+1}: {cmd}")
            if len(commands) > 5:
                print(f"    ... ({len(commands)-5} more)")
            self.results[name] = "DRY_RUN"
            return True

        # Telnet 연결
        try:
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port), timeout=10
            )
            print(f"  [{name}] Connected to {host}:{port}")
        except Exception as e:
            print(f"  [{name}] FAIL — Telnet 연결 실패: {e}")
            self.results[name] = f"CONN_FAIL: {e}"
            return False

        try:
            # 초기화: 엔터 몇 번 쳐서 프롬프트 확보
            writer.write("\r\n\r\n")
            await asyncio.sleep(1)
            try:
                await asyncio.wait_for(reader.read(4096), timeout=1)
            except (asyncio.TimeoutError, Exception):
                pass

            # Enable 모드 진입
            await self.send_cmd(writer, reader, "enable", 0.5)
            # enable password가 있으면 전송
            if self.global_settings.get("enable_password"):
                await self.send_cmd(writer, reader,
                                    self.global_settings["enable_password"], 0.5)

            # Configure terminal 진입
            await self.send_cmd(writer, reader, "configure terminal", 0.5)

            # Config 명령어 전송 (배치 단위로 전송하여 속도 향상)
            batch_size = 5
            for i in range(0, len(commands), batch_size):
                batch = commands[i:i + batch_size]
                for cmd in batch:
                    writer.write(cmd + "\r\n")
                await asyncio.sleep(0.5)
                # 버퍼 비우기
                try:
                    await asyncio.wait_for(reader.read(8192), timeout=0.3)
                except (asyncio.TimeoutError, Exception):
                    pass

                # crypto key 생성 시 yes 응답
                if any("crypto key" in c for c in batch):
                    await asyncio.sleep(1)
                    writer.write("yes\r\n")
                    await asyncio.sleep(2)
                    try:
                        await asyncio.wait_for(reader.read(4096), timeout=0.5)
                    except (asyncio.TimeoutError, Exception):
                        pass

            # Configure 모드 종료 + 저장
            await self.send_cmd(writer, reader, "end", 0.5)
            await self.send_cmd(writer, reader, "write memory", 2.0)

            # 확인: show hostname
            writer.write("show run | include hostname\r\n")
            await asyncio.sleep(0.5)
            try:
                resp = await asyncio.wait_for(reader.read(1024), timeout=1)
                if name.lower() in resp.lower():
                    print(f"  [{name}] OK — hostname 확인됨")
                else:
                    print(f"  [{name}] OK — config 전송 완료 (hostname 확인 불확실)")
            except Exception:
                print(f"  [{name}] OK — config 전송 완료")

            self.results[name] = "OK"
            writer.close()
            return True

        except Exception as e:
            print(f"  [{name}] FAIL — 전송 중 에러: {e}")
            self.results[name] = f"PUSH_FAIL: {e}"
            try:
                writer.close()
            except Exception:
                pass
            return False

    async def verify_device(self, device: dict) -> dict:
        """SSH로 장비에 접속하여 OSPF/MPLS 상태 확인."""
        name = device["name"]
        oob_ip = device["oob_ip"]
        host = self.global_settings["pnetlab_vm_ip"]
        port = device["telnet_port"]

        if port == 0:
            return {"name": name, "status": "SKIP"}

        try:
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port), timeout=10
            )
        except Exception as e:
            return {"name": name, "status": f"CONN_FAIL: {e}"}

        results = {}
        try:
            writer.write("\r\n\r\n")
            await asyncio.sleep(1)
            try:
                await asyncio.wait_for(reader.read(4096), timeout=1)
            except Exception:
                pass

            await self.send_cmd(writer, reader, "enable", 0.5)
            if self.global_settings.get("enable_password"):
                await self.send_cmd(writer, reader,
                                    self.global_settings["enable_password"], 0.5)

            # 검증 명령어 실행
            verify_cmds = [
                ("hostname", "show run | include hostname"),
                ("ospf", "show ip ospf neighbor"),
                ("interfaces", "show ip interface brief"),
            ]
            # PE 장비는 BGP도 확인
            if device["name"].startswith("PE"):
                verify_cmds.append(("bgp", "show bgp vpnv4 unicast summary"))
                verify_cmds.append(("mpls", "show mpls ldp neighbor"))

            for key, cmd in verify_cmds:
                writer.write(cmd + "\r\n")
                await asyncio.sleep(1)
                try:
                    resp = await asyncio.wait_for(reader.read(4096), timeout=2)
                    results[key] = resp.strip()
                except Exception:
                    results[key] = "timeout"

            writer.close()
            return {"name": name, "status": "OK", "data": results}

        except Exception as e:
            try:
                writer.close()
            except Exception:
                pass
            return {"name": name, "status": f"VERIFY_FAIL: {e}"}

    async def run(self, verify_only: bool = False):
        """Run config push for all devices."""
        devices = self.devices
        if self.only:
            devices = [d for d in devices if d["name"] in self.only]

        if verify_only:
            print(f"\n{'='*60}")
            print(f"  VERIFICATION MODE — {len(devices)} devices")
            print(f"{'='*60}\n")
            for device in devices:
                result = await self.verify_device(device)
                print(f"  [{result['name']}] {result['status']}")
                if "data" in result:
                    for key, val in result["data"].items():
                        # 첫 줄만 표시
                        first_line = str(val).split("\n")[0][:80]
                        print(f"    {key}: {first_line}")
            return

        print(f"\n{'='*60}")
        print(f"  CONFIG PUSH — {len(devices)} devices")
        print(f"  PNETLab VM: {self.global_settings['pnetlab_vm_ip']}")
        print(f"  Configs:    {self.configs_dir}")
        print(f"  Dry-run:    {self.dry_run}")
        print(f"{'='*60}\n")

        # 장비별 순차 실행 (동시 telnet은 PNETLab 부하 이슈)
        success = 0
        fail = 0
        for device in devices:
            ok = await self.push_config(device)
            if ok:
                success += 1
            else:
                fail += 1

        # 결과 요약
        print(f"\n{'='*60}")
        print(f"  RESULTS: {success} OK / {fail} FAIL / {len(devices)} Total")
        print(f"{'='*60}")
        for name, status in self.results.items():
            icon = "✓" if status == "OK" else "○" if status == "DRY_RUN" else "✗"
            print(f"  {icon} {name:8s} → {status}")

        if fail > 0:
            print(f"\n[TIP] 실패한 장비만 재시도:")
            failed = [n for n, s in self.results.items()
                      if s not in ("OK", "DRY_RUN", "SKIP")]
            print(f"  python {__file__} --only {','.join(failed)}")


def main():
    parser = argparse.ArgumentParser(
        description="PNETLab 장비에 Config Generator .cfg 파일 자동 적용"
    )
    parser.add_argument(
        "--device-info", default=DEFAULT_DEVICE_INFO,
        help="device_info.json 경로"
    )
    parser.add_argument(
        "--configs-dir", default=DEFAULT_CONFIGS_DIR,
        help=".cfg 파일 디렉토리 경로"
    )
    parser.add_argument(
        "--only", default=None,
        help="특정 장비만 (쉼표 구분: P1,PE1,Leaf1)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="실제 전송 없이 파싱만 확인"
    )
    parser.add_argument(
        "--verify-only", action="store_true",
        help="config push 없이 검증만 수행"
    )
    args = parser.parse_args()

    only = args.only.split(",") if args.only else None

    pusher = ConfigPusher(
        device_info_path=args.device_info,
        configs_dir=args.configs_dir,
        only=only,
        dry_run=args.dry_run,
    )
    asyncio.run(pusher.run(verify_only=args.verify_only))


if __name__ == "__main__":
    main()
