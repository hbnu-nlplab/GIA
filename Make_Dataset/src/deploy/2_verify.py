#!/usr/bin/env python3
"""
Step 2: Deployment Verification
================================
Config push 후 모든 장비의 연결 상태 + 라우팅 프로토콜 검증.

사용법:
  # 전체 검증
  python -m deploy.2_verify

  # ping만 (빠른 확인)
  python -m deploy.2_verify --ping-only

  # 특정 장비만
  python -m deploy.2_verify --only P1,PE1
"""

import json
import asyncio
import argparse
import subprocess
import sys
from pathlib import Path

try:
    import telnetlib3
except ImportError:
    sys.exit("[ERROR] pip install telnetlib3")

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_INFO = ROOT / "Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/device_info.json"


async def run_show_cmd(host: str, port: int, enable_pw: str,
                       cmd: str, timeout: float = 3.0) -> str:
    """Telnet 콘솔로 show 명령어 실행, 결과 반환."""
    if port == 0:
        return "[port=0, skip]"
    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=8)
    except Exception as e:
        return f"[conn fail: {e}]"

    async def drain(t=0.5):
        try:
            return await asyncio.wait_for(reader.read(8192), timeout=t)
        except Exception:
            return ""

    try:
        writer.write("\r\n\r\n")
        await asyncio.sleep(0.8)
        await drain()
        writer.write("enable\r\n")
        await asyncio.sleep(0.3)
        await drain()
        if enable_pw:
            writer.write(enable_pw + "\r\n")
            await asyncio.sleep(0.3)
            await drain()

        # terminal length 0 (페이징 방지)
        writer.write("terminal length 0\r\n")
        await asyncio.sleep(0.3)
        await drain()

        # 명령어 실행
        writer.write(cmd + "\r\n")
        await asyncio.sleep(timeout)
        resp = await drain(2.0)
        writer.close()
        return resp.strip() if resp else "[no output]"
    except Exception as e:
        try:
            writer.close()
        except Exception:
            pass
        return f"[error: {e}]"


def ping_check(ip: str) -> bool:
    """1회 ping, 성공 여부 반환."""
    r = subprocess.run(
        ["ping", "-c", "1", "-W", "2", ip],
        capture_output=True, timeout=5)
    return r.returncode == 0


async def main():
    parser = argparse.ArgumentParser(description="Step 2: Verify deployment")
    parser.add_argument("--device-info", type=Path, default=DEFAULT_INFO)
    parser.add_argument("--only", help="P1,PE1,Leaf1")
    parser.add_argument("--ping-only", action="store_true")
    args = parser.parse_args()

    cfg = json.loads(args.device_info.read_text(encoding="utf-8"))
    gs = cfg["global_settings"]
    host = gs["pnetlab_vm_ip"]
    enable_pw = gs.get("enable_password", "")
    devices = cfg["devices"]

    if args.only:
        only = set(args.only.split(","))
        devices = [d for d in devices if d["name"] in only]

    print(f"\n{'='*55}")
    print(f"  STEP 2: VERIFY — {len(devices)} devices")
    print(f"  PNETLab: {host}")
    print(f"{'='*55}")

    # ── Phase 1: Ping (관리망) ──
    print(f"\n--- Phase 1: Management Ping (10.10.10.x) ---")
    ping_ok, ping_fail = [], []
    for d in devices:
        ok = ping_check(d["oob_ip"])
        (ping_ok if ok else ping_fail).append(d["name"])
        icon = "✓" if ok else "✗"
        print(f"  {icon} {d['name']:8s} {d['oob_ip']}")

    print(f"\n  Ping: {len(ping_ok)}/{len(devices)} OK")
    if ping_fail:
        print(f"  Failed: {', '.join(ping_fail)}")
        print(f"  → Cloud0(e7) 연결 또는 config 미적용 확인 필요")

    if args.ping_only:
        return

    # ── Phase 2: Protocol Check (telnet console) ──
    print(f"\n--- Phase 2: Protocol Verification ---")

    checks = {
        "p":  [("OSPF", "show ip ospf neighbor"),
               ("MPLS", "show mpls ldp neighbor")],
        "pe": [("OSPF", "show ip ospf neighbor"),
               ("MPLS", "show mpls ldp neighbor"),
               ("BGP",  "show bgp vpnv4 unicast summary"),
               ("VRF",  "show ip vrf brief")],
        "lf": [("Intf", "show ip interface brief")],
    }

    for d in devices:
        name = d["name"]
        role = "pe" if name.startswith("PE") else "p" if name.startswith("P") else "lf"
        port = d["telnet_port"]

        print(f"\n  [{name}] (port {port})")
        for label, cmd in checks[role]:
            resp = await run_show_cmd(host, port, enable_pw, cmd)
            # 첫 3줄만 표시
            lines = [l for l in resp.split("\n") if l.strip()][:3]
            summary = " | ".join(lines)[:100]
            has_data = any(kw in resp.lower() for kw in ["full", "established", "up"])
            icon = "✓" if has_data else "○"
            print(f"    {icon} {label:5s}: {summary}")

    print(f"\n{'='*55}")
    print(f"  VERIFICATION COMPLETE")
    print(f"{'='*55}")
    print(f"\n  다음 단계: python -m deploy.3_register_nso")


if __name__ == "__main__":
    asyncio.run(main())
