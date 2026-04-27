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

import asyncio
import argparse
import re
import subprocess
import sys
from pathlib import Path

try:
    import telnetlib3
except ImportError:
    sys.exit("[ERROR] pip install telnetlib3")

from deploy._common import add_common_args, load_and_filter_devices


async def run_show_cmd(host: str, port: int, enable_pw: str,
                       admin_pw: str,
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
        resp = await drain()

        if "initial configuration dialog" in resp.lower():
            writer.write("no\r\n")
            await asyncio.sleep(1.0)
            resp = await drain()

        if "Username:" in resp or "username:" in resp.lower():
            writer.write(f"{admin_pw}\r\n")
            await asyncio.sleep(0.4)
            resp = await drain()
            if "Password:" in resp or "password:" in resp.lower():
                writer.write(f"{admin_pw}\r\n")
                await asyncio.sleep(0.5)
                await drain()
        elif "Password:" in resp or "password:" in resp.lower():
            writer.write(f"{admin_pw}\r\n")
            await asyncio.sleep(0.5)
            await drain()

        writer.write("enable\r\n")
        await asyncio.sleep(0.3)
        resp = await drain()
        if "Password:" in resp or "password:" in resp.lower():
            writer.write((enable_pw or admin_pw) + "\r\n")
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


def parse_hostname(output: str) -> str:
    """Extract hostname from show output."""
    m = re.search(r"(?im)^\s*(\S+)\s+uptime\s+is\b", output)
    if m:
        return m.group(1)

    m = re.search(r"(?im)^\s*hostname\s+(\S+)\s*$", output)
    if m:
        return m.group(1)

    m = re.search(r"(?m)^([A-Za-z][A-Za-z0-9_-]*)[#>]\s*$", output)
    if m and m.group(1) not in {"Username", "Password"}:
        return m.group(1)
    return ""


def parse_interface_ip(output: str, interface: str) -> str:
    """Extract interface IP from show ip interface brief output."""
    if_short = interface.replace("GigabitEthernet", "Gi")
    candidates = {interface, if_short}
    for line in output.splitlines():
        if "IP-Address" in line or "Interface" in line:
            continue
        if any(token in line for token in candidates):
            parts = line.split()
            if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
                return parts[1]
    return ""


def ping_check(ip: str) -> bool:
    """1회 ping, 성공 여부 반환."""
    r = subprocess.run(
        ["ping", "-c", "1", "-W", "2", ip],
        capture_output=True, timeout=5)
    return r.returncode == 0


async def main():
    parser = argparse.ArgumentParser(description="Step 2: Verify deployment")
    add_common_args(parser)
    parser.add_argument("--ping-only", action="store_true")
    parser.add_argument("--no-identity-check", action="store_true",
                        help="Skip console hostname/OOB IP identity check")
    args = parser.parse_args()

    cfg, devices = load_and_filter_devices(args)
    gs = cfg["global_settings"]
    host = gs["pnetlab_vm_ip"]
    enable_pw = gs.get("enable_password", "")
    admin_pw = gs.get("admin_password", "admin")

    print(f"\n{'='*55}")
    print(f"  STEP 2: VERIFY — {len(devices)} devices")
    print(f"  PNETLab: {host}")
    print(f"{'='*55}")

    # ── Phase 0: Console identity check ──
    if not args.no_identity_check:
        print(f"\n--- Phase 0: Console Identity ---")
        identity_fail = []
        for d in devices:
            name = d["name"]
            port = d["telnet_port"]
            oob_intf = d.get("oob_intf", "GigabitEthernet0/7")
            expected_ip = d["oob_ip"]

            host_out = await run_show_cmd(
                host, port, enable_pw, admin_pw,
                "show version",
                timeout=2.5,
            )
            ip_out = await run_show_cmd(
                host, port, enable_pw, admin_pw,
                "show ip interface brief",
                timeout=2.0,
            )
            actual_name = parse_hostname(host_out)
            actual_ip = parse_interface_ip(ip_out, oob_intf)
            name_ok = (actual_name == name) or (not actual_name and actual_ip == expected_ip)
            ok = name_ok and (actual_ip == expected_ip)
            if not ok:
                identity_fail.append(name)
            icon = "✓" if ok else "✗"
            hostname_display = actual_name or "?"
            if ok and not actual_name:
                hostname_display += " (oob-match)"
            print(
                f"  {icon} {name:8s} port={port} "
                f"hostname={hostname_display} "
                f"oob={actual_ip or '?'} expected={expected_ip}"
            )

        if identity_fail:
            print(f"\n  Identity: {len(devices) - len(identity_fail)}/{len(devices)} OK")
            print(f"  Failed: {', '.join(identity_fail)}")
            print("  → device_info.json의 telnet_port와 PNETLab node_id 매핑을 먼저 수정하세요.")
            return

    # ── Phase 1: Ping (관리망) ──
    print(f"\n--- Phase 1: Management Ping ---")
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
            resp = await run_show_cmd(host, port, enable_pw, admin_pw, cmd)
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
