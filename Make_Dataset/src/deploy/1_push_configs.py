#!/usr/bin/env python3
"""
Step 1: Config Push via Telnet Console
=======================================
Config Generator가 생성한 .cfg 파일을 PNETLab 장비에 자동 적용.

사용법:
  # Lab-B 전체 (기본)
  python -m deploy.1_push_configs

  # 특정 장비만
  python -m deploy.1_push_configs --only P1,PE1

  # dry-run
  python -m deploy.1_push_configs --dry-run

  # 다른 Lab
  python -m deploy.1_push_configs \
    --device-info Data/Pnetlab/LabC_.../device_info.json \
    --configs-dir Make_Dataset/config_generator/output/LabC_.../configs
"""

import asyncio
import argparse
import re
import sys
import os
from pathlib import Path

try:
    import telnetlib3
except ImportError:
    sys.exit("[ERROR] pip install telnetlib3")

from deploy._common import ROOT, DEFAULT_DEVICE_INFO, add_common_args, load_and_filter_devices

# ── 기본 경로 ──
DEFAULT_CFGS = ROOT / "Make_Dataset/config_generator/output/LabB_NCN_Basic_SP_20nodes/configs"

# ── .cfg 파서: configure terminal에서 실행할 명령어만 추출 ──
SKIP = [re.compile(p) for p in [
    r"^\s*$", r"^\s*!", r"^version\s", r"^end\s*$",
    r"^Building\s", r"^Current\s", r"^boot-\w+-marker",
]]


def parse_cfg(path: Path) -> list[str]:
    """Parse .cfg → list of CLI commands for config terminal mode."""
    lines = path.read_text(encoding="utf-8").splitlines()
    cmds = []
    in_banner = False
    delim = None

    for raw in lines:
        line = raw.rstrip()

        # banner multi-line 처리
        if in_banner:
            cmds.append(line)
            if delim and delim in line:
                in_banner = False
            continue
        if line.startswith("banner "):
            cmds.append(line)
            parts = line.split(None, 3)
            if len(parts) >= 3:
                delim = parts[2][0]
                in_banner = line.count(delim) < 2
            continue

        if any(p.match(line) for p in SKIP):
            continue

        # crypto key → 프롬프트 자동 응답 필요
        if "crypto key generate rsa" in line:
            cmds.append("crypto key generate rsa modulus 2048")
            continue

        cmds.append(line)
    return cmds


async def push_one(host: str, port: int, name: str, cmds: list[str],
                    enable_pw: str = "") -> str:
    """Push config to one device. Returns status string."""
    if port == 0:
        return "SKIP(port=0)"

    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=10)
    except Exception as e:
        return f"CONN_FAIL({e})"

    async def drain():
        try:
            await asyncio.wait_for(reader.read(8192), timeout=0.4)
        except Exception:
            pass

    try:
        # 프롬프트 확보
        writer.write("\r\n\r\n")
        await asyncio.sleep(1)
        await drain()

        # enable
        writer.write("enable\r\n")
        await asyncio.sleep(0.5)
        await drain()
        if enable_pw:
            writer.write(enable_pw + "\r\n")
            await asyncio.sleep(0.5)
            await drain()

        # configure terminal
        writer.write("configure terminal\r\n")
        await asyncio.sleep(0.5)
        await drain()

        # 명령어 배치 전송 (5줄씩 + 0.4초 대기)
        BATCH = 5
        for i in range(0, len(cmds), BATCH):
            batch = cmds[i:i + BATCH]
            for cmd in batch:
                writer.write(cmd + "\r\n")
            await asyncio.sleep(0.4)
            await drain()

            # crypto key 생성 프롬프트 처리
            if any("crypto key" in c for c in batch):
                await asyncio.sleep(1)
                writer.write("yes\r\n")
                await asyncio.sleep(2)
                await drain()

        # 저장
        writer.write("end\r\n")
        await asyncio.sleep(0.3)
        writer.write("write memory\r\n")
        await asyncio.sleep(2)
        await drain()

        writer.close()
        return "OK"

    except Exception as e:
        try:
            writer.close()
        except Exception:
            pass
        return f"PUSH_FAIL({e})"


async def main():
    parser = argparse.ArgumentParser(description="Step 1: Push .cfg to PNETLab devices")
    add_common_args(parser)
    parser.add_argument("--configs-dir", type=Path, default=DEFAULT_CFGS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cfg, devices = load_and_filter_devices(args)
    gs = cfg["global_settings"]
    host = gs["pnetlab_vm_ip"]
    enable_pw = gs.get("enable_password", "")

    print(f"\n{'='*55}")
    print(f"  STEP 1: CONFIG PUSH — {len(devices)} devices")
    print(f"  PNETLab: {host}")
    print(f"  Configs: {args.configs_dir}")
    print(f"{'='*55}\n")

    results = {}
    for d in devices:
        name = d["name"]
        cfg_path = args.configs_dir / f"{name}.cfg"

        if not cfg_path.exists():
            results[name] = "NO_CFG"
            print(f"  [✗] {name:8s} — {cfg_path.name} not found")
            continue

        cmds = parse_cfg(cfg_path)
        print(f"  [{name:8s}] {len(cmds)} cmds ... ", end="", flush=True)

        if args.dry_run:
            results[name] = "DRY_RUN"
            print("DRY_RUN")
            continue

        status = await push_one(host, d["telnet_port"], name, cmds, enable_pw)
        results[name] = status
        icon = "✓" if status == "OK" else "✗"
        print(f"{icon} {status}")

    # 요약
    ok = sum(1 for s in results.values() if s == "OK")
    print(f"\n{'='*55}")
    print(f"  RESULT: {ok}/{len(results)} OK")
    print(f"{'='*55}")

    failed = [n for n, s in results.items() if s not in ("OK", "DRY_RUN", "SKIP(port=0)")]
    if failed:
        print(f"\n  재시도: python -m deploy.1_push_configs --only {','.join(failed)}")


if __name__ == "__main__":
    asyncio.run(main())
