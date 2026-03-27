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

  # RSA 키 생성 건너뛰기
  python -m deploy.1_push_configs --skip-rsa
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
    """Parse .cfg → list of CLI commands for config terminal mode.

    Changes from original:
    - crypto key generate rsa is EXCLUDED (handled separately after push)
    - 'no shutdown' is auto-injected after interface lines if missing
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    cmds = []
    in_banner = False
    delim = None
    prev_is_interface = False

    for raw in lines:
        line = raw.rstrip()

        # banner multi-line 처리
        if in_banner:
            cmds.append(line)
            if delim and delim in line:
                in_banner = False
            prev_is_interface = False
            continue
        if line.startswith("banner "):
            cmds.append(line)
            parts = line.split(None, 3)
            if len(parts) >= 3:
                delim = parts[2][0]
                in_banner = line.count(delim) < 2
            prev_is_interface = False
            continue

        if any(p.match(line) for p in SKIP):
            # interface 블록이 끝나는 빈 줄/! 에서 no shutdown 삽입
            if prev_is_interface:
                cmds.append(" no shutdown")
                prev_is_interface = False
            continue

        # crypto key → 별도 단계에서 처리하므로 config push에서 제외
        if "crypto key generate rsa" in line or "crypto key zeroize" in line:
            continue

        # aaa new-model → 별도 단계에서 제거 처리 (confirm 프롬프트 필요)
        if line.strip() == "aaa new-model":
            continue
        # aaa authentication → aaa new-model 없이는 불필요
        if line.strip().startswith("aaa "):
            continue

        # interface 블록 추적
        if line.startswith("interface "):
            # 이전 interface 블록이 no shutdown 없이 끝났으면 추가
            if prev_is_interface:
                cmds.append(" no shutdown")
            prev_is_interface = True
            cmds.append(line)
            continue

        # no shutdown이 이미 있으면 플래그 해제
        if prev_is_interface and line.strip() == "no shutdown":
            prev_is_interface = False

        # 다음 섹션 시작 (line/router/ip 등) → interface 블록 끝
        if prev_is_interface and not line.startswith(" "):
            cmds.append(" no shutdown")
            prev_is_interface = False

        cmds.append(line)

    # 파일 끝에서 interface 블록이 열려있었으면
    if prev_is_interface:
        cmds.append(" no shutdown")

    return cmds


async def _read_until(reader, timeout=0.5) -> str:
    """Read available data from telnet with timeout."""
    try:
        data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        return data if data else ""
    except Exception:
        return ""


async def _detect_and_login(reader, writer, admin_pw: str = "admin"):
    """Detect prompt state and handle login if needed.

    Handles:
    - Router> / Router# → just enable
    - Username: → login with admin/admin then enable
    - Initial config dialog → send 'no'
    """
    writer.write("\r\n\r\n")
    await asyncio.sleep(1.5)
    prompt = await _read_until(reader, 1.0)

    # Initial configuration dialog
    if "initial configuration dialog" in prompt.lower():
        writer.write("no\r\n")
        await asyncio.sleep(2)
        await _read_until(reader, 1.0)

    # Username prompt → login
    if "Username:" in prompt or "username:" in prompt.lower():
        writer.write(f"{admin_pw}\r\n")  # username = admin
        await asyncio.sleep(0.5)
        resp = await _read_until(reader, 0.5)
        if "Password:" in resp or "password:" in resp.lower():
            writer.write(f"{admin_pw}\r\n")  # password = admin
            await asyncio.sleep(0.5)
            await _read_until(reader, 0.5)

    # Password prompt (enable password)
    elif "Password:" in prompt:
        writer.write(f"{admin_pw}\r\n")
        await asyncio.sleep(0.5)
        await _read_until(reader, 0.5)


async def push_one(host: str, port: int, name: str, cmds: list[str],
                    enable_pw: str = "", admin_pw: str = "admin") -> str:
    """Push config to one device. Returns status string."""
    if port == 0:
        return "SKIP(port=0)"

    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=10)
    except Exception as e:
        return f"CONN_FAIL({e})"

    try:
        # 프롬프트 감지 및 로그인 처리
        await _detect_and_login(reader, writer, admin_pw)

        # enable
        writer.write("enable\r\n")
        await asyncio.sleep(0.5)
        resp = await _read_until(reader, 0.5)
        if enable_pw and "Password:" in resp:
            writer.write(enable_pw + "\r\n")
            await asyncio.sleep(0.5)
            await _read_until(reader)

        # configure terminal
        writer.write("configure terminal\r\n")
        await asyncio.sleep(0.5)
        await _read_until(reader)

        # 명령어 배치 전송 (5줄씩 + 0.4초 대기)
        BATCH = 5
        for i in range(0, len(cmds), BATCH):
            batch = cmds[i:i + BATCH]
            for cmd in batch:
                writer.write(cmd + "\r\n")
            await asyncio.sleep(0.4)
            await _read_until(reader)

        # 저장
        writer.write("end\r\n")
        await asyncio.sleep(0.3)
        writer.write("write memory\r\n")
        await asyncio.sleep(2)
        await _read_until(reader)

        writer.close()
        return "OK"

    except Exception as e:
        try:
            writer.close()
        except Exception:
            pass
        return f"PUSH_FAIL({e})"


async def generate_rsa_key(host: str, port: int, name: str,
                            admin_pw: str = "admin") -> str:
    """Generate RSA key on device (separate from config push).

    This is done as a separate step because:
    1. crypto key generate rsa is NOT a config command — it's exec-level
    2. It requires interactive prompt handling (yes/no for key replacement)
    3. It takes 5-10 seconds to complete
    4. Re-pushing config would NOT overwrite existing keys, but if done
       inside configure terminal, the prompt handling is unreliable
    """
    if port == 0:
        return "SKIP(port=0)"

    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=10)
    except Exception as e:
        return f"CONN_FAIL({e})"

    try:
        # 프롬프트 감지 및 로그인 처리
        await _detect_and_login(reader, writer, admin_pw)

        # enable
        writer.write("enable\r\n")
        await asyncio.sleep(0.5)
        await _read_until(reader)

        # configure terminal
        writer.write("configure terminal\r\n")
        await asyncio.sleep(0.5)
        await _read_until(reader)

        # 기존 키 삭제 (있으면)
        writer.write("crypto key zeroize rsa\r\n")
        await asyncio.sleep(2)
        # yes/no 프롬프트가 나올 수 있음
        writer.write("yes\r\n")
        await asyncio.sleep(1)
        await _read_until(reader, 1.0)

        # RSA 키 생성 (general-keys + modulus 2048)
        writer.write("crypto key generate rsa general-keys modulus 2048\r\n")
        await asyncio.sleep(10)  # 키 생성에 충분한 시간
        await _read_until(reader, 2.0)

        # 저장
        writer.write("end\r\n")
        await asyncio.sleep(0.3)
        writer.write("write memory\r\n")
        await asyncio.sleep(2)
        await _read_until(reader)

        writer.close()
        return "OK"

    except Exception as e:
        try:
            writer.close()
        except Exception:
            pass
        return f"RSA_FAIL({e})"


async def post_push_fixup(host: str, port: int, name: str,
                          admin_pw: str = "admin") -> str:
    """Post-push fixup: remove aaa new-model (with confirm) + ensure VTY login.

    After config push, devices with 'aaa new-model' in their original config
    need special handling because:
    1. 'no aaa new-model' requires interactive [confirm] prompt → send 'y'
    2. Removing AAA breaks VTY login → must re-apply 'login local'
    3. enable secret may block NSO → remove it
    """
    if port == 0:
        return "SKIP(port=0)"

    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=10)
    except Exception as e:
        return f"CONN_FAIL({e})"

    try:
        await _detect_and_login(reader, writer, admin_pw)

        writer.write("enable\r\n")
        await asyncio.sleep(0.5)
        resp = await _read_until(reader, 0.5)
        if "Password:" in resp or "assword:" in resp:
            writer.write(f"{admin_pw}\r\n")
            await asyncio.sleep(0.5)
            await _read_until(reader)

        writer.write("configure terminal\r\n")
        await asyncio.sleep(0.5)
        await _read_until(reader)

        # 1. Remove aaa new-model (requires [confirm] → send 'y')
        writer.write("no aaa new-model\r\n")
        await asyncio.sleep(1)
        writer.write("y\r\n")  # [confirm] 응답
        await asyncio.sleep(1)
        await _read_until(reader, 1.0)

        # 2. Remove enable secret/password
        writer.write("no enable secret\r\n")
        await asyncio.sleep(0.3)
        await _read_until(reader)
        writer.write("no enable password\r\n")
        await asyncio.sleep(0.3)
        await _read_until(reader)

        # 3. Restore VTY login local (AAA 제거 후 필요)
        writer.write("line vty 0 4\r\n")
        await asyncio.sleep(0.3)
        await _read_until(reader)
        writer.write("login local\r\n")
        await asyncio.sleep(0.3)
        await _read_until(reader)
        writer.write("transport input ssh\r\n")
        await asyncio.sleep(0.3)
        await _read_until(reader)
        writer.write("exit\r\n")
        await asyncio.sleep(0.3)
        await _read_until(reader)

        # 저장
        writer.write("end\r\n")
        await asyncio.sleep(0.3)
        writer.write("write memory\r\n")
        await asyncio.sleep(2)
        await _read_until(reader)

        writer.close()
        return "OK"

    except Exception as e:
        try:
            writer.close()
        except Exception:
            pass
        return f"FIXUP_FAIL({e})"


def _cfg_has_aaa(cfg_path: Path) -> bool:
    """Check if .cfg file contains 'aaa new-model'."""
    try:
        return "aaa new-model" in cfg_path.read_text(encoding="utf-8")
    except Exception:
        return False


async def main():
    parser = argparse.ArgumentParser(description="Step 1: Push .cfg to PNETLab devices")
    add_common_args(parser)
    parser.add_argument("--configs-dir", type=Path, default=DEFAULT_CFGS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-rsa", action="store_true",
                        help="RSA 키 생성 단계 건너뛰기")
    args = parser.parse_args()

    cfg, devices = load_and_filter_devices(args)
    gs = cfg["global_settings"]
    host = gs["pnetlab_vm_ip"]
    enable_pw = gs.get("enable_password", "")
    admin_pw = gs.get("admin_password", "admin")

    print(f"\n{'='*55}")
    print(f"  STEP 1: CONFIG PUSH — {len(devices)} devices")
    print(f"  PNETLab: {host}")
    print(f"  Configs: {args.configs_dir}")
    print(f"{'='*55}\n")

    # ── Phase 1: Config Push ──
    print("--- Phase 1: Config Push ---")
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

        status = await push_one(host, d["telnet_port"], name, cmds,
                                enable_pw, admin_pw)
        results[name] = status
        icon = "✓" if status == "OK" else "✗"
        print(f"{icon} {status}")

    ok = sum(1 for s in results.values() if s == "OK")
    print(f"\n  Config Push: {ok}/{len(results)} OK")

    # ── Phase 2: RSA Key Generation ──
    if not args.dry_run and not args.skip_rsa:
        print(f"\n--- Phase 2: RSA Key Generation ---")
        rsa_results = {}
        for d in devices:
            name = d["name"]
            if results.get(name) != "OK":
                continue
            print(f"  [{name:8s}] generating RSA key ... ", end="", flush=True)
            status = await generate_rsa_key(host, d["telnet_port"], name,
                                            admin_pw)
            rsa_results[name] = status
            icon = "✓" if status == "OK" else "✗"
            print(f"{icon} {status}")

        rsa_ok = sum(1 for s in rsa_results.values() if s == "OK")
        print(f"\n  RSA Keys: {rsa_ok}/{len(rsa_results)} OK")

    # ── Phase 3: AAA Fixup (devices with aaa new-model) ──
    fixup_results = {}
    if not args.dry_run:
        aaa_devices = []
        for d in devices:
            name = d["name"]
            if results.get(name) != "OK":
                continue
            cfg_path = args.configs_dir / f"{name}.cfg"
            if _cfg_has_aaa(cfg_path):
                aaa_devices.append(d)

        if aaa_devices:
            print(f"\n--- Phase 3: AAA Fixup ({len(aaa_devices)} devices) ---")
            for d in aaa_devices:
                name = d["name"]
                print(f"  [{name:8s}] removing aaa + fixing VTY ... ", end="", flush=True)
                status = await post_push_fixup(host, d["telnet_port"], name,
                                               admin_pw)
                fixup_results[name] = status
                icon = "✓" if status == "OK" else "✗"
                print(f"{icon} {status}")

            fixup_ok = sum(1 for s in fixup_results.values() if s == "OK")
            print(f"\n  AAA Fixup: {fixup_ok}/{len(fixup_results)} OK")

    # ── 요약 ──
    print(f"\n{'='*55}")
    print(f"  RESULT: {ok}/{len(results)} configs pushed")
    if not args.dry_run and not args.skip_rsa:
        print(f"  RSA:    {rsa_ok}/{len(rsa_results)} keys generated")
    if fixup_results:
        fixup_ok = sum(1 for s in fixup_results.values() if s == "OK")
        print(f"  AAA:    {fixup_ok}/{len(fixup_results)} fixed")
    print(f"{'='*55}")

    failed = [n for n, s in results.items() if s not in ("OK", "DRY_RUN", "SKIP(port=0)")]
    if failed:
        print(f"\n  재시도: python -m deploy.1_push_configs --only {','.join(failed)}")


if __name__ == "__main__":
    asyncio.run(main())
