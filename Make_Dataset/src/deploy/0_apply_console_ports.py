#!/usr/bin/env python3
"""
Step 0: Apply PNETLab console ports to device_info.json.

PNETLab .unl node id is not a reliable runtime telnet port. Use the port
shown by the PNETLab web UI/runtime and map it by device name.

Input map formats accepted:
  P1 30114
  P1,30114
  30114 P1
  {"P1": 30114, "P2": 30115}
"""

import argparse
import json
import re
from pathlib import Path
from typing import Dict

from deploy._common import DEFAULT_DEVICE_INFO


PORT_RE = re.compile(r"\b([1-9]\d{4})\b")


def load_device_info(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def parse_port_map(path: Path, known_names: set[str]) -> Dict[str, int]:
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except Exception:
        payload = None

    if isinstance(payload, dict):
        return {str(k): int(v) for k, v in payload.items() if str(k) in known_names}

    result: Dict[str, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        ports = [int(p) for p in PORT_RE.findall(line)]
        names = [name for name in known_names if re.search(rf"\b{re.escape(name)}\b", line)]
        if len(ports) == 1 and len(names) == 1:
            result[names[0]] = ports[0]

    return result


def validate_map(port_map: Dict[str, int], expected_names: set[str]) -> list[str]:
    errors = []
    missing = sorted(expected_names - set(port_map))
    if missing:
        errors.append("missing devices: " + ", ".join(missing))

    seen: Dict[int, str] = {}
    duplicates = []
    for name, port in port_map.items():
        if port in seen:
            duplicates.append(f"{port}: {seen[port]}, {name}")
        seen[port] = name
    if duplicates:
        errors.append("duplicate ports: " + "; ".join(duplicates))

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply PNETLab web console ports")
    parser.add_argument("--device-info", type=Path, default=DEFAULT_DEVICE_INFO)
    parser.add_argument("--map", type=Path, required=True,
                        help="Text/CSV/JSON file containing device-name to port mapping")
    parser.add_argument("--write", action="store_true",
                        help="Write updates to device_info.json. Default is dry-run.")
    args = parser.parse_args()

    info = load_device_info(args.device_info)
    devices = info.get("devices", [])
    expected_names = {d["name"] for d in devices}
    port_map = parse_port_map(args.map, expected_names)

    errors = validate_map(port_map, expected_names)
    if errors:
        print("[ERROR] port map is incomplete/invalid:")
        for error in errors:
            print(f"  - {error}")
        raise SystemExit(1)

    print(f"\n{'Device':<10} {'Old':>8} {'New':>8}")
    print("-" * 30)
    for d in devices:
        old = d.get("telnet_port", 0)
        new = port_map[d["name"]]
        print(f"{d['name']:<10} {old:>8} {new:>8}")
        d["telnet_port"] = new

    if args.write:
        args.device_info.write_text(
            json.dumps(info, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"\n[OK] updated {args.device_info}")
    else:
        print("\n[dry-run] add --write to update device_info.json")


if __name__ == "__main__":
    main()
