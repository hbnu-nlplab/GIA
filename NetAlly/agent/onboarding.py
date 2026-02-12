"""
Lab bootstrap helpers
"""
import asyncio
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import telnetlib3

from agent.clients.nso import NSOClient
from agent.clients.pnetlab import PnetlabClient

logger = logging.getLogger(__name__)


def _csv_set(raw: Optional[str]) -> set[str]:
    if not raw:
        return set()
    return {item.strip().lower() for item in str(raw).split(",") if item.strip()}


def should_manage_pnetlab_node(node: Dict[str, Any]) -> bool:
    """
    Determine if a PNETLab node should be treated as an onboard target.
    """
    name = str(node.get("name") or "").strip()
    if not name:
        return False

    include_names = _csv_set(os.getenv("PNETLAB_INCLUDE_NODE_NAMES", ""))
    if include_names and name.lower() not in include_names:
        return False

    exclude_names = _csv_set(
        os.getenv("PNETLAB_EXCLUDE_NODE_NAMES", "NSO,Docker,NetAlly,Admin")
    )
    if name.lower() in exclude_names:
        return False

    exclude_templates = _csv_set(os.getenv("PNETLAB_EXCLUDE_TEMPLATES", ""))
    template = str(node.get("template") or node.get("type") or "").strip().lower()
    if template and template in exclude_templates:
        return False

    return True


@dataclass
class DeviceInfo:
    name: str
    oob_ip: Optional[str]
    oob_intf: str
    telnet_port: int
    device_group: Optional[str] = None


@dataclass
class GlobalSettings:
    pnetlab_vm_ip: str
    gateway_ip: str
    enable_password: str
    admin_password: str
    domain_name: str
    nso_authgroup: str
    nso_ned_id: str
    nso_username: str
    nso_password: str


def load_device_info(config_path: str) -> Dict[str, Any]:
    path = Path(config_path)
    logger.info("Loading device_info.json: %s", path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_pnetlab_vm_ip() -> str:
    env_ip = os.getenv("PNETLAB_VM_IP")
    if env_ip:
        return env_ip
    pnetlab_url = os.getenv("PNETLAB_URL", "")
    if pnetlab_url:
        parsed = urlparse(pnetlab_url)
        if parsed.hostname:
            return parsed.hostname
    return ""


def generate_device_info_from_pnetlab(
    pnetlab: PnetlabClient,
    output_path: str,
    overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    PNETLab API에서 device_info.json 생성 (oob_ip는 선택).
    """
    topology = pnetlab.get_session_topology()
    if "error" in topology:
        from agent.pnetlab_labfs import build_pnetlab_map_from_labfs, resolve_inventory_backend

        backend = resolve_inventory_backend()
        if backend not in {"labfs_local", "labfs_ssh"}:
            raise RuntimeError(f"PNETLab topology error: {topology.get('error')}")

        labfs_topology = build_pnetlab_map_from_labfs()
        if labfs_topology.get("error"):
            raise RuntimeError(f"PNETLab topology error: {labfs_topology.get('error')}")

        nodes = []
        for node in labfs_topology.get("nodes", []):
            if node.get("type") != "device":
                continue
            data = node.get("data", {}) if isinstance(node.get("data"), dict) else {}
            name = str(data.get("label") or node.get("id") or "")
            if not name:
                continue
            telnet_port = int(data.get("telnet_port") or 0)
            nodes.append(
                {
                    "name": name,
                    "telnet_port": telnet_port,
                    "template": str(data.get("template") or ""),
                    "type": str(data.get("kind") or data.get("template") or ""),
                    # Keep API-compatible meaning: 2 means running.
                    "status": 2 if telnet_port > 0 else 0,
                }
            )
    else:
        nodes = pnetlab.get_nodes_from_topology(topology)
    devices = []
    overrides = overrides or {}

    def pick(key: str, default: str = "") -> str:
        val = overrides.get(key)
        if val is not None and str(val).strip() != "":
            return str(val).strip()
        return os.getenv(key, default)

    default_oob_intf = pick("PNETLAB_OOB_INTF", "")
    default_group = pick("PNETLAB_DEVICE_GROUP", "")

    for node in nodes:
        if node.get("status") != 2:
            continue
        if not should_manage_pnetlab_node(node):
            logger.info("Skipping non-managed node for device_info: %s", node.get("name"))
            continue
        telnet_port = node.get("telnet_port", 0)
        if not telnet_port:
            continue
        devices.append({
            "name": node.get("name"),
            "oob_ip": None,
            "oob_intf": default_oob_intf,
            "device_group": default_group or None,
            "telnet_port": int(telnet_port),
        })

    pnetlab_vm_ip = pick("PNETLAB_VM_IP", "")
    if not pnetlab_vm_ip:
        pnetlab_vm_ip = _resolve_pnetlab_vm_ip()

    global_settings = {
        "pnetlab_vm_ip": pnetlab_vm_ip,
        "gateway_ip": pick("PNETLAB_GATEWAY_IP", ""),
        "enable_password": pick("PNETLAB_ENABLE_PASSWORD", ""),
        "admin_password": pick("PNETLAB_ADMIN_PASSWORD", "admin"),
        "domain_name": pick("PNETLAB_DOMAIN_NAME", "lab.local"),
        "nso_authgroup": pick("NSO_AUTHGROUP", "default"),
        "nso_ned_id": pick("NSO_NED_ID", ""),
        "nso_username": pick("NSO_USERNAME", "") or pick("NSO_USER", "admin"),
        "nso_password": pick("NSO_PASSWORD", "") or pick("NSO_PASS", "admin"),
        "batfish_output_dir": pick("BATFISH_EXPORT_DIR", "./snapshot"),
    }

    payload = {
        "global_settings": global_settings,
        "devices": devices,
    }

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info("Generated device_info.json: %s (devices=%d)", out_path, len(devices))
    return payload


def ensure_device_info(
    config_path: str,
    pnetlab: PnetlabClient,
    overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    device_info.json이 없으면 PNETLab API로 자동 생성합니다.
    """
    path = Path(config_path)
    if path.exists():
        return load_device_info(config_path)

    autogen = os.getenv("PNETLAB_DEVICE_INFO_AUTOGEN", "true").lower() == "true"
    if not autogen:
        raise FileNotFoundError(f"device_info.json not found: {config_path}")

    return generate_device_info_from_pnetlab(pnetlab, config_path, overrides=overrides)


def parse_config(cfg: Dict[str, Any]) -> tuple[GlobalSettings, List[DeviceInfo]]:
    g = cfg.get("global_settings", {})
    global_settings = GlobalSettings(
        pnetlab_vm_ip=g.get("pnetlab_vm_ip", ""),
        gateway_ip=g.get("gateway_ip", ""),
        enable_password=g.get("enable_password", ""),
        admin_password=g.get("admin_password", "admin"),
        domain_name=g.get("domain_name", "lab.local"),
        nso_authgroup=g.get("nso_authgroup", "default"),
        nso_ned_id=g.get("nso_ned_id", ""),
        nso_username=g.get("nso_username", "admin"),
        nso_password=g.get("nso_password", "admin"),
    )
    devices = []
    for d in cfg.get("devices", []):
        devices.append(
            DeviceInfo(
                name=d.get("name", ""),
                oob_ip=d.get("oob_ip") or None,
                oob_intf=d.get("oob_intf", ""),
                telnet_port=int(d.get("telnet_port", 0)),
                device_group=d.get("device_group"),
            )
        )
    logger.info("Parsed devices: %d", len(devices))
    return global_settings, devices


async def enable_ssh_via_telnet(device: DeviceInfo, gs: GlobalSettings) -> bool:
    host = gs.pnetlab_vm_ip
    port = device.telnet_port
    if not host or not port:
        logger.warning("Missing telnet endpoint for %s (host=%s, port=%s)", device.name, host, port)
        return False

    try:
        logger.info("Telnet connect: %s:%s (%s)", host, port, device.name)
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=10
        )
    except Exception:
        return False

    async def send_cmd(cmd: str, sleep_time: float = 1.0) -> None:
        writer.write(cmd + "\r\n")
        await asyncio.sleep(sleep_time)
        try:
            await asyncio.wait_for(reader.read(1024), timeout=0.5)
        except Exception:
            pass

    try:
        writer.write("\r\n\r\n")
        await asyncio.sleep(1)

        await send_cmd("enable")
        if gs.enable_password:
            await send_cmd(gs.enable_password)

        await send_cmd("conf t")
        await send_cmd("no ip domain-lookup")
        await send_cmd(f"hostname {device.name}")

        if device.oob_intf and device.oob_ip:
            await send_cmd(f"interface {device.oob_intf}")
            await send_cmd(f"ip address {device.oob_ip} 255.255.255.0")
            await send_cmd("no shutdown", sleep_time=2.0)
            await send_cmd("exit")
        else:
            logger.info("Skip OOB IP config for %s (oob_ip missing)", device.name)

        if gs.gateway_ip and device.oob_ip:
            await send_cmd(f"ip route 0.0.0.0 0.0.0.0 {gs.gateway_ip}")

        if gs.domain_name:
            await send_cmd(f"ip domain-name {gs.domain_name}")

        await send_cmd("crypto key zeroize rsa", sleep_time=2.0)
        writer.write("yes\r\n")
        await asyncio.sleep(1)
        writer.write("crypto key generate rsa general-keys modulus 2048\r\n")
        await asyncio.sleep(10)

        await send_cmd(f"username admin privilege 15 secret {gs.admin_password}")

        await send_cmd("line vty 0 4")
        await send_cmd("transport input ssh")
        await send_cmd("login local")
        await send_cmd("exit")
        await send_cmd("ip ssh version 2")

        await send_cmd("end")
        await send_cmd("write memory", sleep_time=10.0)
        writer.close()
        await writer.wait_closed()
        logger.info("SSH enabled via telnet: %s", device.name)
        return True
    except Exception:
        writer.close()
        await writer.wait_closed()
        logger.exception("SSH enable failed: %s", device.name)
        return False


async def enable_ssh_all(gs: GlobalSettings, devices: List[DeviceInfo]) -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    logger.info("Enabling SSH for %d devices", len(devices))
    for dev in devices:
        results[dev.name] = await enable_ssh_via_telnet(dev, gs)
    return results


async def check_connectivity(gs: GlobalSettings, device: DeviceInfo) -> bool:
    host = gs.pnetlab_vm_ip
    port = device.telnet_port
    if not host or not port:
        logger.warning("Missing telnet endpoint for connectivity check: %s", device.name)
        return False

    try:
        logger.info("Connectivity check telnet: %s:%s (%s)", host, port, device.name)
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=5
        )
    except Exception:
        return False

    try:
        writer.write("\r\n")
        await asyncio.sleep(1)
        writer.write("enable\r\n")
        await asyncio.sleep(0.5)
        if gs.gateway_ip:
            writer.write(f"ping {gs.gateway_ip}\r\n")

        output = ""
        try:
            for _ in range(10):
                chunk = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                output += chunk
                if "Success rate" in output:
                    break
        except asyncio.TimeoutError:
            pass

        writer.close()
        await writer.wait_closed()
        logger.info("Connectivity result for %s: %s", device.name, "ok" if "Success rate is 100 percent" in output else "fail")
        return "Success rate is 100 percent" in output
    except Exception:
        writer.close()
        await writer.wait_closed()
        logger.exception("Connectivity check failed: %s", device.name)
        return False


def register_devices_nso(gs: GlobalSettings, devices: List[DeviceInfo], nso: NSOClient) -> Dict[str, Any]:
    results = {"registered": [], "failed": []}

    logger.info("Registering devices to NSO: %d", len(devices))
    nso.create_authgroup(gs.nso_authgroup, gs.nso_username, gs.nso_password)

    for dev in devices:
        # 내부망 기준: oob_ip가 없으면 PNETLab VM IP + telnet 포트를 사용
        address = dev.oob_ip or gs.pnetlab_vm_ip
        protocol = "ssh" if dev.oob_ip else "telnet"
        port = 22 if dev.oob_ip else dev.telnet_port
        device_info = {
            "name": dev.name,
            "oob_ip": address,
            "port": port,
            "protocol": protocol,
            "authgroup": gs.nso_authgroup,
            "ned_id": gs.nso_ned_id,
        }
        if nso.register_device(device_info):
            try:
                if protocol == "ssh":
                    nso.fetch_host_keys(dev.name)
            except Exception:
                logger.exception("Fetch host keys failed: %s", dev.name)
                pass
            if nso.sync_from(dev.name):
                results["registered"].append(dev.name)
            else:
                results["failed"].append(dev.name)
        else:
            results["failed"].append(dev.name)

    logger.info("NSO registration results: %s", results)
    return results
