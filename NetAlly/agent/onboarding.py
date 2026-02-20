"""
Lab bootstrap helpers
"""
import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import telnetlib3

from agent.clients.nso import NSOClient
from agent.clients.pnetlab import PnetlabClient

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r'(\d+\.\d+\.\d+\.\d+)')


def _parse_interface_ip(show_output: str, iface_name: str) -> Optional[str]:
    """
    'show ip interface brief' 출력에서 특정 인터페이스의 IP를 추출.
    예: "Ethernet0/0   10.10.10.5   YES manual up   up" → "10.10.10.5"
    """
    for line in show_output.splitlines():
        if iface_name.lower() in line.lower():
            match = _IP_RE.search(line)
            if match and match.group(1) not in ("0.0.0.0", "127.0.0.1"):
                return match.group(1)
    return None


def _ssh_state_from_output(show_output: str) -> Optional[bool]:
    """
    Parse `show ip ssh` output.
    Returns:
      - True: SSH appears enabled
      - False: SSH appears explicitly disabled
      - None: command unsupported/unknown/inconclusive output
    """
    text = str(show_output or "").strip().lower()
    if not text:
        return None
    if any(token in text for token in ("invalid input", "incomplete command", "unknown command")):
        return None
    if "ssh disabled" in text:
        return False
    if "ssh enabled" in text:
        return True
    if "ssh" in text and "version" in text:
        return False if "disabled" in text else True
    return None


def _is_ssh_enabled_output(show_output: str) -> bool:
    return _ssh_state_from_output(show_output) is True


def _requires_confirm(output: str) -> bool:
    text = str(output or "").lower()
    return "yes/no" in text or "[confirm]" in text


def _contains_invalid_command(output: str) -> bool:
    text = str(output or "").lower()
    return any(
        token in text
        for token in ("invalid input", "incomplete command", "unknown command", "ambiguous command")
    )


def _requires_modulus_input(output: str) -> bool:
    text = str(output or "").lower()
    return (
        "how many bits" in text
        or "modulus" in text and "[" in text
        or "choose the size of the key modulus" in text
    )


def _requires_key_name_accept(output: str) -> bool:
    text = str(output or "").lower()
    return "the name for the keys will be" in text


def _missing_domain_for_keygen(output: str) -> bool:
    text = str(output or "").lower()
    return "please define a domain-name first" in text


def _is_connection_refused_sync_error(error: str) -> bool:
    text = str(error or "").strip().lower()
    if not text:
        return False
    return (
        "connection refused" in text
        or ("failed to connect to device" in text and "refused" in text)
    )


def _resolve_mgmt_network(
    gs: "GlobalSettings",
    existing_devices: Optional[List["DeviceInfo"]] = None,
) -> Optional[ipaddress.IPv4Network]:
    """
    Resolve management IPv4 network for OOB assignment.
    Priority:
    1) PNETLAB_MGMT_SUBNET / PNETLAB_OOB_SUBNET (CIDR)
    2) /24 inferred from gateway IP
    3) /24 inferred from existing OOB IPs
    """
    cidr_raw = (
        os.getenv("PNETLAB_MGMT_SUBNET", "").strip()
        or os.getenv("PNETLAB_OOB_SUBNET", "").strip()
    )
    if cidr_raw:
        try:
            net = ipaddress.ip_network(cidr_raw, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                return net
        except Exception:
            logger.warning("Invalid management subnet: %s", cidr_raw)

    gateway_ip = str(gs.gateway_ip or "").strip() or os.getenv("PNETLAB_GATEWAY_IP", "").strip()
    if gateway_ip:
        try:
            return ipaddress.ip_network(f"{gateway_ip}/24", strict=False)
        except Exception:
            logger.warning("Invalid gateway IP for mgmt subnet inference: %s", gateway_ip)

    for dev in existing_devices or []:
        candidate = str(dev.oob_ip or "").strip()
        if not candidate:
            continue
        try:
            return ipaddress.ip_network(f"{candidate}/24", strict=False)
        except Exception:
            continue
    return None


def _prefix_to_netmask(prefix_len: int) -> str:
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
    except Exception:
        return "255.255.255.0"


def assign_missing_oob_ips(
    gs: "GlobalSettings",
    devices: List["DeviceInfo"],
    existing_devices: Optional[List["DeviceInfo"]] = None,
) -> Dict[str, str]:
    """
    Assign deterministic OOB IPs for devices that have OOB interface but no OOB IP.
    Returns {device_name: assigned_ip}.
    """
    mgmt_net = _resolve_mgmt_network(gs, existing_devices=existing_devices)
    if not mgmt_net:
        return {}

    used: set[ipaddress.IPv4Address] = set()

    def reserve(ip_raw: Optional[str]) -> None:
        ip_val = str(ip_raw or "").strip()
        if not ip_val:
            return
        try:
            addr = ipaddress.ip_address(ip_val)
        except Exception:
            return
        if isinstance(addr, ipaddress.IPv4Address) and addr in mgmt_net:
            used.add(addr)

    reserve(gs.gateway_ip)
    reserve(gs.pnetlab_vm_ip)
    for dev in (existing_devices or []):
        reserve(dev.oob_ip)
    for dev in devices:
        reserve(dev.oob_ip)

    start_host_raw = os.getenv("PNETLAB_MGMT_IP_START", "10").strip()
    try:
        start_host = max(2, int(start_host_raw))
    except Exception:
        start_host = 10

    net_base = int(mgmt_net.network_address)
    net_last = int(mgmt_net.broadcast_address)
    max_host_offset = max(2, net_last - net_base - 1)  # avoid network/broadcast

    def iter_candidates() -> List[ipaddress.IPv4Address]:
        ordered: List[ipaddress.IPv4Address] = []
        for host in range(start_host, max_host_offset + 1):
            ordered.append(ipaddress.IPv4Address(net_base + host))
        for host in range(2, start_host):
            ordered.append(ipaddress.IPv4Address(net_base + host))
        return ordered

    pool = iter_candidates()
    assigned: Dict[str, str] = {}
    pool_idx = 0

    for dev in sorted(devices, key=lambda d: d.name.lower()):
        if dev.oob_ip or not dev.oob_intf:
            continue
        while pool_idx < len(pool) and pool[pool_idx] in used:
            pool_idx += 1
        if pool_idx >= len(pool):
            logger.warning("No free OOB IP left in mgmt subnet %s", mgmt_net)
            break
        picked = pool[pool_idx]
        pool_idx += 1
        dev.oob_ip = str(picked)
        used.add(picked)
        assigned[dev.name] = dev.oob_ip

    if assigned:
        logger.info("Assigned missing OOB IPs from %s: %s", mgmt_net, assigned)
    return assigned


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
    # Runtime-only flag (not persisted) used to decide SSH vs telnet onboarding path.
    # True: SSH explicitly verified, False: SSH inconclusive/unsupported, None: unknown.
    ssh_verified: Optional[bool] = None


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


def save_device_info(config_path: str, gs: GlobalSettings, devices: List[DeviceInfo]) -> None:
    """발견된 관리 IP + 인터페이스를 device_info.json에 저장 (다음 실행 시 재발견 불필요)."""
    payload = {
        "global_settings": {
            "pnetlab_vm_ip": gs.pnetlab_vm_ip,
            "gateway_ip": gs.gateway_ip,
            "enable_password": gs.enable_password,
            "admin_password": gs.admin_password,
            "domain_name": gs.domain_name,
            "nso_authgroup": gs.nso_authgroup,
            "nso_ned_id": gs.nso_ned_id,
            "nso_username": gs.nso_username,
            "nso_password": gs.nso_password,
        },
        "devices": [
            {
                "name": d.name,
                "oob_ip": d.oob_ip,
                "oob_intf": d.oob_intf,
                "telnet_port": d.telnet_port,
                "device_group": d.device_group,
            }
            for d in devices
        ],
    }
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info(
        "Saved device_info.json (%d devices, IPs: %s)",
        len(devices),
        {d.name: d.oob_ip for d in devices if d.oob_ip},
    )
    logger.debug("device_info path: %s", path)


def load_device_info(config_path: str) -> Dict[str, Any]:
    path = Path(config_path)
    logger.info("Loading device_info.json")
    logger.debug("device_info path: %s", path)
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


def _dedupe_hosts(hosts: List[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for host in hosts:
        h = str(host or "").strip()
        if not h or h in seen:
            continue
        seen.add(h)
        out.append(h)
    return out


def _can_connect(host: str, port: int, timeout_sec: float = 1.0) -> bool:
    if not host or port <= 0:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)
    try:
        sock.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        sock.close()


def resolve_console_host(gs: GlobalSettings, devices: List[DeviceInfo]) -> str:
    """
    Pick the most reachable console host across likely candidates.
    This avoids stale device_info host values when .env/runtime changed.
    """
    parsed = urlparse(os.getenv("PNETLAB_URL", ""))
    candidates = _dedupe_hosts(
        [
            os.getenv("PNETLAB_VM_IP", ""),
            parsed.hostname or "",
            os.getenv("PNETLAB_SSH_HOST", ""),
            gs.pnetlab_vm_ip,
            os.getenv("PNETLAB_GATEWAY_IP", ""),
        ]
    )
    if not candidates:
        return gs.pnetlab_vm_ip

    ports: List[int] = []
    for dev in devices:
        p = int(dev.telnet_port or 0)
        if p > 0 and p not in ports:
            ports.append(p)
    if not ports:
        return candidates[0]

    sample_ports = ports[:5]
    best_host = candidates[0]
    best_score = -1
    for host in candidates:
        score = sum(1 for port in sample_ports if _can_connect(host, port))
        if score > best_score:
            best_host = host
            best_score = score

    if best_score <= 0:
        return gs.pnetlab_vm_ip or best_host
    return best_host


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
    device.ssh_verified = None
    if not host or not port:
        logger.warning("Missing telnet endpoint for %s (host=%s, port=%s)", device.name, host, port)
        device.ssh_verified = False
        return False

    try:
        logger.info("Telnet connect: %s:%s (%s)", host, port, device.name)
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(host, port), timeout=10
        )
    except Exception:
        device.ssh_verified = False
        return False

    async def _drain_output(max_wait: float = 1.4, chunk_timeout: float = 0.35) -> str:
        out: List[str] = []
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max_wait
        while loop.time() < deadline:
            remaining = max(0.01, deadline - loop.time())
            timeout = min(chunk_timeout, remaining)
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            except Exception:
                break
            if not chunk:
                break
            out.append(chunk if isinstance(chunk, str) else str(chunk))
            if sum(len(x) for x in out) >= 8192:
                break
        return "".join(out)

    async def send_cmd(cmd: str, sleep_time: float = 1.0, capture: bool = False) -> str:
        writer.write(cmd + "\r\n")
        await asyncio.sleep(sleep_time)
        if not capture:
            try:
                await asyncio.wait_for(reader.read(1024), timeout=0.5)
            except Exception:
                pass
            return ""
        return await _drain_output(max_wait=2.2)

    async def probe_ssh_state(probe_wait: float = 0.8) -> tuple[Optional[bool], str]:
        out = await send_cmd("show ip ssh", sleep_time=probe_wait, capture=True)
        return _ssh_state_from_output(out), out

    async def wait_for_ssh_state(
        timeout_sec: float,
        probe_wait: float = 0.9,
        interval_sec: float = 1.2,
    ) -> tuple[Optional[bool], str]:
        """
        Poll SSH state with grace period.
        Returns (state, last_show_output):
          state=True  -> confirmed enabled
          state=False -> confirmed disabled after timeout
          state=None  -> inconclusive/unsupported command
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.5, timeout_sec)
        last_state: Optional[bool] = None
        last_out = ""

        while loop.time() < deadline:
            state, out = await probe_ssh_state(probe_wait=probe_wait)
            last_state = state
            last_out = out
            if state is True:
                return True, out
            if state is None:
                # Unsupported/inconclusive output should not burn full timeout budget.
                return None, out
            await asyncio.sleep(interval_sec)

        if last_state is None:
            return None, last_out
        return False, last_out

    try:
        writer.write("\r\n\r\n")
        await asyncio.sleep(1)

        await send_cmd("enable")
        if gs.enable_password:
            await send_cmd(gs.enable_password)

        # 관리 IP 동적 발견: oob_intf가 있지만 oob_ip가 없으면 show ip interface brief로 발견
        if device.oob_intf and not device.oob_ip:
            writer.write("show ip interface brief\r\n")
            await asyncio.sleep(2)
            output = ""
            try:
                raw = await asyncio.wait_for(reader.read(4096), timeout=3)
                output = raw if isinstance(raw, str) else str(raw)
            except (asyncio.TimeoutError, Exception):
                pass
            discovered = _parse_interface_ip(output, device.oob_intf)
            if discovered:
                device.oob_ip = discovered
                logger.info("Discovered mgmt IP: %s -> %s (%s)",
                            device.name, discovered, device.oob_intf)

        # Fallback allocation if discovery failed but interface is known.
        if device.oob_intf and not device.oob_ip:
            assigned = assign_missing_oob_ips(gs, [device])
            if assigned.get(device.name):
                logger.info(
                    "Assigned mgmt IP fallback: %s -> %s (%s)",
                    device.name,
                    assigned[device.name],
                    device.oob_intf,
                )

        mgmt_net = _resolve_mgmt_network(gs, existing_devices=[device])
        mgmt_netmask = _prefix_to_netmask(mgmt_net.prefixlen if mgmt_net else 24)

        ssh_username = str(gs.nso_username or "").strip() or "admin"
        ssh_password = str(gs.nso_password or "").strip() or str(gs.admin_password or "").strip() or "admin"

        # Stage 1: base management config
        await send_cmd("conf t")
        await send_cmd("no ip domain-lookup")
        await send_cmd(f"hostname {device.name}")

        if device.oob_intf and device.oob_ip:
            await send_cmd(f"interface {device.oob_intf}")
            await send_cmd(f"ip address {device.oob_ip} {mgmt_netmask}")
            await send_cmd("no shutdown", sleep_time=2.0)
            await send_cmd("exit")
        else:
            logger.info("Skip OOB IP config for %s (oob_ip missing)", device.name)

        if gs.gateway_ip and device.oob_ip:
            await send_cmd(f"ip route 0.0.0.0 0.0.0.0 {gs.gateway_ip}")

        if gs.domain_name:
            await send_cmd(f"ip domain-name {gs.domain_name}")

        await send_cmd("end")

        # Stage 2: RSA key generation (IOS image syntax differs; try safe fallbacks).
        zeroize_out = await send_cmd("crypto key zeroize rsa", sleep_time=1.4, capture=True)
        if _requires_confirm(zeroize_out):
            writer.write("yes\r\n")
            await asyncio.sleep(1.0)
            await _drain_output(max_wait=1.8)

        keygen_cmds = [
            "crypto key generate rsa general-keys modulus 2048",
            "crypto key generate rsa general-keys modulus 1024",
            "crypto key generate rsa modulus 2048",
            "crypto key generate rsa modulus 1024",
            "crypto key generate rsa",
        ]
        ssh_ready = False
        keygen_debug_last = ""
        for cmd in keygen_cmds:
            out = await send_cmd(cmd, sleep_time=2.0, capture=True)
            keygen_debug_last = out
            if _requires_modulus_input(out):
                writer.write("1024\r\n")
                await asyncio.sleep(2.0)
                out += await _drain_output(max_wait=6.0)
                keygen_debug_last = out
            if _requires_key_name_accept(out):
                # IOS prompt: "The name for the keys will be ..."
                writer.write("\r\n")
                await asyncio.sleep(0.8)
                out += await _drain_output(max_wait=4.0)
                keygen_debug_last = out
            if _requires_confirm(out):
                writer.write("yes\r\n")
                await asyncio.sleep(1.2)
                out += await _drain_output(max_wait=3.0)
                keygen_debug_last = out
            if _missing_domain_for_keygen(out):
                # 일부 IOS 이미지는 domain-name 미설정 시 키 생성을 거부합니다.
                await send_cmd("conf t")
                await send_cmd(f"ip domain-name {gs.domain_name or 'lab.local'}")
                await send_cmd("end")
                continue
            if _contains_invalid_command(out):
                continue

            # RSA generation can take longer on low-spec lab nodes.
            state, _show_ssh = await wait_for_ssh_state(timeout_sec=20.0, probe_wait=1.0, interval_sec=1.5)
            if state is True:
                ssh_ready = True
                break
            if state is None:
                # show ip ssh unsupported/inconclusive on some images; proceed and verify later.
                break
            if ssh_ready:
                break

        if not ssh_ready:
            logger.warning(
                "SSH readiness could not be confirmed right after key generation: %s (last output: %s)",
                device.name,
                str(keygen_debug_last).strip().replace("\n", " ")[:220],
            )

        # Stage 3: user + vty hardening for NSO SSH onboarding.
        await send_cmd("conf t")

        # Keep CLI credentials aligned with NSO authgroup credentials.
        user_out = await send_cmd(
            f"username {ssh_username} privilege 15 secret {ssh_password}",
            capture=True,
        )
        if _contains_invalid_command(user_out):
            await send_cmd(
                f"username {ssh_username} privilege 15 password {ssh_password}",
                capture=False,
            )
        if ssh_username.lower() != "admin":
            admin_pw = str(gs.admin_password or "").strip() or ssh_password
            admin_out = await send_cmd(f"username admin privilege 15 secret {admin_pw}", capture=True)
            if _contains_invalid_command(admin_out):
                await send_cmd(f"username admin privilege 15 password {admin_pw}")

        # Ensure console telnet path can authenticate when SSH fallback is needed.
        con_out = await send_cmd("line con 0", capture=True)
        if not _contains_invalid_command(con_out):
            await send_cmd("login local")
            await send_cmd("exec-timeout 0 0")
            await send_cmd("exit")

        vty_out = await send_cmd("line vty 0 15", capture=True)
        if _contains_invalid_command(vty_out):
            await send_cmd("line vty 0 4")
        await send_cmd("transport input ssh")
        await send_cmd("login local")
        await send_cmd("exit")
        await send_cmd("ip ssh version 2", capture=False)

        await send_cmd("end")

        final_state, final_show = await wait_for_ssh_state(
            timeout_sec=25.0,
            probe_wait=0.8,
            interval_sec=1.2,
        )
        if final_state is False:
            # Last effort: regenerate lighter key size and re-check.
            rescue = await send_cmd("crypto key generate rsa modulus 1024", sleep_time=2.0, capture=True)
            if _requires_modulus_input(rescue):
                writer.write("1024\r\n")
                await asyncio.sleep(2.0)
                rescue += await _drain_output(max_wait=4.0)
            if _requires_confirm(rescue):
                writer.write("yes\r\n")
                await asyncio.sleep(1.0)
                rescue += await _drain_output(max_wait=2.0)
            final_state, final_show = await wait_for_ssh_state(
                timeout_sec=20.0,
                probe_wait=0.8,
                interval_sec=1.2,
            )
        if final_state is False:
            logger.error("SSH verification failed after config for %s: %s", device.name, final_show[:200])
            writer.close()
            await writer.wait_closed()
            device.ssh_verified = False
            return False
        if final_state is None:
            logger.warning("SSH verification inconclusive for %s (show ip ssh unsupported/unknown)", device.name)
            device.ssh_verified = False
        else:
            device.ssh_verified = True
        await send_cmd("write memory", sleep_time=10.0)
        writer.close()
        await writer.wait_closed()
        logger.info("SSH enabled via telnet: %s", device.name)
        return True
    except Exception:
        device.ssh_verified = False
        writer.close()
        await writer.wait_closed()
        logger.exception("SSH enable failed: %s", device.name)
        return False


async def enable_ssh_all(gs: GlobalSettings, devices: List[DeviceInfo]) -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    resolved_host = resolve_console_host(gs, devices)
    if resolved_host and resolved_host != gs.pnetlab_vm_ip:
        logger.info("Resolved console host: %s -> %s", gs.pnetlab_vm_ip, resolved_host)
        gs.pnetlab_vm_ip = resolved_host
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

    def _rehydrate_ssh_and_resync(target: DeviceInfo) -> bool:
        """
        Last-resort recovery path for SSH sync failures:
        1) Re-apply SSH config through telnet
        2) Re-fetch host keys
        3) Retry sync-from
        """
        logger.warning("Attempting SSH remediation via telnet: %s", target.name)
        try:
            repaired = asyncio.run(enable_ssh_via_telnet(target, gs))
        except RuntimeError as e:
            # Defensive fallback when called under an active event loop.
            logger.error("Cannot run SSH remediation for %s: %s", target.name, e)
            return False
        except Exception as e:
            logger.error("SSH remediation failed for %s: %s", target.name, e)
            return False

        if not repaired:
            return False

        try:
            nso.fetch_host_keys(target.name)
        except Exception:
            logger.exception("Fetch host keys after remediation failed: %s", target.name)

        for attempt in range(1, 3):
            if nso.sync_from(target.name):
                logger.info("Sync-from recovered after SSH remediation: %s", target.name)
                return True
            if attempt < 2:
                time.sleep(2.0)
        return False

    def _last_sync_error(device_name: str) -> str:
        getter = getattr(nso, "get_last_sync_error", None)
        if callable(getter):
            try:
                return str(getter(device_name) or "")
            except Exception:
                return ""
        return ""

    def _register_telnet_console_and_sync(target: DeviceInfo) -> bool:
        if target.telnet_port <= 0:
            return False
        logger.warning(
            "Falling back to telnet console for %s (host=%s port=%s)",
            target.name,
            gs.pnetlab_vm_ip,
            target.telnet_port,
        )
        telnet_info = {
            "name": target.name,
            "oob_ip": gs.pnetlab_vm_ip,
            "port": target.telnet_port,
            "protocol": "telnet",
            "authgroup": gs.nso_authgroup,
            "ned_id": gs.nso_ned_id,
        }
        if not nso.register_device(telnet_info):
            return False
        for attempt in range(1, 3):
            if nso.sync_from(target.name):
                logger.info("Sync-from recovered via telnet console fallback: %s", target.name)
                return True
            if attempt < 2:
                time.sleep(1.5)
        return False

    for dev in devices:
        # SSH가 명시적으로 확인된 장비만 SSH 우선 등록.
        # IOL 이미지에서 show ip ssh가 불명확할 경우 telnet 콘솔로 빠르게 우회.
        use_ssh = bool(dev.oob_ip) and dev.ssh_verified is not False
        if bool(dev.oob_ip) and not use_ssh:
            logger.info(
                "Using telnet onboarding for %s (ssh verification inconclusive/unsupported)",
                dev.name,
            )
        address = dev.oob_ip if use_ssh else gs.pnetlab_vm_ip
        protocol = "ssh" if use_ssh else "telnet"
        port = 22 if use_ssh else dev.telnet_port
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
            sync_ok = False
            # SSH onboarding can race briefly with key/daemon readiness on virtual IOS images.
            # Retry sync-from a few times before marking device failed.
            max_attempts = 3 if protocol == "ssh" else 1
            for attempt in range(1, max_attempts + 1):
                if nso.sync_from(dev.name):
                    sync_ok = True
                    break
                last_err = _last_sync_error(dev.name)
                if protocol == "ssh" and _is_connection_refused_sync_error(last_err):
                    logger.warning(
                        "SSH sync-from refused for %s, skipping remaining SSH retries: %s",
                        dev.name,
                        last_err,
                    )
                    break
                if attempt < max_attempts:
                    logger.warning(
                        "Sync-from retry %d/%d for %s",
                        attempt + 1,
                        max_attempts,
                        dev.name,
                    )
                    try:
                        if protocol == "ssh":
                            nso.fetch_host_keys(dev.name)
                    except Exception:
                        pass
                    # Lightweight backoff to let SSH daemon settle on lab nodes.
                    time.sleep(2.0)
            if not sync_ok and protocol == "ssh":
                last_err = _last_sync_error(dev.name)
                if _is_connection_refused_sync_error(last_err):
                    sync_ok = _register_telnet_console_and_sync(dev)
                if not sync_ok:
                    sync_ok = _rehydrate_ssh_and_resync(dev)
            if sync_ok:
                results["registered"].append(dev.name)
            else:
                results["failed"].append(dev.name)
        else:
            results["failed"].append(dev.name)

    logger.info("NSO registration results: %s", results)
    return results
