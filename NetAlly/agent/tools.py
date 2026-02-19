import os
import json
import asyncio
import socket
from typing import Dict, Any, List, Optional, Literal
from urllib.parse import urlparse
from langchain_core.tools import tool
from dotenv import load_dotenv

# Clients
from agent.clients.nso import NSOClient
from agent.clients.batfish import BatfishClient
from agent.clients.pnetlab import PnetlabClient
from agent.onboarding import (
    load_device_info,
    ensure_device_info,
    generate_device_info_from_pnetlab,
    parse_config,
    enable_ssh_all,
    assign_missing_oob_ips,
    check_connectivity,
    register_devices_nso,
    should_manage_pnetlab_node,
    DeviceInfo,
    save_device_info,
)

load_dotenv()


# =============================================================================
# Client Singletons
# =============================================================================

_nso_client: Optional[NSOClient] = None
_batfish_client: Optional[BatfishClient] = None
_pnetlab_client: Optional[PnetlabClient] = None
_LOCAL_LOOPBACKS = {"localhost", "127.0.0.1"}


def _is_tcp_open(host: str, port: int, timeout_sec: float = 0.35) -> bool:
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


def _maybe_rewrite_local_nso_base_url(base_url: str) -> str:
    """
    Local dev fallback:
    if NSO_BASE_URL points to localhost:8080 but it's closed and SSH tunnel
    127.0.0.1:18080 is open, transparently switch to the tunnel endpoint.
    """
    raw = str(base_url or "").strip()
    if not raw:
        return raw
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw

    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme or "http"
    path = parsed.path or "/restconf"
    port = parsed.port or (443 if scheme == "https" else 80)
    if host not in _LOCAL_LOOPBACKS or port != 8080:
        return raw

    tunnel_host = str(os.getenv("NETALLY_NSO_LOCAL_TUNNEL_HOST", "127.0.0.1") or "127.0.0.1").strip()
    tunnel_port_raw = str(os.getenv("NETALLY_NSO_LOCAL_TUNNEL_PORT", "18080") or "18080").strip()
    try:
        tunnel_port = int(tunnel_port_raw)
    except Exception:
        tunnel_port = 18080

    # Keep explicit localhost:8080 when it is actually reachable.
    if _is_tcp_open(host, port):
        return raw
    if not _is_tcp_open(tunnel_host, tunnel_port):
        return raw

    rewritten = f"{scheme}://{tunnel_host}:{tunnel_port}{path}"
    if parsed.query:
        rewritten = f"{rewritten}?{parsed.query}"
    print(
        f"[lab_bootstrap] NSO localhost fallback: {raw} -> {rewritten} "
        "(localhost:8080 closed, tunnel detected)"
    )
    return rewritten

def get_nso_client() -> NSOClient:
    global _nso_client
    if not _nso_client:
        base_url = os.getenv("NSO_BASE_URL")
        if base_url:
            base_url = _maybe_rewrite_local_nso_base_url(base_url)
        if not base_url:
            base_url = _discover_nso_base_url()
        if base_url:
            print(f"[lab_bootstrap] NSO base_url resolved: {base_url}")
        if not base_url:
            base_url = (
                "http://127.0.0.1:18080/restconf"
                if _is_tcp_open("127.0.0.1", 18080)
                else "http://localhost:8080/restconf"
            )
        _nso_client = NSOClient(
            base_url=base_url,
            username=os.getenv("NSO_USERNAME") or os.getenv("NSO_USER", "admin"),
            password=os.getenv("NSO_PASSWORD") or os.getenv("NSO_PASS", "admin")
        )
    return _nso_client

def get_batfish_client() -> BatfishClient:
    global _batfish_client
    if not _batfish_client:
        _batfish_client = BatfishClient(
            host=os.getenv("BATFISH_HOST", "localhost")
        )
    return _batfish_client

def get_pnetlab_client() -> PnetlabClient:
    global _pnetlab_client
    if not _pnetlab_client:
        _pnetlab_client = PnetlabClient(
            base_url=os.getenv("PNETLAB_URL") or os.getenv("PNETLAB_HOST", "http://localhost"),
            username=os.getenv("PNETLAB_USERNAME", ""),
            password=os.getenv("PNETLAB_PASSWORD", ""),
        )
    return _pnetlab_client


def reset_pnetlab_client() -> None:
    global _pnetlab_client
    _pnetlab_client = None


def reset_nso_client() -> None:
    """NSO 클라이언트 싱글톤 리셋 (설정 변경 시 호출)"""
    global _nso_client
    _nso_client = None


def reset_batfish_client() -> None:
    """Batfish 클라이언트 싱글톤 리셋 (설정 변경 시 호출)"""
    global _batfish_client
    _batfish_client = None


def _discover_nso_base_url() -> Optional[str]:
    """
    PNETLab API에서 NSO 노드의 관리 IP를 찾아 RESTCONF URL을 생성합니다.
    필요 환경변수:
      - PNETLAB_NSO_NODE (default: NSO)
      - NSO_SCHEME (default: http)
      - NSO_PORT (default: 8080)
      - NSO_RESTCONF_PATH (default: /restconf)
    """
    try:
        node_name = os.getenv("PNETLAB_NSO_NODE", "NSO")
        scheme = os.getenv("NSO_SCHEME", "http")
        port = os.getenv("NSO_PORT", "8080")
        path = os.getenv("NSO_RESTCONF_PATH", "/restconf").lstrip("/")
        pnetlab = get_pnetlab_client()
        ip = pnetlab.get_node_ip_by_name(node_name)
        print(f"[lab_bootstrap] discover_nso: node={node_name} ip={ip}")
        if not ip:
            return None
        return f"{scheme}://{ip}:{port}/{path}"
    except Exception:
        return None


def _get_inventory_nodes(pnetlab: PnetlabClient) -> Dict[str, Any]:
    """
    Resolve inventory nodes with backend-aware priority.
    - If LabFS backend is explicit (or auto-resolved in auto mode), use LabFS first.
    - Otherwise try API first, then LabFS fallback.
    Returns API-compatible node objects with `name`, `status`, `telnet_port`.
    """
    try:
        from agent.pnetlab_labfs import build_pnetlab_map_from_labfs, resolve_inventory_backend
    except Exception:
        build_pnetlab_map_from_labfs = None
        resolve_inventory_backend = None

    def _from_labfs() -> Dict[str, Any]:
        if not callable(build_pnetlab_map_from_labfs):
            return {"error": "PNETLab LabFS module unavailable"}
        labfs_topology = build_pnetlab_map_from_labfs()
        if labfs_topology.get("error"):
            return {"error": f"PNETLab LabFS error: {labfs_topology.get('error')}"}

        nodes: List[Dict[str, Any]] = []
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
                    "status": 2 if telnet_port > 0 else 0,
                    "template": str(data.get("template") or ""),
                    "type": str(data.get("kind") or data.get("template") or ""),
                }
            )

        meta = labfs_topology.get("meta", {}) if isinstance(labfs_topology.get("meta"), dict) else {}
        return {
            "nodes": nodes,
            "lab": {"name": os.getenv("PNETLAB_LAB_NAME"), "path": meta.get("unl_path")},
            "source": "labfs",
        }

    explicit_backend = os.getenv("PNETLAB_INVENTORY_BACKEND", "").strip().lower()
    resolved_backend = (
        resolve_inventory_backend() if callable(resolve_inventory_backend) else explicit_backend
    )
    prefer_labfs = (
        explicit_backend in {"labfs_local", "labfs_ssh"}
        or (not explicit_backend and resolved_backend in {"labfs_local", "labfs_ssh"})
    )

    if prefer_labfs:
        labfs_first = _from_labfs()
        if "error" not in labfs_first:
            return labfs_first
        # Explicit LabFS mode should surface LabFS errors directly.
        if explicit_backend in {"labfs_local", "labfs_ssh"}:
            return labfs_first

    topology = pnetlab.get_session_topology()
    if "error" not in topology:
        return {
            "nodes": pnetlab.get_nodes_from_topology(topology),
            "lab": {"name": topology.get("name"), "path": topology.get("path")},
            "source": "api",
        }

    if resolved_backend not in {"labfs_local", "labfs_ssh"}:
        return {"error": f"PNETLab API error: {topology.get('error')}"}

    labfs_topology = _from_labfs()
    if "error" in labfs_topology:
        return labfs_topology
    return labfs_topology


def _call_tool_or_fn(target: Any, kwargs: Dict[str, Any]) -> Any:
    """
    Call either a StructuredTool (`invoke`) or a plain function (`**kwargs`).
    """
    invoke = getattr(target, "invoke", None)
    if callable(invoke):
        return invoke(kwargs)
    if callable(target):
        return target(**kwargs)
    raise TypeError(f"Unsupported callable target: {type(target)}")


def _probe_nso_connectivity(nso: Any) -> Dict[str, Any]:
    """
    Best-effort NSO RESTCONF probe with actionable diagnostics.
    """
    req = getattr(nso, "_request", None)
    if not callable(req):
        # In tests/mocks we often don't expose _request.
        return {"ok": True, "checked": False}

    try:
        res = req("GET", "tailf-ncs:devices/device?fields=name")
    except Exception as e:
        return {"ok": False, "checked": True, "error": str(e)}

    if isinstance(res, dict) and res.get("status") == "error":
        return {"ok": False, "checked": True, "error": str(res.get("message") or "unknown")}

    return {"ok": True, "checked": True}


def _build_missing_device_candidates(
    missing_nodes: List[Dict[str, Any]],
    all_devices: List[DeviceInfo],
    mgmt_ifaces: Dict[str, str],
    mgmt_ips: Dict[str, str],
    oob_intf_fallback: str,
) -> List[DeviceInfo]:
    """
    Build onboarding candidates for missing nodes.
    Live inventory telnet ports always override stale device_info values.
    """
    missing_by_name = {
        str(node.get("name") or ""): node
        for node in missing_nodes
        if str(node.get("name") or "")
    }
    candidates: List[DeviceInfo] = []
    seen_names: set[str] = set()

    for dev in all_devices:
        live = missing_by_name.get(dev.name)
        if not live:
            continue
        live_port = int(live.get("telnet_port") or 0)
        if live_port > 0:
            dev.telnet_port = live_port
        dev.oob_intf = mgmt_ifaces.get(dev.name, oob_intf_fallback or dev.oob_intf)
        if not dev.oob_ip:
            dev.oob_ip = mgmt_ips.get(dev.name) or dev.oob_ip
        candidates.append(dev)
        seen_names.add(dev.name)

    for name, node in missing_by_name.items():
        if name in seen_names:
            continue
        candidates.append(
            DeviceInfo(
                name=name,
                oob_ip=mgmt_ips.get(name),
                oob_intf=mgmt_ifaces.get(name, oob_intf_fallback),
                telnet_port=int(node.get("telnet_port") or 0),
            )
        )

    return candidates


def _collect_onboarding_candidates(
    pnetlab: PnetlabClient,
    config_path: str,
    missing_nodes: List[Dict[str, Any]],
    overrides: Optional[Dict[str, Any]] = None,
) -> tuple[Any, List[DeviceInfo], List[DeviceInfo]]:
    from agent.pnetlab_labfs import discover_management_endpoints

    cfg = ensure_device_info(config_path, pnetlab, overrides=overrides)
    gs, all_devices = parse_config(cfg)
    mgmt_meta = discover_management_endpoints()
    mgmt_ifaces = {
        name: str(meta.get("iface") or "")
        for name, meta in mgmt_meta.items()
        if str(meta.get("iface") or "")
    }
    mgmt_ips = {
        name: str(meta.get("ip") or "")
        for name, meta in mgmt_meta.items()
        if str(meta.get("ip") or "")
    }
    oob_intf_fallback = os.getenv("PNETLAB_OOB_INTF", "")
    candidates = _build_missing_device_candidates(
        missing_nodes=missing_nodes,
        all_devices=all_devices,
        mgmt_ifaces=mgmt_ifaces,
        mgmt_ips=mgmt_ips,
        oob_intf_fallback=oob_intf_fallback,
    )
    return gs, all_devices, candidates


# =============================================================================
# 1. network_query (NSO)
# =============================================================================

@tool
def network_query(
    category: Literal["device", "interface", "routing", "vrf", "security", "acl"],
    device: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [Query] Network configuration query via NSO.
    
    Args:
        category: "device", "interface", "routing", "vrf", "security", "acl"
        device: Device hostname (e.g., "p1")
        params: Additional parameters
    """
    try:
        nso = get_nso_client()
        params = params or {}
        
        if category == "device":
            if device:
                return nso.get_device_info(device)
            return {"devices": nso.get_devices()}
            
        elif category == "interface":
            if not device: return {"error": "device required"}
            return {"interfaces": nso.get_interfaces(device)}
            
        elif category == "routing":
            if not device: return {"error": "device required"}
            proto = params.get("protocol", "bgp")
            if proto == "bgp":
                return {
                    "as": nso.get_bgp_as_number(device),
                    "neighbors": nso.get_bgp_neighbors(device)
                }
            return {"error": f"Protocol {proto} not supported yet"}
            
        elif category == "vrf":
            if not device: return {"error": "device required"}
            return {"vrfs": nso.get_vrf_list(device)}

        elif category == "security":
            if not device:
                return {"error": "device required"}
            return {
                "ssh": nso.get_ssh_config(device),
                "aaa": nso.get_aaa_config(device),
            }

        elif category == "acl":
            if not device:
                return {"error": "device required"}
            # Prefer structured RESTCONF subtree first.
            acl = nso._fetch_config(device, "ip/access-list")
            if isinstance(acl, dict) and acl.get("status") == "error":
                native = nso.get_native_config(device)
                acl_lines = [
                    line for line in native.splitlines()
                    if line.strip().startswith("ip access-list")
                ]
                return {"acl": acl_lines}
            return {"acl": acl}
            
        return {"error": f"Category {category} not implemented in stub"}
        
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# 2. network_verify (Batfish) - L4/L5 분석 지원
# =============================================================================

@tool
def network_verify(
    test_type: Literal[
        # 기본
        "reachability", "traceroute", "bgp_session", "route_table",
        # L4 (도달성 분석)
        "acl_blocking", "loop_detection", "blackhole_detection", "waypoint_check",
        # L5 (What-If 분석)
        "link_failure_impact", "node_failure_impact", "spof_detection"
    ],
    params: Dict[str, Any]
) -> Dict[str, Any]:
    """
    [Verify] Network verification via Batfish.
    
    Supports L4 (Reachability Analysis) and L5 (What-If Analysis).
    
    Args:
        test_type: Test type
            - Basic: "reachability", "traceroute", "bgp_session", "route_table"
            - L4: "acl_blocking", "loop_detection", "blackhole_detection", "waypoint_check"
            - L5: "link_failure_impact", "node_failure_impact", "spof_detection"
        params: Test parameters (varies by test_type)
    
    Examples:
        # L5: 링크 장애 시뮬레이션
        network_verify("link_failure_impact", {
            "node1": "p1", "node2": "p2",  # 끊을 링크
            "src": "ce1", "dst": "ce2"      # 테스트 트래픽
        })
        
        # L4: ACL 차단 분석
        network_verify("acl_blocking", {
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "dst_port": 80
        })
    """
    try:
        bf = get_batfish_client()
        
        # Ensure Batfish is available
        if not bf.is_available:
            return {"error": "Batfish SDK not available"}
        
        # Ensure snapshot is initialized
        if not bf._builder:
            return {"error": "Batfish not initialized. Run lab_manage('init_batfish') first."}
        
        builder = bf._builder  # BatfishBuilder (inherits L4/L5 Mixins)

        # =====================================================================
        # 기본 검증
        # =====================================================================
        if test_type == "reachability":
            return bf.check_reachability(
                src=params.get("src"),
                dst=params.get("dst"),
                protocol=params.get("protocol", "icmp")
            )
            
        elif test_type == "traceroute":
            return bf.traceroute(
                src=params.get("src"),
                dst=params.get("dst")
            )
            
        elif test_type == "bgp_session":
            return {"sessions": bf.get_bgp_sessions(device_filter=params.get("device"))}
            
        elif test_type == "route_table":
            return {"routes": bf.get_route_table(device=params.get("device"))}
        
        # =====================================================================
        # L4 분석 (도달성 상세 분석)
        # =====================================================================
        elif test_type == "acl_blocking":
            result = builder.acl_blocking_point(
                src_ip=params.get("src_ip"),
                dst_ip=params.get("dst_ip"),
                dst_port=params.get("dst_port", 80)
            )
            return result.value if hasattr(result, 'value') else {"result": str(result)}
            
        elif test_type == "loop_detection":
            result = builder.loop_detection()
            return result.value if hasattr(result, 'value') else {"result": str(result)}
            
        elif test_type == "blackhole_detection":
            result = builder.blackhole_detection(
                dst_prefix=params.get("dst_prefix", "0.0.0.0/0")
            )
            return result.value if hasattr(result, 'value') else {"result": str(result)}
            
        elif test_type == "waypoint_check":
            result = builder.waypoint_check(
                src_ip=params.get("src_ip"),
                dst_ip=params.get("dst_ip"),
                waypoint_node=params.get("waypoint")
            )
            return result.value if hasattr(result, 'value') else {"result": str(result)}
        
        # =====================================================================
        # L5 분석 (What-If 시뮬레이션) - Batfish fork_snapshot 활용
        # =====================================================================
        elif test_type == "link_failure_impact":
            # 링크 장애 시뮬레이션: fork_snapshot으로 인터페이스 비활성화
            result = builder.link_failure_impact(
                node1=params.get("node1"),
                node2=params.get("node2"),
                test_src=params.get("src"),
                test_dst=params.get("dst")
            )
            return result.value if hasattr(result, 'value') else {"result": str(result)}
            
        elif test_type == "node_failure_impact":
            # 노드 장애 시뮬레이션: blast_radius_estimation 사용
            result = builder.blast_radius_estimation(
                failed_node=params.get("node")
            )
            return result.value if hasattr(result, 'value') else {"result": str(result)}
            
        elif test_type == "spof_detection":
            # 단일 장애점 탐지
            result = builder.spof_detection()
            return result.value if hasattr(result, 'value') else {"result": str(result)}
            
        return {"error": f"Test type {test_type} not implemented"}
        
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# 3. lab_manage (PNETLab)
# =============================================================================

@tool
def lab_manage(
    action: Literal["show_inventory", "get_status", "export_configs", "init_batfish"],
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [Lab] PNETLab management and Batfish initialization.
    
    Args:
        action: "show_inventory", "get_status", "export_configs", "init_batfish"
        params: Action parameters
    """
    try:
        pnetlab = get_pnetlab_client()
        nso = get_nso_client()
        params = params or {}
        
        if action == "show_inventory":
            inventory = _get_inventory_nodes(pnetlab)
            if "error" in inventory:
                return {"error": inventory.get("error")}
            return {
                "nodes": inventory.get("nodes", []),
                "lab": inventory.get("lab", {}),
                "source": inventory.get("source", "api"),
            }
            
        elif action == "get_status":
            device = params.get("device")
            status = pnetlab.get_nodes_status()
            if "error" in status:
                inventory = _get_inventory_nodes(pnetlab)
                if "error" in inventory:
                    return status
                nodes = inventory.get("nodes", [])
                status_nodes = {
                    str(idx): {
                        "name": n.get("name"),
                        "status": n.get("status", 0),
                        "telnet_port": n.get("telnet_port", 0),
                    }
                    for idx, n in enumerate(nodes, start=1)
                }
                status = {"data": {"nodes": status_nodes}, "source": inventory.get("source", "labfs")}
            if not device:
                return status
            # filter by device name if possible
            nodes = status.get("data", {}).get("nodes", {})
            for node_id, info in nodes.items():
                if str(info.get("name", "")).lower() == str(device).lower():
                    return {"node_id": node_id, "status": info}
            return {"error": f"device not found in status: {device}"}
            
        elif action == "export_configs":
            output_dir = params.get("output_dir", "./snapshot")
            export_xml = bool(params.get("export_xml", True))
            export_yang = bool(params.get("export_yang_json", True))
            devices = params.get("devices")
            return nso.export_batfish_configs(
                devices=devices,
                output_dir=output_dir,
                export_xml=export_xml,
                export_yang_json=export_yang,
            )
            
        elif action == "init_batfish":
            bf = get_batfish_client()
            topology_name = (
                params.get("topology_name")
                or os.getenv("BATFISH_SNAPSHOT")
                or os.getenv("BATFISH_NETWORK")
                or "default"
            )
            output_dir = params.get("output_dir", "./snapshot")
            devices = params.get("devices")
            use_restconf = bool(params.get("use_restconf", False))
            
            export_result = nso.export_batfish_configs(
                devices=devices,
                output_dir=output_dir,
                export_xml=False,
                export_yang_json=False,
            )
            if "error" in export_result and use_restconf:
                device_names = devices or nso.get_devices()
                if not device_names:
                    return {"error": "No devices found for RESTCONF export"}
                
                configs = {}
                for name in device_names:
                    cfg = nso.get_native_config(name)
                    if cfg:
                        configs[name] = cfg
                if not configs:
                    return {"error": "RESTCONF export returned empty configs"}
                
                return bf.init_snapshot(
                    topology_name=topology_name,
                    configs=configs,
                    device_info={
                        "source": "NSO_RESTCONF",
                        "topology": topology_name,
                    },
                )
            elif "error" in export_result:
                return export_result
            
            configs_dir = export_result.get("configs_dir")
            if not configs_dir:
                return {"error": "configs_dir missing from export result"}
            
            from pathlib import Path
            cfg_files = list(Path(configs_dir).glob("*.cfg"))
            if not cfg_files:
                return {"error": f"No .cfg files found in {configs_dir}"}
            
            return bf.init_snapshot(
                topology_name=topology_name,
                configs=[str(p) for p in cfg_files],
                device_info={
                    "source": "NSO",
                    "topology": topology_name,
                },
            )
            
        return {"error": f"Action {action} not implemented"}
        
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# 4. scan_and_sync (PNETLab ↔ NSO Reconciliation)
# =============================================================================

@tool
def scan_and_sync(
    action: Literal["scan", "sync", "scan_and_sync"],
    auto_onboard: bool = False,
    auto_remove: bool = False,
    oob_ip: str = "",
    protocol: str = "telnet"
) -> Dict[str, Any]:
    """
    [Sync] PNETLab 노드와 NSO 장비를 비교하고 동기화합니다.
    
    Args:
        action: "scan" (비교만), "sync" (누락 장비 등록), "scan_and_sync" (둘 다)
        auto_onboard: True면 누락 장비 자동 등록 (action이 "sync" 또는 "scan_and_sync"일 때)
        auto_remove: True면 PNETLab에 없는 NSO 장비 자동 삭제
        oob_ip: OOB IP 주소 (기본: "localhost")
        protocol: 연결 프로토콜 ("telnet" 또는 "ssh")
    
    Returns:
        Dict with pnetlab_nodes, nso_devices, missing, and optionally onboarded results
    """
    if not oob_ip:
        oob_ip = os.getenv("PNETLAB_GATEWAY_IP", "") or os.getenv("PNETLAB_VM_IP", "") or os.getenv("PNETLAB_SSH_HOST", "") or "localhost"

    try:
        pnetlab = get_pnetlab_client()
        nso = get_nso_client()

        result = {
            "action": action,
            "debug": {},
            "pnetlab_nodes": [],
            "ignored_nodes": [],
            "nso_devices": [],
            "nso_devices_managed": [],
            "missing": [],
            "already_registered": [],
            "removed": [],
            "deleted": [],
            "delete_failed": [],
            "onboarded": [],
            "failed": [],
            "skipped": [],
        }
        
        # 1. PNETLab에서 실행 중인 노드 목록 조회
        inventory = _get_inventory_nodes(pnetlab)
        if "error" in inventory:
            return {"error": inventory.get("error")}

        pnetlab_nodes_all = inventory.get("nodes", [])
        pnetlab_nodes = []
        for node in pnetlab_nodes_all:
            if should_manage_pnetlab_node(node):
                pnetlab_nodes.append(node)
            else:
                result["ignored_nodes"].append(node.get("name"))
        pnetlab_name_set = set(node.get("name", "").lower() for node in pnetlab_nodes)
        
        # 실행 중인 노드만 필터링 (status == 2 means running)
        running_nodes = [
            {
                "name": node["name"],
                "telnet_port": node.get("telnet_port", 0),
                "status": node.get("status", "unknown")
            }
            for node in pnetlab_nodes
            if node.get("status") == 2  # Running status
        ]
        result["pnetlab_nodes"] = running_nodes
        
        # 2. NSO에서 등록된 장비 목록 조회
        nso_probe = _probe_nso_connectivity(nso)
        result["debug"]["nso_probe"] = nso_probe
        if not nso_probe.get("ok", False):
            return {
                **result,
                "code": "nso_unreachable",
                "error": (
                    "NSO RESTCONF is unreachable. "
                    "Check NSO_BASE_URL/credentials/network reachability."
                ),
            }

        nso_devices = nso.get_devices()
        result["nso_devices"] = nso_devices
        nso_devices_managed = [
            d for d in nso_devices if should_manage_pnetlab_node({"name": d})
        ]
        result["nso_devices_managed"] = nso_devices_managed

        # 3. Diff 계산: PNETLab에는 있지만 NSO에 없는 장비
        nso_device_set = set(d.lower() for d in nso_devices_managed)
        
        for node in running_nodes:
            node_name = node["name"]
            if node_name.lower() in nso_device_set:
                result["already_registered"].append(node_name)
            else:
                result["missing"].append(node)

        # 3-b. NSO에는 있으나 PNETLab에 없는 장비
        removed = [d for d in nso_devices_managed if d.lower() not in pnetlab_name_set]
        result["removed"] = removed
        
        # 4. Sync: SSH-first 플로우 (관리 인터페이스 감지 → IP 발견 → SSH 활성화 → NSO 등록)
        if action in ["sync", "scan_and_sync"] and auto_onboard and result["missing"]:
            config_path = os.getenv("PNETLAB_DEVICE_INFO", "device_info.json")
            gs, all_devices, candidates = _collect_onboarding_candidates(
                pnetlab=pnetlab,
                config_path=config_path,
                missing_nodes=result["missing"],
            )

            if candidates:
                assigned_oob = assign_missing_oob_ips(gs, candidates, existing_devices=all_devices)
                if assigned_oob:
                    result["assigned_oob_ip"] = assigned_oob
                ssh_results = asyncio.run(enable_ssh_all(gs, candidates))
                result["ssh_enabled"] = ssh_results

                # Discovered OOB fields and refreshed telnet ports are persisted for next refresh.
                all_updated = list(all_devices)
                existing_names = {d.name for d in all_devices}
                for dev in candidates:
                    if dev.name not in existing_names:
                        all_updated.append(dev)
                save_device_info(config_path, gs, all_updated)

                ready: List[DeviceInfo] = []
                for dev in candidates:
                    if dev.telnet_port <= 0:
                        result["skipped"].append(
                            {"device": dev.name, "reason": "console_unreachable"}
                        )
                        continue
                    if not ssh_results.get(dev.name, False):
                        result["skipped"].append(
                            {"device": dev.name, "reason": "ssh_enable_failed"}
                        )
                        continue
                    if not dev.oob_ip:
                        result["skipped"].append(
                            {"device": dev.name, "reason": "mgmt_ip_not_discovered"}
                        )
                        continue
                    ready.append(dev)

                if ready:
                    reg_results = register_devices_nso(gs, ready, nso)
                    result["onboarded"] = reg_results.get("registered", [])
                    result["failed"] = [
                        {"device": name, "error": "registration_failed"}
                        for name in reg_results.get("failed", [])
                    ]

        # 5. Remove (auto_remove가 True이고 action이 sync 또는 scan_and_sync인 경우)
        if action in ["sync", "scan_and_sync"] and auto_remove and result["removed"]:
            for device_name in result["removed"]:
                if nso.delete_device(device_name):
                    result["deleted"].append(device_name)
                else:
                    result["delete_failed"].append(device_name)
        
        return result
        
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# 5. check_logs (Dynamic Log Analysis)
# =============================================================================

@tool
def check_logs(
    device: str,
    lines: int = 50,
    keyword: Optional[str] = None
) -> str:
    """
    [Log] 장비의 최신 로그를 조회합니다 (Dynamic State).
    NIKA Benchmark와 유사하게, 정적 설정(Config)이 아닌 
    실제 발생한 이벤트(Syslog)를 확인하여 문제 원인을 파악합니다.
    
    Args:
        device: 장비 호스트네임 (예: "p1")
        lines: 조회할 최근 로그 라인 수 (기본: 50)
        keyword: (선택) 특정 키워드가 포함된 로그만 필터링
    """
    try:
        nso = get_nso_client()
        logs = nso.get_logs(device, lines)
        
        if keyword:
            filtered = [line for line in logs.splitlines() if keyword.lower() in line.lower()]
            if not filtered:
                return f"No logs found containing keyword '{keyword}'"
            return "\n".join(filtered)
            
        return logs
        
    except Exception as e:
        return f"Error fetching logs: {str(e)}"


# =============================================================================
# 6. lab_bootstrap (PNETLab -> SSH -> NSO)
# =============================================================================

@tool
def lab_bootstrap(
    action: Literal[
        "enable_ssh",
        "register_nso",
        "check_connectivity",
        "sync_from",
        "detect_changes",
        "sync_changed",
        "diff_report",
        "generate_device_info",
        "refresh_onboard",
        "full",
        "discover_nso"
    ],
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [Bootstrap] PNETLab 장비 초기화 파이프라인.
    
    Args:
        action: "enable_ssh", "register_nso", "check_connectivity", "full"
        params:
            - config_path: device_info.json 경로 (기본: PNETLAB_DEVICE_INFO env)
            - device: 특정 장비 이름 (check_connectivity에서 선택)
    """
    try:
        params = params or {}
        config_path = params.get("config_path") or os.getenv(
            "PNETLAB_DEVICE_INFO",
            "Data/Pnetlab/Research_Institute_Internal_DC/device_info.json"
        )
        pnetlab = get_pnetlab_client()
        overrides = params.get("overrides") if params else None
        cfg = ensure_device_info(config_path, pnetlab, overrides=overrides)
        gs, devices = parse_config(cfg)
        device_filter = params.get("devices")
        if device_filter:
            device_set = set(str(d).lower() for d in device_filter)
            devices = [d for d in devices if d.name.lower() in device_set]
            if not devices:
                return {"error": "No matching devices for filter", "devices": device_filter}
        
        if action == "enable_ssh":
            results = asyncio.run(enable_ssh_all(gs, devices))
            return {"status": "completed", "results": results}
        
        if action == "check_connectivity":
            target_name = params.get("device")
            target = None
            for dev in devices:
                if not target_name or dev.name.lower() == str(target_name).lower():
                    target = dev
                    break
            if not target:
                return {"error": f"device not found: {target_name}"}
            ok = asyncio.run(check_connectivity(gs, target))
            return {"device": target.name, "reachable": ok}
        
        if action == "register_nso":
            nso = get_nso_client()
            result = register_devices_nso(gs, devices, nso)
            return {"status": "completed", **result}

        if action == "sync_from":
            nso = get_nso_client()
            synced = []
            failed = []
            for dev in devices:
                if nso.sync_from(dev.name):
                    synced.append(dev.name)
                else:
                    failed.append(dev.name)
            return {"status": "completed", "synced": synced, "failed": failed}

        if action == "detect_changes":
            nso = get_nso_client()
            in_sync = []
            out_of_sync = []
            for dev in devices:
                if nso.check_sync(dev.name):
                    in_sync.append(dev.name)
                else:
                    out_of_sync.append(dev.name)
            return {
                "status": "completed",
                "in_sync": in_sync,
                "out_of_sync": out_of_sync,
            }

        if action == "sync_changed":
            nso = get_nso_client()
            changed = []
            synced = []
            failed = []
            for dev in devices:
                if nso.check_sync(dev.name):
                    continue
                changed.append(dev.name)
                if nso.sync_from(dev.name):
                    synced.append(dev.name)
                else:
                    failed.append(dev.name)
            return {
                "status": "completed",
                "changed": changed,
                "synced": synced,
                "failed": failed,
            }

        if action == "diff_report":
            # 1) 신규/삭제 감지 (PNETLab vs NSO)
            diff = _call_tool_or_fn(
                scan_and_sync,
                {
                    "action": "scan",
                    "auto_onboard": False,
                    "auto_remove": False,
                },
            )
            # 2) 변경 감지 (NSO check-sync)
            change = _call_tool_or_fn(
                lab_bootstrap,
                {
                    "action": "detect_changes",
                    "params": {"config_path": config_path, "devices": [d.name for d in devices]},
                },
            )
            return {
                "status": "completed",
                "new_devices": diff.get("missing", []),
                "removed_devices": diff.get("removed", []),
                "out_of_sync": change.get("out_of_sync", []),
                "in_sync": change.get("in_sync", []),
            }
        
        if action == "full":
            ssh_result = asyncio.run(enable_ssh_all(gs, devices))
            nso = get_nso_client()
            reg_result = register_devices_nso(gs, devices, nso)
            return {"status": "completed", "ssh": ssh_result, "nso": reg_result}

        if action == "discover_nso":
            node_name = params.get("node_name") if params else None
            node_name = node_name or os.getenv("PNETLAB_NSO_NODE", "NSO")
            ip = pnetlab.get_node_ip_by_name(node_name)
            return {"node_name": node_name, "ip": ip}

        if action == "generate_device_info":
            payload = generate_device_info_from_pnetlab(pnetlab, config_path, overrides=overrides)
            return {"status": "completed", "path": config_path, "devices": len(payload.get("devices", []))}

        if action == "refresh_onboard":
            diff = _call_tool_or_fn(
                scan_and_sync,
                {
                    "action": "scan",
                    "auto_onboard": False,
                    "auto_remove": False,
                },
            )
            if isinstance(diff, dict) and diff.get("error"):
                return {
                    "status": "failed",
                    "code": str(diff.get("code") or "refresh_scan_failed"),
                    "error": str(diff.get("error")),
                    "debug": diff.get("debug", {}),
                }
            missing = diff.get("missing", [])
            missing_names = [n.get("name") for n in missing if n.get("name")]
            if not missing_names:
                return {"status": "completed", "message": "No new devices", "missing": []}

            refresh_gs, all_devices, candidates = _collect_onboarding_candidates(
                pnetlab=pnetlab,
                config_path=config_path,
                missing_nodes=missing,
                overrides=overrides,
            )
            if not candidates:
                return {"status": "completed", "message": "No onboarding candidates", "missing": missing_names}

            assigned_oob = assign_missing_oob_ips(refresh_gs, candidates, existing_devices=all_devices)
            ssh_result = asyncio.run(enable_ssh_all(refresh_gs, candidates))
            all_updated = list(all_devices)
            existing_names = {d.name for d in all_devices}
            for dev in candidates:
                if dev.name not in existing_names:
                    all_updated.append(dev)
            save_device_info(config_path, refresh_gs, all_updated)

            ready: List[DeviceInfo] = []
            skipped: List[Dict[str, str]] = []
            for dev in candidates:
                if dev.telnet_port <= 0:
                    skipped.append({"device": dev.name, "reason": "console_unreachable"})
                    continue
                if not ssh_result.get(dev.name, False):
                    skipped.append({"device": dev.name, "reason": "ssh_enable_failed"})
                    continue
                if not dev.oob_ip:
                    skipped.append({"device": dev.name, "reason": "mgmt_ip_not_discovered"})
                    continue
                ready.append(dev)

            nso = get_nso_client()
            reg_result = register_devices_nso(refresh_gs, ready, nso) if ready else {"registered": [], "failed": []}
            return {
                "status": "completed",
                "missing": missing_names,
                "assigned_oob_ip": assigned_oob,
                "ssh": ssh_result,
                "nso": reg_result,
                "skipped": skipped,
            }
        
        return {"error": f"Action {action} not implemented"}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Tool List (for LangGraph)
# =============================================================================

def get_tools() -> List:
    """도구 목록 반환"""
    return [
        network_query,
        network_verify,
        lab_manage,
        scan_and_sync,
        check_logs,
        lab_bootstrap,
    ]


def get_tool_by_names(names: List[str]) -> List:
    """이름 목록으로 도구 필터링"""
    all_tools = get_tools()
    name_set = set(names)
    return [t for t in all_tools if t.name in name_set]


def get_tool_descriptions() -> str:
    """도구 설명 (프롬프트용)"""
    return "\\n".join([f"- {t.name}: {t.description}" for t in get_tools()])
