import os
import json
import asyncio
from typing import Dict, Any, List, Optional, Literal
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
    check_connectivity,
    register_devices_nso,
    should_manage_pnetlab_node,
)

load_dotenv()


# =============================================================================
# Client Singletons
# =============================================================================

_nso_client: Optional[NSOClient] = None
_batfish_client: Optional[BatfishClient] = None
_pnetlab_client: Optional[PnetlabClient] = None

def get_nso_client() -> NSOClient:
    global _nso_client
    if not _nso_client:
        base_url = os.getenv("NSO_BASE_URL")
        if not base_url:
            base_url = _discover_nso_base_url()
        if base_url:
            print(f"[lab_bootstrap] NSO base_url resolved: {base_url}")
        if not base_url:
            base_url = "http://localhost:8080/restconf"
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
    Resolve inventory nodes via API first, then LabFS fallback.
    Returns API-compatible node objects with `name`, `status`, `telnet_port`.
    """
    topology = pnetlab.get_session_topology()
    if "error" not in topology:
        return {
            "nodes": pnetlab.get_nodes_from_topology(topology),
            "lab": {"name": topology.get("name"), "path": topology.get("path")},
            "source": "api",
        }

    try:
        from agent.pnetlab_labfs import build_pnetlab_map_from_labfs, resolve_inventory_backend
    except Exception:
        return {"error": f"PNETLab API error: {topology.get('error')}"}

    backend = resolve_inventory_backend()
    if backend not in {"labfs_local", "labfs_ssh"}:
        return {"error": f"PNETLab API error: {topology.get('error')}"}

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
    oob_ip: str = "localhost",
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
    try:
        pnetlab = get_pnetlab_client()
        nso = get_nso_client()
        
        result = {
            "action": action,
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
            "failed": []
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
        
        # 4. Sync (auto_onboard가 True이고 action이 sync 또는 scan_and_sync인 경우)
        if action in ["sync", "scan_and_sync"] and auto_onboard and result["missing"]:
            for node in result["missing"]:
                device_name = node["name"]
                telnet_port = node.get("telnet_port", 0)
                
                if telnet_port == 0:
                    result["failed"].append({
                        "device": device_name,
                        "error": "No telnet port available"
                    })
                    continue
                
                # NSO에 자동 등록
                onboard_result = nso.auto_onboard_from_pnetlab(
                    device_name=device_name,
                    telnet_port=telnet_port,
                    oob_ip=oob_ip,
                    protocol=protocol
                )
                
                if onboard_result.get("success"):
                    result["onboarded"].append(device_name)
                else:
                    result["failed"].append({
                        "device": device_name,
                        "error": onboard_result.get("error", "Unknown error"),
                        "steps": onboard_result.get("steps", [])
                    })

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
            missing = diff.get("missing", [])
            missing_names = [n.get("name") for n in missing if n.get("name")]
            if not missing_names:
                return {"status": "completed", "message": "No new devices", "missing": []}

            filtered = [d for d in devices if d.name in set(missing_names)]
            if not filtered:
                return {"status": "completed", "message": "No matching devices in device_info", "missing": missing_names}
            ssh_result = asyncio.run(enable_ssh_all(gs, filtered))
            nso = get_nso_client()
            reg_result = register_devices_nso(gs, filtered, nso)
            return {"status": "completed", "missing": missing_names, "ssh": ssh_result, "nso": reg_result}
        
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
