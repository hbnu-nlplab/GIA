import os
import json
from typing import Dict, Any, List, Optional, Literal
from langchain_core.tools import tool
from dotenv import load_dotenv

# Clients
from agent.clients.nso import NSOClient
from agent.clients.batfish import BatfishClient
from agent.clients.pnetlab import PnetlabClient

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
        _nso_client = NSOClient(
            base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf"),
            username=os.getenv("NSO_USERNAME", "admin"),
            password=os.getenv("NSO_PASSWORD", "admin")
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
            base_url=os.getenv("PNETLAB_URL", "http://localhost"),
        )
    return _pnetlab_client


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
        params = params or {}
        
        if action == "show_inventory":
            return pnetlab.get_nodes()
            
        elif action == "get_status":
            device = params.get("device")
            if not device: return {"error": "device required"}
            return pnetlab.get_node_status(device)
            
        elif action == "init_batfish":
            # 1. Export configs from NSO/PNETLab
            # 2. Init Batfish snapshot
            bf = get_batfish_client()
            snapshot_path = params.get("snapshot_path", "./snapshot")
            bf.init_snapshot(snapshot_path)
            return {"status": "Batfish initialized", "snapshot": snapshot_path}
            
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
    oob_ip: str = "localhost",
    protocol: str = "telnet"
) -> Dict[str, Any]:
    """
    [Sync] PNETLab 노드와 NSO 장비를 비교하고 동기화합니다.
    
    Args:
        action: "scan" (비교만), "sync" (누락 장비 등록), "scan_and_sync" (둘 다)
        auto_onboard: True면 누락 장비 자동 등록 (action이 "sync" 또는 "scan_and_sync"일 때)
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
            "nso_devices": [],
            "missing": [],
            "already_registered": [],
            "onboarded": [],
            "failed": []
        }
        
        # 1. PNETLab에서 실행 중인 노드 목록 조회
        topology = pnetlab.get_session_topology()
        if "error" in topology:
            return {"error": f"PNETLab API error: {topology.get('error')}"}
        
        pnetlab_nodes = pnetlab.get_nodes_from_topology(topology)
        
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
        
        # 3. Diff 계산: PNETLab에는 있지만 NSO에 없는 장비
        nso_device_set = set(d.lower() for d in nso_devices)
        
        for node in running_nodes:
            node_name = node["name"]
            if node_name.lower() in nso_device_set:
                result["already_registered"].append(node_name)
            else:
                result["missing"].append(node)
        
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
    ]


def get_tool_by_names(names: List[str]) -> List:
    """이름 목록으로 도구 필터링"""
    all_tools = get_tools()
    name_set = set(names)
    return [t for t in all_tools if t.name in name_set]


def get_tool_descriptions() -> str:
    """도구 설명 (프롬프트용)"""
    return "\\n".join([f"- {t.name}: {t.description}" for t in get_tools()])
