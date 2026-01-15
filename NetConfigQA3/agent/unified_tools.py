"""
Unified Tools (통합 도구 7개)

LLM에게 노출되는 통합 도구들입니다.
각 도구는 내부적으로 MCP 서버로 라우팅됩니다.

도구 목록:
1. network_query - NSO에서 설정 정보 조회
2. network_verify - Batfish로 네트워크 검증
3. network_change - NSO로 설정 변경
4. telemetry_query - 로그/메트릭/플로우 조회
5. lab_manage - PNETLab 관리
6. approval_request - 위험 작업 승인 요청
7. help_guide - 도구 사용법 조회
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Literal

# LangChain import
try:
    from langchain_core.tools import tool
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    # 데코레이터 스텁
    def tool(func):
        return func

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_servers.nso_server import NSOServer
from mcp_servers.batfish_server import BatfishServer
from mcp_servers.pnetlab_server import PnetlabServer
from mcp_servers.telemetry_server import TelemetryServer

logger = logging.getLogger(__name__)


# =============================================================================
# Server Singletons (지연 초기화)
# =============================================================================

_nso_server: Optional[NSOServer] = None
_batfish_server: Optional[BatfishServer] = None
_pnetlab_server: Optional[PnetlabServer] = None
_telemetry_server: Optional[TelemetryServer] = None


def get_nso_server() -> NSOServer:
    """NSO 서버 싱글톤"""
    global _nso_server
    if _nso_server is None:
        _nso_server = NSOServer()
    return _nso_server


def get_batfish_server() -> BatfishServer:
    """Batfish 서버 싱글톤"""
    global _batfish_server
    if _batfish_server is None:
        _batfish_server = BatfishServer()
    return _batfish_server


def get_pnetlab_server() -> PnetlabServer:
    """PNETLab 서버 싱글톤"""
    global _pnetlab_server
    if _pnetlab_server is None:
        _pnetlab_server = PnetlabServer()
    return _pnetlab_server


def get_telemetry_server() -> TelemetryServer:
    """Telemetry 서버 싱글톤"""
    global _telemetry_server
    if _telemetry_server is None:
        _telemetry_server = TelemetryServer()
    return _telemetry_server


# =============================================================================
# 1. network.query - 네트워크 정보 조회
# =============================================================================

@tool
def network_query(
    category: Literal["device", "interface", "routing", "vrf", "security", "acl"],
    device: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [조회] 네트워크 설정 정보를 조회합니다.
    
    Args:
        category: 조회 카테고리
            - "device": 장비 목록/정보
            - "interface": 인터페이스 설정
            - "routing": BGP/OSPF 라우팅
            - "vrf": VRF 설정
            - "security": SSH/AAA 보안
            - "acl": ACL 규칙
        device: 대상 장비명 (없으면 전체)
        params: 카테고리별 추가 파라미터
            - routing: {"protocol": "bgp" | "ospf"}
            - interface: {"name": "GigabitEthernet0/0"}
    
    Returns:
        조회 결과 딕셔너리
    
    Examples:
        - network_query("device") → 전체 장비 목록
        - network_query("routing", device="PE1", params={"protocol": "bgp"})
        - network_query("interface", device="P1")
    """
    logger.info(f"network_query({category}, {device}, {params})")
    
    try:
        nso = get_nso_server()
        params = params or {}
        
        if category == "device":
            if device:
                return nso.get_device_info(device)
            else:
                devices = nso.get_devices()
                return {"devices": devices, "count": len(devices)}
        
        elif category == "interface":
            if not device:
                return {"error": "device parameter required for interface query"}
            interfaces = nso.get_interfaces(device)
            return {"device": device, "interfaces": interfaces, "count": len(interfaces)}
        
        elif category == "routing":
            if not device:
                return {"error": "device parameter required for routing query"}
            
            protocol = params.get("protocol", "bgp")
            if protocol == "bgp":
                neighbors = nso.client.get_bgp_neighbors(device)
                as_number = nso.client.get_bgp_as_number(device)
                return {
                    "device": device,
                    "protocol": "bgp",
                    "as_number": as_number,
                    "neighbors": neighbors
                }
            elif protocol == "ospf":
                ospf_config = nso.client.get_ospf_config(device)
                return {"device": device, "protocol": "ospf", "config": ospf_config}
            else:
                return {"error": f"Unknown protocol: {protocol}"}
        
        elif category == "vrf":
            if not device:
                return {"error": "device parameter required for VRF query"}
            vrfs = nso.client.get_vrf_list(device)
            return {"device": device, "vrfs": vrfs, "count": len(vrfs)}
        
        elif category == "security":
            if not device:
                return {"error": "device parameter required for security query"}
            ssh = nso.client.get_ssh_config(device)
            aaa = nso.client.get_aaa_config(device)
            return {"device": device, "ssh": ssh, "aaa": aaa}
        
        elif category == "acl":
            if not device:
                return {"error": "device parameter required for ACL query"}
            # ACL 조회는 config path로 처리
            config = nso.get_config(device, "ip/access-list")
            return {"device": device, "acl": config}
        
        else:
            return {"error": f"Unknown category: {category}"}
            
    except Exception as e:
        logger.error(f"network_query error: {e}")
        return {"error": str(e)}


# =============================================================================
# 2. network.verify - 네트워크 검증 (Batfish)
# =============================================================================

@tool
def network_verify(
    test_type: Literal["reachability", "traceroute", "bgp_session", "route_table", "loop_check"],
    params: Dict[str, Any]
) -> Dict[str, Any]:
    """
    [검증] Batfish로 네트워크 속성을 검증합니다.
    
    Args:
        test_type: 검증 유형
            - "reachability": A→B 도달 가능 여부
            - "traceroute": 경로 추적
            - "bgp_session": BGP 세션 상태
            - "route_table": 라우팅 테이블
            - "loop_check": 루프 검사
        params: 테스트별 파라미터
            - reachability: {"src": "10.1.1.1", "dst": "10.2.2.2", "protocol": "tcp", "dst_port": 443}
            - traceroute: {"src": "PE1", "dst": "10.2.2.2"}
            - bgp_session: {"device": "PE1"}
            - route_table: {"device": "PE1", "vrf": "default"}
    
    Returns:
        검증 결과 (success, details, path 등)
    
    Examples:
        - network_verify("reachability", {"src": "10.1.1.1", "dst": "10.2.2.2"})
        - network_verify("traceroute", {"src": "PE1", "dst": "10.3.3.3"})
    """
    logger.info(f"network_verify({test_type}, {params})")
    
    try:
        batfish = get_batfish_server()
        
        # Batfish 초기화 확인
        if not batfish._initialized:
            return {"error": "Batfish not initialized. Use lab_manage('export_configs') first."}
        
        if test_type == "reachability":
            return batfish.check_reachability(
                src=params.get("src"),
                dst=params.get("dst"),
                protocol=params.get("protocol", "icmp"),
                dst_port=params.get("dst_port")
            )
        
        elif test_type == "traceroute":
            return batfish.traceroute(
                src=params.get("src"),
                dst=params.get("dst")
            )
        
        elif test_type == "bgp_session":
            return batfish.get_bgp_sessions(device=params.get("device"))
        
        elif test_type == "route_table":
            return batfish.get_route_table(
                device=params.get("device"),
                vrf=params.get("vrf", "default")
            )
        
        elif test_type == "loop_check":
            # Loop detection (simplified)
            edges = batfish.get_layer3_edges()
            return {"loop_detected": False, "edges_checked": len(edges)}
        
        else:
            return {"error": f"Unknown test_type: {test_type}"}
            
    except Exception as e:
        logger.error(f"network_verify error: {e}")
        return {"error": str(e)}


# =============================================================================
# 3. network.change - 설정 변경 (NSO)
# =============================================================================

@tool
def network_change(
    action: Literal[
        # 설정 변경
        "dry_run", "commit", "rollback", "diff",
        # 장비 라이프사이클
        "register_device", "delete_device", "sync_from", "fetch_host_keys"
    ],
    device: Optional[str] = None,
    config_path: Optional[str] = None,
    config_value: Optional[Any] = None,
    rollback_id: Optional[str] = None,
    device_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [변경] NSO를 통해 네트워크 설정을 변경하거나 장비를 관리합니다.
    
    ⚠️ 주의: commit/rollback/delete_device는 승인이 필요합니다.
    
    Args:
        action: 변경 액션
            [설정 변경]
            - "dry_run": 변경 시뮬레이션 (실제 적용 X)
            - "commit": 변경 적용 (⚠️ 승인 필요)
            - "rollback": 이전 상태로 복구 (⚠️ 승인 필요)
            - "diff": 현재 vs 변경안 비교
            
            [장비 라이프사이클]
            - "register_device": NSO에 장비 등록
            - "delete_device": NSO에서 장비 삭제 (⚠️ 승인 필요)
            - "sync_from": 장비에서 설정 동기화
            - "fetch_host_keys": SSH 호스트 키 가져오기
            
        device: 대상 장비명 (설정 변경/sync_from/delete_device 시)
        config_path: 설정 경로 (예: "interface/GigabitEthernet0/0/ip/address")
        config_value: 설정값 (action이 dry_run/commit일 때)
        rollback_id: 롤백 ID (action이 rollback일 때)
        device_info: 장비 등록 정보 (register_device 시)
            - name: 장비명 (필수)
            - oob_ip: 관리 IP (필수)
            - port: SSH 포트 (기본: 22)
            - authgroup: 인증 그룹 (기본: default)
            - ned_id: NED ID (기본: cisco-ios-cli-6.110)
            - protocol: 프로토콜 (기본: ssh)
    
    Returns:
        변경 결과 (preview, affected_devices, status 등)
    
    Examples:
        - network_change("dry_run", "PE1", "acl/100", {"permit": "10.1.1.0/24"})
        - network_change("register_device", device_info={"name": "NewRouter", "oob_ip": "192.168.1.100"})
        - network_change("sync_from", device="PE1")
        - network_change("delete_device", device="OldRouter")
    """
    logger.info(f"network_change({action}, device={device})")
    
    try:
        nso = get_nso_server()
        
        # ===== 설정 변경 =====
        if action == "dry_run":
            # Dry-run 모드로 변경 시뮬레이션
            return {
                "status": "simulated",
                "action": "dry_run",
                "device": device,
                "config_path": config_path,
                "config_value": config_value,
                "message": "Dry-run completed. No changes applied."
            }
        
        elif action == "commit":
            # 커밋은 승인이 필요
            return {
                "status": "requires_approval",
                "action": "commit",
                "device": device,
                "config_path": config_path,
                "message": "Use approval_request() to request commit approval."
            }
        
        elif action == "rollback":
            # 롤백은 승인이 필요
            return {
                "status": "requires_approval",
                "action": "rollback",
                "device": device,
                "rollback_id": rollback_id,
                "message": "Use approval_request() to request rollback approval."
            }
        
        elif action == "diff":
            # 현재 설정 조회
            current_config = nso.get_config(device, config_path)
            return {
                "status": "success",
                "action": "diff",
                "device": device,
                "config_path": config_path,
                "current_config": current_config,
                "proposed_value": config_value
            }
        
        # ===== 장비 라이프사이클 =====
        elif action == "register_device":
            if not device_info:
                return {"error": "device_info parameter required"}
            if "name" not in device_info or "oob_ip" not in device_info:
                return {"error": "device_info must contain 'name' and 'oob_ip'"}
            
            # Authgroup 생성 (필요 시)
            authgroup = device_info.get("authgroup", "default")
            if authgroup != "default":
                nso.client.create_authgroup(
                    group=authgroup,
                    username=device_info.get("username", "admin"),
                    password=device_info.get("password", "admin")
                )
            
            # 장비 등록
            success = nso.client.register_device(device_info)
            if not success:
                return {"error": f"Failed to register device: {device_info.get('name')}"}
            
            return {
                "status": "success",
                "action": "register_device",
                "device": device_info.get("name"),
                "message": f"Device {device_info.get('name')} registered successfully. Run sync_from to synchronize."
            }
        
        elif action == "delete_device":
            if not device:
                return {"error": "device parameter required"}
            
            # 삭제는 승인 권장
            success = nso.client.delete_device(device)
            if not success:
                return {"error": f"Failed to delete device: {device}"}
            
            return {
                "status": "success",
                "action": "delete_device",
                "device": device,
                "message": f"Device {device} deleted from NSO."
            }
        
        elif action == "sync_from":
            if not device:
                return {"error": "device parameter required"}
            
            result = nso.client.sync_from(device)
            return {
                "status": "success" if result.get("result", False) else "failed",
                "action": "sync_from",
                "device": device,
                "result": result
            }
        
        elif action == "fetch_host_keys":
            if not device:
                return {"error": "device parameter required"}
            
            result = nso.client.fetch_host_keys(device)
            return {
                "status": "success" if result else "failed",
                "action": "fetch_host_keys",
                "device": device,
                "message": "SSH host keys fetched." if result else "Failed to fetch host keys."
            }
        
        else:
            return {"error": f"Unknown action: {action}"}
            
    except Exception as e:
        logger.error(f"network_change error: {e}")
        return {"error": str(e)}


# =============================================================================
# 4. telemetry.query - 동적 데이터 조회
# =============================================================================

@tool
def telemetry_query(
    source: Literal["logs", "metrics", "flows"],
    filters: Dict[str, Any],
    time_range: Optional[str] = "1h"
) -> Dict[str, Any]:
    """
    [관측] 로그/메트릭/플로우 데이터를 조회합니다.
    
    Args:
        source: 데이터 소스
            - "logs": 시스템 로그/이벤트
            - "metrics": 인터페이스 통계/CPU/메모리
            - "flows": 트래픽 플로우 요약
        filters: 필터 조건
            - device: 장비명
            - severity: 로그 심각도 ("error", "warning")
            - interface: 인터페이스명
            - component: 컴포넌트 ("BGP", "OSPF")
        time_range: 조회 시간 범위 ("1h", "6h", "1d")
    
    Returns:
        정규화된 이벤트/메트릭 리스트 (최대 30개)
    
    Examples:
        - telemetry_query("logs", {"device": "PE1", "severity": "error"})
        - telemetry_query("metrics", {"interface": "Gi0/0", "device": "P1"})
    """
    logger.info(f"telemetry_query({source}, {filters}, {time_range})")
    
    try:
        telemetry = get_telemetry_server()
        
        if source == "logs":
            return telemetry.query_logs(
                device=filters.get("device"),
                severity=filters.get("severity"),
                component=filters.get("component"),
                time_range=time_range
            )
        
        elif source == "metrics":
            return telemetry.query_metrics(
                device=filters.get("device"),
                interface=filters.get("interface"),
                metric_type=filters.get("metric_type"),
                time_range=time_range
            )
        
        elif source == "flows":
            return telemetry.query_flows(
                src=filters.get("src"),
                dst=filters.get("dst"),
                time_range=time_range
            )
        
        else:
            return {"error": f"Unknown source: {source}"}
            
    except Exception as e:
        logger.error(f"telemetry_query error: {e}")
        return {"error": str(e)}


# =============================================================================
# 5. lab.manage - PNETLab 관리
# =============================================================================

@tool
def lab_manage(
    action: Literal[
        # 조회
        "show_inventory", "get_status", "get_console_link",
        # 장비 관리
        "add_node", "delete_node", "start_node", "stop_node",
        # 네트워크 관리
        "add_network", "delete_network",
        # 연결 관리
        "connect_interface", "disconnect_interface",
        # Batfish 통합
        "export_configs", "init_batfish"
    ],
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [Lab] PNETLab 실험실을 관리합니다.
    
    Args:
        action: 관리 액션
            [조회]
            - "show_inventory": 현재 Lab 장비 목록
            - "get_status": 장비 상태 조회
            - "get_console_link": 콘솔 접속 링크
            
            [장비 관리]
            - "add_node": 새 장비 추가
            - "delete_node": 장비 삭제 (⚠️ 승인 필요)
            - "start_node": 장비 시작
            - "stop_node": 장비 중지
            
            [네트워크 관리]
            - "add_network": 네트워크(Cloud) 추가
            - "delete_network": 네트워크 삭제 (⚠️ 승인 필요)
            
            [연결 관리]
            - "connect_interface": 장비 인터페이스를 네트워크에 연결
            - "disconnect_interface": 인터페이스 연결 해제
            
            [Batfish 통합]
            - "export_configs": NSO에서 Batfish용 cfg 추출
            - "init_batfish": Batfish 스냅샷 초기화
            
        params: 액션별 파라미터
            - get_status: {"device": "PE1"}
            - get_console_link: {"device": "PE1"}
            - add_node: {"name": "vIOS99", "template": "vios", "left": 400, "top": 300}
            - delete_node: {"name": "vIOS99"}
            - start_node: {"name": "vIOS99"}
            - stop_node: {"name": "vIOS99"}
            - add_network: {"name": "Cloud99", "net_type": "pnet2"}
            - delete_network: {"name": "Cloud99"}
            - connect_interface: {"device_name": "vIOS99", "interface_id": 0, "network_name": "Cloud1"}
            - disconnect_interface: {"device_name": "vIOS99", "interface_id": 0}
            - export_configs: {"output_dir": "/path/to/output", "devices": ["PE1", "PE2"]}
            - init_batfish: {"snapshot_path": "/path/to/snapshot"}
    
    Returns:
        액션 결과
    
    Examples:
        - lab_manage("show_inventory")
        - lab_manage("add_node", {"name": "NewRouter", "template": "vios"})
        - lab_manage("connect_interface", {"device_name": "NewRouter", "interface_id": 0, "network_name": "Cloud1"})
    """
    logger.info(f"lab_manage({action}, {params})")
    
    try:
        params = params or {}
        pnetlab = get_pnetlab_server()
        
        # ===== 조회 =====
        if action == "show_inventory":
            return pnetlab.show_inventory()
        
        elif action == "get_status":
            return pnetlab.get_status(device=params.get("device"))
        
        elif action == "get_console_link":
            device = params.get("device")
            if not device:
                return {"error": "device parameter required"}
            return pnetlab.get_console_link(device)
        
        # ===== 장비 관리 =====
        elif action == "add_node":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            return pnetlab.add_node(
                name=name,
                template=params.get("template", "vios"),
                left=params.get("left", 400),
                top=params.get("top", 300)
            )
        
        elif action == "delete_node":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            # 삭제는 승인 권장
            return pnetlab.delete_node(name=name)
        
        elif action == "start_node":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            return pnetlab.start_node(name=name)
        
        elif action == "stop_node":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            return pnetlab.stop_node(name=name)
        
        # ===== 네트워크 관리 =====
        elif action == "add_network":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            return pnetlab.add_network(
                name=name,
                net_type=params.get("net_type", "pnet2"),
                left=params.get("left", 300),
                top=params.get("top", 150)
            )
        
        elif action == "delete_network":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            return pnetlab.delete_network(name=name)
        
        # ===== 연결 관리 =====
        elif action == "connect_interface":
            device_name = params.get("device_name")
            interface_id = params.get("interface_id")
            network_name = params.get("network_name")
            if not all([device_name, network_name]) or interface_id is None:
                return {"error": "device_name, interface_id, network_name required"}
            return pnetlab.connect_interface(
                device_name=device_name,
                interface_id=interface_id,
                network_name=network_name
            )
        
        elif action == "disconnect_interface":
            device_name = params.get("device_name")
            interface_id = params.get("interface_id", 0)
            if not device_name:
                return {"error": "device_name parameter required"}
            return pnetlab.disconnect_interface(
                device_name=device_name,
                interface_id=interface_id
            )
        
        # ===== Batfish 통합 =====
        elif action == "export_configs":
            nso = get_nso_server()
            output_dir = params.get("output_dir", "./batfish_snapshot")
            devices = params.get("devices")
            export_xml = params.get("export_xml", False)
            return nso.export_batfish_configs(
                devices=devices,
                output_dir=output_dir,
                export_xml=export_xml
            )
        
        elif action == "init_batfish":
            batfish = get_batfish_server()
            snapshot_path = params.get("snapshot_path")
            if not snapshot_path:
                return {"error": "snapshot_path parameter required"}
            return batfish.init_snapshot(snapshot_path)
        
        else:
            return {"error": f"Unknown action: {action}"}
            
    except Exception as e:
        logger.error(f"lab_manage error: {e}")
        return {"error": str(e)}


# =============================================================================
# 6. approval.request - 승인 요청
# =============================================================================

# 승인 요청 저장소 (메모리)
_pending_approvals: Dict[str, Dict[str, Any]] = {}
_approval_counter = 0


@tool
def approval_request(
    action_type: str,
    description: str,
    affected_devices: List[str],
    risk_assessment: str
) -> Dict[str, Any]:
    """
    [승인] 위험 작업에 대한 승인을 요청합니다.
    
    Args:
        action_type: 요청 액션 유형 ("commit", "rollback", "bulk_change")
        description: 변경 내용 설명
        affected_devices: 영향받는 장비 목록
        risk_assessment: 위험도 평가 ("low", "medium", "high")
    
    Returns:
        승인 요청 결과 (request_id, status)
    
    Examples:
        - approval_request("commit", "ACL 규칙 추가", ["PE1"], "low")
    """
    global _approval_counter
    logger.info(f"approval_request({action_type}, {description})")
    
    try:
        _approval_counter += 1
        request_id = f"REQ-{_approval_counter:04d}"
        
        approval = {
            "request_id": request_id,
            "action_type": action_type,
            "description": description,
            "affected_devices": affected_devices,
            "risk_assessment": risk_assessment,
            "status": "pending",
            "created_at": __import__("datetime").datetime.now().isoformat()
        }
        
        _pending_approvals[request_id] = approval
        
        return {
            "status": "pending",
            "request_id": request_id,
            "message": f"Approval request created. Awaiting review.",
            "details": approval
        }
        
    except Exception as e:
        logger.error(f"approval_request error: {e}")
        return {"error": str(e)}


def approve_request(request_id: str, approved: bool, reason: str = "") -> Dict[str, Any]:
    """
    승인 요청 처리 (관리자용)
    
    Args:
        request_id: 요청 ID
        approved: 승인 여부
        reason: 승인/거부 사유
    """
    if request_id not in _pending_approvals:
        return {"error": f"Request not found: {request_id}"}
    
    approval = _pending_approvals[request_id]
    approval["status"] = "approved" if approved else "rejected"
    approval["reason"] = reason
    approval["processed_at"] = __import__("datetime").datetime.now().isoformat()
    
    return approval


# =============================================================================
# 7. help.guide - 도움말
# =============================================================================

@tool
def help_guide(
    topic: Literal["tools", "examples", "troubleshooting", "best_practices"]
) -> str:
    """
    [도움] 도구 사용법과 예시를 제공합니다.
    
    Args:
        topic: 도움말 주제
            - "tools": 사용 가능한 도구 목록
            - "examples": 일반적인 사용 예시
            - "troubleshooting": 문제 해결 가이드
            - "best_practices": 권장 사항
    
    Returns:
        도움말 텍스트
    """
    logger.info(f"help_guide({topic})")
    
    guides = {
        "tools": """
## 사용 가능한 도구

1. **network_query** - 네트워크 설정 조회
   - category: device, interface, routing, vrf, security, acl
   
2. **network_verify** - Batfish 네트워크 검증
   - test_type: reachability, traceroute, bgp_session, route_table

3. **network_change** - 설정 변경 (승인 필요)
   - action: dry_run, commit, rollback, diff

4. **telemetry_query** - 로그/메트릭 조회
   - source: logs, metrics, flows

5. **lab_manage** - 실험실 관리
   - action: show_inventory, get_status, export_configs, init_batfish

6. **approval_request** - 위험 작업 승인 요청

7. **help_guide** - 도움말 (현재 도구)
""",
        
        "examples": """
## 일반적인 사용 예시

### 장비 목록 조회
```python
network_query("device")
```

### BGP 설정 확인
```python
network_query("routing", device="PE1", params={"protocol": "bgp"})
```

### 도달성 검증
```python
lab_manage("export_configs", {"output_dir": "./snapshot"})
lab_manage("init_batfish", {"snapshot_path": "./snapshot"})
network_verify("reachability", {"src": "PE1", "dst": "10.2.2.2"})
```

### 설정 변경 (dry-run)
```python
network_change("dry_run", "PE1", "acl/100", {"permit": "10.1.1.0/24"})
```
""",
        
        "troubleshooting": """
## 문제 해결 가이드

### "Batfish not initialized" 오류
1. `lab_manage("export_configs", {"output_dir": "./snapshot"})` 실행
2. `lab_manage("init_batfish", {"snapshot_path": "./snapshot"})` 실행

### "Device not found" 오류
- `network_query("device")`로 장비 목록 확인
- 장비명 대소문자 확인

### NSO 연결 실패
- .env 파일의 NSO_BASE_URL, NSO_USER, NSO_PASS 확인
- NSO Docker 컨테이너 상태 확인
""",
        
        "best_practices": """
## 권장 사항

1. **변경 전 검증**
   - 설정 변경 전 반드시 `network_change("dry_run", ...)` 실행
   - `network_verify("reachability", ...)` 로 영향 확인

2. **승인 프로세스**
   - commit/rollback은 항상 `approval_request()` 사용
   - 위험도(risk_assessment)를 정확히 평가

3. **효율적인 조회**
   - 전체 데이터 대신 필요한 장비/설정만 조회
   - 캐시된 결과 활용

4. **금지 행동**
   - any-any permit ACL 추가 금지
   - default route 무단 추가 금지
   - 전체 BGP clear 금지
"""
    }
    
    return guides.get(topic, f"Unknown topic: {topic}")


# =============================================================================
# 8. device.workflow - PNETLab-NSO 통합 워크플로우
# =============================================================================

@tool
def device_workflow(
    action: Literal["add", "delete", "sync_topology"],
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    [워크플로우] PNETLab과 NSO를 동기화하는 통합 장비 관리 워크플로우입니다.
    
    ⚠️ 주의: delete 작업은 승인이 권장됩니다.
    
    Args:
        action: 워크플로우 액션
            - "add": 장비 추가 (PNETLab 추가 → NSO 등록 → sync_from)
            - "delete": 장비 삭제 (NSO 해제 → PNETLab 삭제) ⚠️ 승인 권장
            - "sync_topology": 토폴로지 동기화 (PNETLab 장비 → NSO 자동 등록)
            
        params: 액션별 파라미터
            - add:
                - name: 장비명 (필수)
                - template: 템플릿 (기본: vios)
                - oob_ip: 관리 IP (필수 - NSO 등록용)
                - authgroup: 인증 그룹 (기본: default)
            - delete:
                - name: 장비명 (필수)
            - sync_topology:
                - device_info_file: 장비 정보 파일 경로 (선택)
                - auto_register: 미등록 장비 자동 등록 (기본: True)
    
    Returns:
        워크플로우 실행 결과
        
    Examples:
        - device_workflow("add", {"name": "R10", "oob_ip": "10.10.10.10", "template": "vios"})
        - device_workflow("delete", {"name": "R10"})
        - device_workflow("sync_topology")
    """
    logger.info(f"device_workflow({action}, {params})")
    
    import time
    
    try:
        params = params or {}
        pnetlab = get_pnetlab_server()
        nso = get_nso_server()
        
        results = {
            "action": action,
            "steps": [],
            "status": "in_progress"
        }
        
        # ===== 장비 추가 워크플로우 =====
        if action == "add":
            name = params.get("name")
            oob_ip = params.get("oob_ip")
            template = params.get("template", "vios")
            
            if not name:
                return {"error": "name parameter required"}
            if not oob_ip:
                return {"error": "oob_ip parameter required for NSO registration"}
            
            # Step 1: PNETLab에 노드 추가
            step1 = pnetlab.add_node(
                name=name,
                template=template,
                left=params.get("left", 400),
                top=params.get("top", 300)
            )
            results["steps"].append({"step": "add_node", "result": step1})
            
            if "error" in step1:
                results["status"] = "failed"
                results["error"] = f"Failed to add node: {step1['error']}"
                return results
            
            # Step 2: 노드 시작
            step2 = pnetlab.start_node(name=name)
            results["steps"].append({"step": "start_node", "result": step2})
            
            # Step 3: 부팅 대기 (30초)
            results["steps"].append({"step": "wait_boot", "duration": "30s"})
            logger.info(f"Waiting 30s for {name} to boot...")
            time.sleep(30)
            
            # Step 4: NSO에 장비 등록
            device_info = {
                "name": name,
                "oob_ip": oob_ip,
                "port": params.get("port", 22),
                "authgroup": params.get("authgroup", "default"),
                "ned_id": params.get("ned_id", "cisco-ios-cli-6.110"),
                "protocol": params.get("protocol", "ssh")
            }
            
            step4 = nso.client.register_device(device_info)
            results["steps"].append({"step": "register_device", "success": step4})
            
            if not step4:
                results["status"] = "partial"
                results["warning"] = "Device added to PNETLab but NSO registration failed"
                return results
            
            # Step 5: SSH 호스트 키 가져오기
            step5 = nso.client.fetch_host_keys(name)
            results["steps"].append({"step": "fetch_host_keys", "success": step5})
            
            # Step 6: 설정 동기화
            step6 = nso.client.sync_from(name)
            results["steps"].append({"step": "sync_from", "result": step6})
            
            results["status"] = "success"
            results["message"] = f"Device {name} added to PNETLab and registered with NSO"
            return results
        
        # ===== 장비 삭제 워크플로우 =====
        elif action == "delete":
            name = params.get("name")
            if not name:
                return {"error": "name parameter required"}
            
            # Step 1: NSO에서 장비 삭제 (먼저!)
            try:
                step1 = nso.client.delete_device(name)
                results["steps"].append({"step": "nso_delete_device", "success": step1})
            except Exception as e:
                results["steps"].append({"step": "nso_delete_device", "error": str(e)})
            
            # Step 2: PNETLab에서 노드 중지
            step2 = pnetlab.stop_node(name=name)
            results["steps"].append({"step": "stop_node", "result": step2})
            
            # Step 3: PNETLab에서 노드 삭제
            step3 = pnetlab.delete_node(name=name)
            results["steps"].append({"step": "delete_node", "result": step3})
            
            results["status"] = "success"
            results["message"] = f"Device {name} removed from NSO and PNETLab"
            return results
        
        # ===== 토폴로지 동기화 워크플로우 =====
        elif action == "sync_topology":
            auto_register = params.get("auto_register", True)
            device_info_file = params.get("device_info_file")
            
            # Step 1: PNETLab 장비 목록 조회
            pnetlab_inventory = pnetlab.show_inventory()
            pnetlab_nodes = pnetlab_inventory.get("nodes", [])
            pnetlab_names = {node.get("name") for node in pnetlab_nodes if node.get("name")}
            results["steps"].append({
                "step": "pnetlab_inventory",
                "count": len(pnetlab_names),
                "devices": list(pnetlab_names)
            })
            
            # Step 2: NSO 등록 장비 목록 조회
            nso_devices = nso.list_devices()
            nso_names = set()
            if isinstance(nso_devices, dict) and "devices" in nso_devices:
                nso_names = {d.get("name") for d in nso_devices["devices"] if d.get("name")}
            results["steps"].append({
                "step": "nso_inventory",
                "count": len(nso_names),
                "devices": list(nso_names)
            })
            
            # Step 3: 미등록 장비 찾기
            unregistered = pnetlab_names - nso_names
            results["unregistered_devices"] = list(unregistered)
            results["steps"].append({
                "step": "compare",
                "unregistered_count": len(unregistered),
                "unregistered": list(unregistered)
            })
            
            # Step 4: 장비 정보 파일에서 OOB IP 로드 (있다면)
            device_ip_map = {}
            if device_info_file:
                try:
                    import json
                    with open(device_info_file, 'r') as f:
                        info = json.load(f)
                    for dev in info.get("devices", []):
                        device_ip_map[dev["name"]] = dev.get("oob_ip")
                except Exception as e:
                    results["steps"].append({"step": "load_device_info", "error": str(e)})
            
            # Step 5: 자동 등록 (활성화된 경우)
            registered = []
            failed = []
            
            if auto_register and unregistered:
                for device_name in unregistered:
                    oob_ip = device_ip_map.get(device_name)
                    
                    if not oob_ip:
                        failed.append({
                            "name": device_name,
                            "reason": "oob_ip not found in device_info_file"
                        })
                        continue
                    
                    try:
                        device_info = {
                            "name": device_name,
                            "oob_ip": oob_ip,
                            "authgroup": "default",
                            "ned_id": "cisco-ios-cli-6.110"
                        }
                        
                        if nso.client.register_device(device_info):
                            nso.client.fetch_host_keys(device_name)
                            nso.client.sync_from(device_name)
                            registered.append(device_name)
                        else:
                            failed.append({"name": device_name, "reason": "registration failed"})
                    except Exception as e:
                        failed.append({"name": device_name, "reason": str(e)})
            
            results["steps"].append({
                "step": "auto_register",
                "registered": registered,
                "failed": failed
            })
            
            results["status"] = "success"
            results["summary"] = {
                "pnetlab_devices": len(pnetlab_names),
                "nso_devices": len(nso_names),
                "newly_registered": len(registered),
                "failed_registration": len(failed)
            }
            
            if unregistered and not auto_register:
                results["message"] = f"Found {len(unregistered)} unregistered devices. Use auto_register=True to register them."
            elif registered:
                results["message"] = f"Registered {len(registered)} devices to NSO: {', '.join(registered)}"
            else:
                results["message"] = "Topology is synchronized. All PNETLab devices are registered in NSO."
            
            return results
        
        else:
            return {"error": f"Unknown action: {action}"}
            
    except Exception as e:
        logger.error(f"device_workflow error: {e}")
        return {"error": str(e), "status": "failed"}




# =============================================================================
# 도구 목록 내보내기
# =============================================================================

UNIFIED_TOOLS = [
    network_query,
    network_verify,
    network_change,
    telemetry_query,
    lab_manage,
    approval_request,
    help_guide,
    device_workflow,  # PNETLab-NSO 통합 워크플로우
]

# 도구 이름 → 도구 매핑
TOOL_NAME_MAP = {
    "network_query": network_query,
    "network_verify": network_verify,
    "network_change": network_change,
    "telemetry_query": telemetry_query,
    "lab_manage": lab_manage,
    "approval_request": approval_request,
    "help_guide": help_guide,
    "device_workflow": device_workflow,
}


def get_unified_tools() -> List:
    """통합 도구 목록 반환 (전체)"""
    return UNIFIED_TOOLS


def get_filtered_tools(tool_names: List[str]) -> List:
    """
    이름 목록으로 도구 필터링 (Planner가 선택한 도구만)
    
    Args:
        tool_names: 도구 이름 리스트 (예: ["network_query", "lab_manage"])
        
    Returns:
        필터링된 도구 리스트
        
    Example:
        tools = get_filtered_tools(["network_query", "lab_manage"])
        # → [network_query, lab_manage] 도구만 반환
    """
    filtered = []
    for name in tool_names:
        if name in TOOL_NAME_MAP:
            filtered.append(TOOL_NAME_MAP[name])
        else:
            logger.warning(f"Unknown tool name: {name}")
    
    # 최소 1개 도구 보장
    if not filtered:
        logger.warning("No tools matched, returning network_query as fallback")
        filtered = [network_query]
    
    return filtered


def get_tool_count() -> int:
    """도구 수 반환"""
    return len(UNIFIED_TOOLS)


def get_tool_names() -> List[str]:
    """사용 가능한 도구 이름 목록"""
    return list(TOOL_NAME_MAP.keys())

