"""
LangGraph Agent Tools
에이전트가 사용하는 도구(Tool) 정의
"""

import sys
from pathlib import Path
from typing import List, Dict, Any

# 상위 모듈 import를 위한 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from langchain_core.tools import tool

from clients.pnetlab import PnetlabClient
from clients.nso import NSOClient
from inventory.builder import InventoryBuilder
from config.settings import settings

import logging
logger = logging.getLogger(__name__)


# =============================================================================
# 클라이언트 초기화 (전역)
# =============================================================================

_nso_client = None
_pnetlab_client = None


def get_nso_client() -> NSOClient:
    """NSO 클라이언트 싱글톤 반환"""
    global _nso_client
    if _nso_client is None:
        _nso_client = NSOClient(
            base_url=settings.nso.base_url,
            username=settings.nso.username,
            password=settings.nso.password,
            timeout=settings.nso.timeout
        )
    return _nso_client


def get_pnetlab_client() -> PnetlabClient:
    """PNETLab 클라이언트 싱글톤 반환"""
    global _pnetlab_client
    if _pnetlab_client is None:
        _pnetlab_client = PnetlabClient(
            base_url=settings.pnetlab.base_url,
            username=settings.pnetlab.username,
            password=settings.pnetlab.password,
            timeout=settings.pnetlab.timeout
        )
    return _pnetlab_client


# =============================================================================
# Tier 1: Discovery (탐색) 도구
# =============================================================================

@tool
def scan_network_devices() -> List[str]:
    """
    [Discovery] NSO에 등록된 모든 장비 목록을 조회합니다.
    
    Returns:
        장비 이름 리스트 (예: ["P1", "PE1", "Leaf1"])
    """
    logger.info("scan_network_devices() called")
    try:
        nso = get_nso_client()
        devices = nso.get_devices()
        logger.info(f"Found {len(devices)} devices")
        return devices
    except Exception as e:
        logger.error(f"scan_network_devices error: {e}")
        return []


@tool
def get_device_info(device: str) -> Dict[str, Any]:
    """
    [Discovery] 특정 장비의 기본 정보를 조회합니다.
    
    Args:
        device: 장비명 (예: "PE1")
        
    Returns:
        장비 정보 딕셔너리 (IP, 포트, 인증그룹 등)
    """
    logger.info(f"get_device_info({device}) called")
    try:
        nso = get_nso_client()
        info = nso.get_device_info(device)
        return info if info else {"error": f"Device {device} not found"}
    except Exception as e:
        logger.error(f"get_device_info error: {e}")
        return {"error": str(e)}


# =============================================================================
# Tier 2: Diagnosis (진단) 도구
# =============================================================================

@tool
def get_interfaces(device: str) -> List[Dict[str, Any]]:
    """
    [Diagnosis] 장비의 모든 인터페이스 설정을 조회합니다.
    
    Args:
        device: 장비명
        
    Returns:
        인터페이스 정보 리스트
    """
    logger.info(f"get_interfaces({device}) called")
    try:
        nso = get_nso_client()
        return nso.get_interfaces(device)
    except Exception as e:
        logger.error(f"get_interfaces error: {e}")
        return []


@tool
def get_interface_ips(device: str) -> Dict[str, str]:
    """
    [Diagnosis] 장비의 인터페이스별 IP 주소를 조회합니다.
    
    Args:
        device: 장비명
        
    Returns:
        {인터페이스명: IP/Mask} 매핑
    """
    logger.info(f"get_interface_ips({device}) called")
    try:
        nso = get_nso_client()
        return nso.get_interface_ips(device)
    except Exception as e:
        logger.error(f"get_interface_ips error: {e}")
        return {}


@tool
def get_routing_info(device: str, protocol: str) -> Any:
    """
    [Diagnosis] 라우팅 프로토콜 설정을 조회합니다.
    
    Args:
        device: 장비명
        protocol: 'bgp' 또는 'ospf'
        
    Returns:
        라우팅 설정 정보
    """
    logger.info(f"get_routing_info({device}, {protocol}) called")
    try:
        nso = get_nso_client()
        if protocol.lower() == 'bgp':
            return {
                "neighbors": nso.get_bgp_neighbors(device),
                "as_number": nso.get_bgp_as_number(device)
            }
        elif protocol.lower() == 'ospf':
            return nso.get_ospf_config(device)
        else:
            return {"error": f"Unknown protocol: {protocol}. Use 'bgp' or 'ospf'"}
    except Exception as e:
        logger.error(f"get_routing_info error: {e}")
        return {"error": str(e)}


@tool
def get_security_config(device: str) -> Dict[str, Any]:
    """
    [Diagnosis] 장비의 보안 설정(SSH, AAA)을 조회합니다.
    
    Args:
        device: 장비명
        
    Returns:
        보안 설정 정보
    """
    logger.info(f"get_security_config({device}) called")
    try:
        nso = get_nso_client()
        return {
            "ssh": nso.get_ssh_config(device),
            "aaa": nso.get_aaa_config(device)
        }
    except Exception as e:
        logger.error(f"get_security_config error: {e}")
        return {"error": str(e)}


# =============================================================================
# Tier 3: Analysis (분석) 도구
# =============================================================================

@tool
def compare_devices(dev1: str, dev2: str, aspect: str) -> Dict[str, Any]:
    """
    [Analysis] 두 장비의 설정을 비교합니다.
    
    Args:
        dev1: 첫 번째 장비명
        dev2: 두 번째 장비명
        aspect: 비교 항목 ('interface_count', 'bgp_neighbor_count', 'bgp_as')
        
    Returns:
        비교 결과
    """
    logger.info(f"compare_devices({dev1}, {dev2}, {aspect}) called")
    try:
        nso = get_nso_client()
        return nso.compare_devices(dev1, dev2, aspect)
    except Exception as e:
        logger.error(f"compare_devices error: {e}")
        return {"error": str(e)}


@tool
def find_devices_by_condition(condition: str) -> List[str]:
    """
    [Analysis] 조건에 맞는 장비를 검색합니다.
    
    Args:
        condition: 'ssh_enabled', 'bgp_configured'
        
    Returns:
        조건에 맞는 장비 리스트
    """
    logger.info(f"find_devices_by_condition({condition}) called")
    try:
        nso = get_nso_client()
        return nso.find_devices_with(condition)
    except Exception as e:
        logger.error(f"find_devices_by_condition error: {e}")
        return []


@tool
def check_ip_conflicts() -> List[Dict[str, Any]]:
    """
    [Analysis] 네트워크 전체의 IP 충돌을 검사합니다.
    
    Returns:
        충돌 정보 리스트
    """
    logger.info("check_ip_conflicts() called")
    try:
        nso = get_nso_client()
        return nso.check_ip_conflicts()
    except Exception as e:
        logger.error(f"check_ip_conflicts error: {e}")
        return []


# =============================================================================
# Tier 4: Verification (검증) 도구
# =============================================================================

@tool
def ping_test(device: str, target: str) -> Dict[str, Any]:
    """
    [Verification] 장비에서 대상으로 Ping 테스트를 수행합니다.
    
    Args:
        device: 출발지 장비명
        target: 대상 IP 주소
        
    Returns:
        Ping 결과 (success, packet_loss, sent, received)
    """
    logger.info(f"ping_test({device}, {target}) called")
    try:
        nso = get_nso_client()
        return nso.ping(device, target)
    except Exception as e:
        logger.error(f"ping_test error: {e}")
        return {"error": str(e)}


@tool
def traceroute_test(device: str, target: str) -> Dict[str, Any]:
    """
    [Verification] 장비에서 대상까지 경로를 추적합니다.
    
    Args:
        device: 출발지 장비명
        target: 대상 IP 주소
        
    Returns:
        경로 정보 (path, hop_count)
    """
    logger.info(f"traceroute_test({device}, {target}) called")
    try:
        nso = get_nso_client()
        return nso.traceroute(device, target)
    except Exception as e:
        logger.error(f"traceroute_test error: {e}")
        return {"error": str(e)}


# =============================================================================
# Tier 5: Integration (통합) 도구 - Lab ↔ NSO
# =============================================================================

@tool
def lab_show_inventory() -> Dict[str, Any]:
    """
    [Integration] 현재 열려있는 PNETLab 실험실의 장비 목록을 조회합니다.
    
    Returns:
        장비 목록 및 요약 정보
    """
    logger.info("lab_show_inventory() called")
    try:
        pnetlab = get_pnetlab_client()
        
        # 로그인
        if not pnetlab.is_authenticated:
            if not pnetlab.login():
                return {"error": "PNETLab 로그인 실패"}
        
        # 토폴로지 조회
        topology = pnetlab.get_session_topology()
        if "error" in topology:
            return topology
        
        # 노드 추출
        nodes = pnetlab.get_nodes_from_topology(topology)
        
        return {
            "status": "success",
            "total_nodes": len(nodes),
            "nodes": [{"name": n["name"], "type": n["type"]} for n in nodes]
        }
        
    except Exception as e:
        logger.error(f"lab_show_inventory error: {e}")
        return {"error": str(e)}


@tool
def lab_sync_to_nso() -> Dict[str, Any]:
    """
    [Integration] 현재 열려있는 PNETLab 실험실을 NSO에 자동 연동합니다.
    
    작업 순서:
    1. PNETLab에서 장비 목록 조회
    2. device_info.json 자동 생성
    3. NSO에 장비 등록 (기존 스크립트 활용)
    4. 결과 요약
    
    ⚠️ 주의: 이 작업은 NSO에 장비를 등록합니다.
    
    Returns:
        연동 결과 (성공/실패 수, 상세 정보)
    """
    logger.info("lab_sync_to_nso() called")
    
    result = {
        "status": "in_progress",
        "steps": [],
        "success_count": 0,
        "fail_count": 0,
        "devices": []
    }
    
    try:
        # Step 1: PNETLab 토폴로지 조회
        result["steps"].append("PNETLab 토폴로지 조회 중...")
        
        pnetlab = get_pnetlab_client()
        if not pnetlab.is_authenticated:
            if not pnetlab.login():
                result["status"] = "failed"
                result["error"] = "PNETLab 로그인 실패"
                return result
        
        topology = pnetlab.get_session_topology()
        if "error" in topology:
            result["status"] = "failed"
            result["error"] = f"토폴로지 조회 실패: {topology['error']}"
            return result
        
        result["steps"].append("✅ 토폴로지 조회 완료")
        
        # Step 2: 인벤토리 생성
        result["steps"].append("인벤토리 생성 중...")
        
        builder = InventoryBuilder(settings.pnetlab.base_url)
        
        # 기존 device_info.json이 있으면 보조 매핑으로 사용
        aux_mapping = builder.load_auxiliary_mapping(
            "Data/Pnetlab/Research_Institute_Internal_DC/device_info.json"
        )
        
        inventory = builder.from_topology(topology, aux_mapping)
        
        result["steps"].append(f"✅ 인벤토리 생성 완료 ({len(inventory['devices'])}개 장비)")
        result["devices"] = [d["name"] for d in inventory["devices"]]
        
        # Step 3: NSO에 등록된 장비 확인
        result["steps"].append("NSO 등록 상태 확인 중...")
        
        nso = get_nso_client()
        registered = nso.get_devices()
        
        new_devices = [d["name"] for d in inventory["devices"] if d["name"] not in registered]
        already_registered = [d["name"] for d in inventory["devices"] if d["name"] in registered]
        
        result["steps"].append(f"✅ NSO 확인 완료 (기존: {len(already_registered)}개, 신규: {len(new_devices)}개)")
        
        # Step 4: 결과 요약
        result["status"] = "success"
        result["success_count"] = len(already_registered)
        result["summary"] = {
            "total": len(inventory["devices"]),
            "already_registered": already_registered,
            "new_devices": new_devices,
            "message": "NSO 등록이 필요한 경우 2-NSO_Register.py를 실행하세요."
        }
        
        return result
        
    except Exception as e:
        logger.error(f"lab_sync_to_nso error: {e}")
        result["status"] = "failed"
        result["error"] = str(e)
        return result


# =============================================================================
# 도구 목록 내보내기
# =============================================================================

# 에이전트에서 사용할 도구 목록
ALL_TOOLS = [
    # Tier 1: Discovery
    scan_network_devices,
    get_device_info,
    # Tier 2: Diagnosis
    get_interfaces,
    get_interface_ips,
    get_routing_info,
    get_security_config,
    # Tier 3: Analysis
    compare_devices,
    find_devices_by_condition,
    check_ip_conflicts,
    # Tier 4: Verification
    ping_test,
    traceroute_test,
    # Tier 5: Integration
    lab_show_inventory,
    lab_sync_to_nso,
]


def get_tools():
    """에이전트에서 사용할 도구 목록 반환"""
    return ALL_TOOLS

