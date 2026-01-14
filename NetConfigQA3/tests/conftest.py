"""
NetConfigQA3 Test Configuration

pytest fixtures와 공통 테스트 유틸리티 제공
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, AsyncMock
from typing import Dict, Any, List

# 프로젝트 루트를 Python 경로에 추가
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT.parent))  # Make_Dataset 모듈 접근용


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture
def sample_devices() -> List[str]:
    """샘플 장비 목록"""
    return ["PE1", "PE2", "P1", "CE1", "Spine1", "Leaf1"]


@pytest.fixture
def sample_device_info() -> Dict[str, Any]:
    """샘플 장비 정보"""
    return {
        "name": "PE1",
        "address": "10.0.0.1",
        "port": 22,
        "authgroup": "default",
        "device-type": {"cli": {"ned-id": "cisco-ios-cli-6.89"}}
    }


@pytest.fixture
def sample_interfaces() -> List[Dict[str, Any]]:
    """샘플 인터페이스 목록"""
    return [
        {"name": "GigabitEthernet0/0", "ip": {"address": {"primary": {"address": "10.1.1.1", "mask": "255.255.255.0"}}}},
        {"name": "GigabitEthernet0/1", "ip": {"address": {"primary": {"address": "10.1.2.1", "mask": "255.255.255.0"}}}},
        {"name": "Loopback0", "ip": {"address": {"primary": {"address": "1.1.1.1", "mask": "255.255.255.255"}}}},
    ]


@pytest.fixture
def sample_running_config() -> str:
    """샘플 running-config"""
    return """!
version 15.7
hostname PE1
!
interface GigabitEthernet0/0
 ip address 10.1.1.1 255.255.255.0
 no shutdown
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
!
router bgp 65001
 neighbor 10.1.1.2 remote-as 65002
!
end
"""


@pytest.fixture
def sample_topology() -> Dict[str, Any]:
    """샘플 PNETLab 토폴로지"""
    return {
        "name": "Test Lab",
        "path": "/labs/test_lab",
        "nodes": {
            "1": {"name": "PE1", "type": "qemu", "template": "vios"},
            "2": {"name": "PE2", "type": "qemu", "template": "vios"},
            "3": {"name": "CE1", "type": "qemu", "template": "vios"},
        }
    }


# =============================================================================
# Mock Client Fixtures
# =============================================================================

@pytest.fixture
def mock_nso_client(sample_devices, sample_device_info, sample_interfaces, sample_running_config):
    """NSO 클라이언트 모킹"""
    mock = MagicMock()
    
    # 기본 메서드 모킹
    mock.get_devices.return_value = sample_devices
    mock.get_device_info.return_value = sample_device_info
    mock.get_interfaces.return_value = sample_interfaces
    mock.get_interface_ips.return_value = {
        "GigabitEthernet0/0": "10.1.1.1/255.255.255.0",
        "Loopback0": "1.1.1.1/255.255.255.255"
    }
    mock.get_bgp_neighbors.return_value = [{"neighbor": "10.1.1.2", "remote-as": 65002}]
    mock.get_bgp_as_number.return_value = 65001
    mock.get_ospf_config.return_value = {"process-id": 1, "router-id": "1.1.1.1"}
    mock.get_ssh_config.return_value = {"enabled": True, "version": "2"}
    mock.get_aaa_config.return_value = {"enabled": True, "methods": ["authentication"]}
    mock.get_vrf_list.return_value = ["VRF_A", "VRF_B"]
    
    # CLI 명령어 실행 모킹
    mock._run_command.return_value = sample_running_config
    
    # 연결 상태
    mock.base_url = "http://localhost:8080/restconf/data"
    mock.timeout = 30
    
    return mock


@pytest.fixture
def mock_batfish_session(sample_devices):
    """Batfish 세션 모킹"""
    mock = MagicMock()
    
    # 노드 정보
    mock.nodes = sample_devices[:4]  # PE1, PE2, P1, CE1
    mock.interfaces = {
        "PE1": [{"name": "GigabitEthernet0/0", "active": True, "primary_address": "10.1.1.1/24"}],
        "PE2": [{"name": "GigabitEthernet0/0", "active": True, "primary_address": "10.1.2.1/24"}],
    }
    mock.node_ips = {
        "PE1": ["10.1.1.1", "1.1.1.1"],
        "PE2": ["10.1.2.1", "2.2.2.2"],
    }
    
    # 초기화 상태
    mock._initialized = True
    mock.snapshot_name = "baseline"
    
    # Batfish 쿼리 모킹
    mock.bf = MagicMock()
    mock.bf.q = MagicMock()
    
    # reachability 쿼리 결과
    mock_reachability_result = MagicMock()
    mock_reachability_result.frame.return_value = MagicMock()
    mock.bf.q.reachability.return_value.answer.return_value = mock_reachability_result
    
    # traceroute 쿼리 결과
    mock_traceroute_result = MagicMock()
    mock_traceroute_result.frame.return_value = MagicMock()
    mock.bf.q.traceroute.return_value.answer.return_value = mock_traceroute_result
    
    return mock


@pytest.fixture
def mock_pnetlab_client(sample_topology):
    """PNETLab 클라이언트 모킹"""
    mock = MagicMock()
    
    mock.is_authenticated = True
    mock.base_url = "http://100.66.240.82"
    
    mock.login.return_value = True
    mock.get_session_topology.return_value = sample_topology
    mock.get_nodes_from_topology.return_value = [
        {"name": "PE1", "type": "qemu", "template": "vios"},
        {"name": "PE2", "type": "qemu", "template": "vios"},
        {"name": "CE1", "type": "qemu", "template": "vios"},
    ]
    
    return mock


# =============================================================================
# MCP Server Fixtures
# =============================================================================

@pytest.fixture
def nso_server_config() -> Dict[str, Any]:
    """NSO MCP 서버 설정"""
    return {
        "base_url": "http://localhost:8080/restconf/data",
        "username": "admin",
        "password": "admin",
        "timeout": 30,
        "docker_container": "cisco-nso-dev"
    }


@pytest.fixture
def batfish_server_config() -> Dict[str, Any]:
    """Batfish MCP 서버 설정"""
    return {
        "host": "localhost",
        "network_name": "netconfig_qa",
        "snapshot_path": "/path/to/snapshot"
    }


@pytest.fixture
def pnetlab_server_config() -> Dict[str, Any]:
    """PNETLab MCP 서버 설정"""
    return {
        "base_url": "http://100.66.240.82",
        "username": "admin",
        "password": "admin",
        "jwt_token": "test_token"
    }


# =============================================================================
# Async Fixtures
# =============================================================================

@pytest.fixture
def async_mock_nso_client(mock_nso_client):
    """비동기 NSO 클라이언트 모킹"""
    async_mock = AsyncMock()
    
    # 동기 메서드를 비동기로 래핑
    async_mock.get_devices = AsyncMock(return_value=mock_nso_client.get_devices())
    async_mock.get_device_info = AsyncMock(return_value=mock_nso_client.get_device_info())
    async_mock.get_interfaces = AsyncMock(return_value=mock_nso_client.get_interfaces())
    
    return async_mock


# =============================================================================
# Utility Functions
# =============================================================================

def create_mcp_request(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """MCP 요청 메시지 생성 헬퍼"""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": params
        }
    }


def create_mcp_response(result: Any, request_id: int = 1) -> Dict[str, Any]:
    """MCP 응답 메시지 생성 헬퍼"""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {"type": "text", "text": str(result)}
            ]
        }
    }
