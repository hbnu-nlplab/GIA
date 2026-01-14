from pathlib import Path
"""
PNETLab MCP Server Unit Tests

PNETLab MCP 서버의 각 도구 기능을 테스트합니다.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_servers.pnetlab_server import PnetlabServer


class TestPnetlabServerInit:
    """PnetlabServer 초기화 테스트"""
    
    def test_server_init_with_defaults(self):
        """기본값으로 서버 초기화"""
        with patch('mcp_servers.pnetlab_server.settings') as mock_settings:
            mock_settings.pnetlab.base_url = "http://100.66.240.82"
            mock_settings.pnetlab.username = "admin"
            mock_settings.pnetlab.password = "admin"
            mock_settings.pnetlab.jwt_token = ""
            
            server = PnetlabServer()
            
            assert server.base_url == "http://100.66.240.82"
            assert server.username == "admin"
    
    def test_server_init_with_custom_values(self):
        """커스텀 값으로 서버 초기화"""
        server = PnetlabServer(
            base_url="http://custom.pnetlab",
            username="custom_user",
            password="custom_pass",
            jwt_token="custom_token"
        )
        
        assert server.base_url == "http://custom.pnetlab"
        assert server.username == "custom_user"
        assert server.jwt_token == "custom_token"


class TestPnetlabServerShowInventory:
    """show_inventory 도구 테스트"""
    
    def test_show_inventory_success(self, mock_pnetlab_client, sample_topology):
        """인벤토리 조회 성공 테스트"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.show_inventory()
        
        assert result["status"] == "success"
        assert result["total_nodes"] == 3
        assert len(result["nodes"]) == 3
    
    def test_show_inventory_login_failure(self, mock_pnetlab_client):
        """로그인 실패 테스트"""
        mock_pnetlab_client.is_authenticated = False
        mock_pnetlab_client.login.return_value = False
        
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.show_inventory()
        
        assert "error" in result
        assert "로그인 실패" in result["error"]
    
    def test_show_inventory_topology_error(self, mock_pnetlab_client):
        """토폴로지 조회 오류 테스트"""
        mock_pnetlab_client.get_session_topology.return_value = {"error": "No lab open"}
        
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.show_inventory()
        
        assert "error" in result


class TestPnetlabServerGetStatus:
    """get_status 도구 테스트"""
    
    def test_get_status_all_devices(self, mock_pnetlab_client):
        """전체 장비 상태 조회"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.get_status()
        
        assert result["status"] == "success"
        assert result["device_filter"] is None
        assert result["count"] == 3
    
    def test_get_status_single_device(self, mock_pnetlab_client):
        """단일 장비 상태 조회"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.get_status(device="PE1")
        
        assert result["status"] == "success"
        assert result["device_filter"] == "PE1"
        assert result["count"] == 1
    
    def test_get_status_device_not_found(self, mock_pnetlab_client):
        """존재하지 않는 장비 조회"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.get_status(device="NONEXISTENT")
        
        assert result["count"] == 0


class TestPnetlabServerGetConsoleLink:
    """get_console_link 도구 테스트"""
    
    def test_get_console_link_success(self, mock_pnetlab_client):
        """콘솔 링크 조회 성공"""
        # 콘솔 정보가 있는 노드 설정
        mock_pnetlab_client.get_nodes_from_topology.return_value = [
            {"name": "PE1", "type": "qemu", "template": "vios", "console": "5001"},
            {"name": "PE2", "type": "qemu", "template": "vios", "console": "5002"},
        ]
        
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.get_console_link("PE1")
        
        assert result["status"] == "success"
        assert result["device"] == "PE1"
        assert "console_link" in result
        assert "5001" in result["console_link"]
    
    def test_get_console_link_no_console(self, mock_pnetlab_client):
        """콘솔 없는 장비"""
        mock_pnetlab_client.get_nodes_from_topology.return_value = [
            {"name": "PE1", "type": "qemu", "template": "vios", "console": None},
        ]
        
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.get_console_link("PE1")
        
        assert "error" in result
        assert "No console" in result["error"]
    
    def test_get_console_link_device_not_found(self, mock_pnetlab_client):
        """존재하지 않는 장비"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = server.get_console_link("NONEXISTENT")
        
        assert "error" in result
        assert "not found" in result["error"].lower()


class TestPnetlabServerMCPToolCall:
    """MCP 도구 호출 테스트"""
    
    async def test_handle_show_inventory_tool(self, mock_pnetlab_client):
        """show_inventory 도구 호출"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = await server._handle_tool_call("pnetlab.show_inventory", {})
        
        assert result["status"] == "success"
        assert "nodes" in result
    
    async def test_handle_get_status_tool(self, mock_pnetlab_client):
        """get_status 도구 호출"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = await server._handle_tool_call("pnetlab.get_status", {
            "device": "PE1"
        })
        
        assert result["status"] == "success"
        assert result["device_filter"] == "PE1"
    
    async def test_handle_get_console_link_tool(self, mock_pnetlab_client):
        """get_console_link 도구 호출"""
        mock_pnetlab_client.get_nodes_from_topology.return_value = [
            {"name": "PE1", "type": "qemu", "template": "vios", "console": "5001"},
        ]
        
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        server._client = mock_pnetlab_client
        
        result = await server._handle_tool_call("pnetlab.get_console_link", {
            "device": "PE1"
        })
        
        assert result["status"] == "success"
        assert "console_link" in result
    
    async def test_handle_unknown_tool(self):
        """알 수 없는 도구 호출"""
        server = PnetlabServer(
            base_url="http://test.pnetlab",
            username="test",
            password="test"
        )
        
        result = await server._handle_tool_call("pnetlab.unknown", {})
        
        assert "error" in result
        assert "Unknown tool" in result["error"]
