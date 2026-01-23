from pathlib import Path
"""
Batfish MCP Server Unit Tests

Batfish MCP 서버의 각 도구 기능을 테스트합니다.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
import tempfile

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_servers.batfish_server import BatfishServer


class TestBatfishServerInit:
    """BatfishServer 초기화 테스트"""
    
    def test_server_init_with_defaults(self):
        """기본값으로 서버 초기화"""
        server = BatfishServer()
        
        assert server.host == "localhost"
        assert server.network_name == "netconfig_qa"
        assert server.snapshot_path is None
        assert server._initialized is False
    
    def test_server_init_with_custom_values(self):
        """커스텀 값으로 서버 초기화"""
        server = BatfishServer(
            host="batfish.local",
            network_name="custom_network",
            snapshot_path="/path/to/snapshot"
        )
        
        assert server.host == "batfish.local"
        assert server.network_name == "custom_network"
        assert server.snapshot_path == "/path/to/snapshot"


class TestBatfishServerAvailability:
    """Batfish 가용성 테스트"""
    
    def test_is_available_property(self):
        """is_available 속성 테스트"""
        server = BatfishServer()
        # pybatfish가 설치되어 있지 않으면 False
        # 설치되어 있으면 True
        assert isinstance(server.is_available, bool)


class TestBatfishServerInitSnapshot:
    """init_snapshot 도구 테스트"""
    
    def test_init_snapshot_without_batfish(self):
        """Batfish 없이 초기화 시도"""
        with patch('mcp_servers.batfish_server.BATFISH_AVAILABLE', False):
            with patch('mcp_servers.batfish_server.BatfishBuilder', None):
                server = BatfishServer()
                
                result = server.init_snapshot("/path/to/snapshot")
                
                assert "error" in result
                assert "not available" in result["error"].lower()
    
    def test_init_snapshot_with_mock(self, mock_batfish_session):
        """모의 Batfish로 초기화 테스트"""
        with patch('mcp_servers.batfish_server.BATFISH_AVAILABLE', True):
            with patch('mcp_servers.batfish_server.BatfishBuilder') as MockBuilder:
                mock_instance = MagicMock()
                mock_instance.initialize.return_value = True
                mock_instance.nodes = ["PE1", "PE2", "P1"]
                MockBuilder.return_value = mock_instance
                
                server = BatfishServer()
                result = server.init_snapshot("/path/to/snapshot")
                
                assert result["status"] == "initialized"
                assert result["node_count"] == 3
                assert "PE1" in result["nodes"]


class TestBatfishServerReachability:
    """check_reachability 도구 테스트"""
    
    def test_reachability_not_initialized(self):
        """초기화 안 된 상태에서 호출"""
        server = BatfishServer()
        
        result = server.check_reachability(src="PE1", dst="10.1.1.1")
        
        assert "error" in result
        assert "not initialized" in result["error"].lower()
    
    def test_reachability_with_mock(self):
        """모의 데이터로 도달성 검증"""
        server = BatfishServer()
        server._initialized = True
        server._builder = MagicMock()
        
        # 모의 결과 설정
        mock_frame = MagicMock()
        mock_frame.empty = False
        mock_frame.iloc.__getitem__.return_value = {
            "Flow_Disposition": "ACCEPTED",
            "Traces": [[MagicMock(), MagicMock()]]
        }
        
        server._builder.bf.q.reachability.return_value.answer.return_value.frame.return_value = mock_frame
        
        result = server.check_reachability(
            src="PE1",
            dst="10.2.2.2",
            protocol="icmp"
        )
        
        assert result["src"] == "PE1"
        assert result["dst"] == "10.2.2.2"
        # 결과가 에러가 아니면 성공
        assert "error" not in result or result.get("reachable") is not None


class TestBatfishServerTraceroute:
    """traceroute 도구 테스트"""
    
    def test_traceroute_not_initialized(self):
        """초기화 안 된 상태에서 호출"""
        server = BatfishServer()
        
        result = server.traceroute(src="PE1", dst="10.1.1.1")
        
        assert "error" in result
        assert "not initialized" in result["error"].lower()


class TestBatfishServerBGPSession:
    """get_bgp_sessions 도구 테스트"""
    
    def test_bgp_sessions_not_initialized(self):
        """초기화 안 된 상태에서 호출"""
        server = BatfishServer()
        
        result = server.get_bgp_sessions()
        
        assert "error" in result
        assert "not initialized" in result["error"].lower()
    
    def test_bgp_sessions_with_mock(self):
        """모의 데이터로 BGP 세션 조회"""
        server = BatfishServer()
        server._initialized = True
        server._builder = MagicMock()
        
        # 모의 DataFrame 생성
        import pandas as pd
        mock_df = pd.DataFrame([
            {"Node": "PE1", "Remote_Node": "PE2", "Local_AS": 65001, "Remote_AS": 65002, "Established_Status": "ESTABLISHED"},
            {"Node": "PE2", "Remote_Node": "PE1", "Local_AS": 65002, "Remote_AS": 65001, "Established_Status": "ESTABLISHED"},
        ])
        
        server._builder.bf.q.bgpSessionStatus.return_value.answer.return_value.frame.return_value = mock_df
        
        result = server.get_bgp_sessions()
        
        assert "sessions" in result
        assert result["total"] == 2


class TestBatfishServerRouteTable:
    """get_route_table 도구 테스트"""
    
    def test_route_table_not_initialized(self):
        """초기화 안 된 상태에서 호출"""
        server = BatfishServer()
        
        result = server.get_route_table(device="PE1")
        
        assert "error" in result
        assert "not initialized" in result["error"].lower()


class TestBatfishServerGetNodes:
    """get_nodes 메서드 테스트"""
    
    def test_get_nodes_not_initialized(self):
        """초기화 안 된 상태"""
        server = BatfishServer()
        
        nodes = server.get_nodes()
        
        assert nodes == []
    
    def test_get_nodes_with_builder(self):
        """빌더가 있는 경우"""
        server = BatfishServer()
        server._initialized = True
        server._builder = MagicMock()
        server._builder.nodes = ["PE1", "PE2", "CE1"]
        
        nodes = server.get_nodes()
        
        assert nodes == ["PE1", "PE2", "CE1"]


class TestBatfishServerMCPToolCall:
    """MCP 도구 호출 테스트"""
    
    async def test_handle_get_nodes_tool(self):
        """get_nodes 도구 호출"""
        server = BatfishServer()
        server._initialized = True
        server._builder = MagicMock()
        server._builder.nodes = ["PE1", "PE2"]
        
        result = await server._handle_tool_call("batfish.get_nodes", {})
        
        assert "nodes" in result
        assert result["nodes"] == ["PE1", "PE2"]
    
    async def test_handle_unknown_tool(self):
        """알 수 없는 도구 호출"""
        server = BatfishServer()
        
        result = await server._handle_tool_call("batfish.unknown", {})
        
        assert "error" in result
        assert "Unknown tool" in result["error"]
    
    async def test_handle_init_snapshot_tool(self):
        """init_snapshot 도구 호출"""
        server = BatfishServer()
        
        with patch.object(server, 'init_snapshot') as mock_init:
            mock_init.return_value = {"status": "initialized", "nodes": ["PE1"]}
            
            result = await server._handle_tool_call("batfish.init_snapshot", {
                "snapshot_path": "/path/to/snapshot"
            })
            
            mock_init.assert_called_once_with("/path/to/snapshot")
            assert result["status"] == "initialized"
