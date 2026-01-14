"""
NSO MCP Server Unit Tests

NSO MCP 서버의 각 도구 기능을 테스트합니다.
"""

import pytest
import sys
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, AsyncMock
import tempfile
import os

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_servers.nso_server import NSOServer, ConfigExportResult


class TestNSOServerInit:
    """NSOServer 초기화 테스트"""
    
    def test_server_init_with_defaults(self):
        """기본값으로 서버 초기화"""
        with patch('mcp_servers.nso_server.settings') as mock_settings:
            mock_settings.nso.base_url = "http://localhost:8080/restconf/data"
            mock_settings.nso.username = "admin"
            mock_settings.nso.password = "admin"
            
            server = NSOServer()
            
            assert server.base_url == "http://localhost:8080/restconf/data"
            assert server.username == "admin"
            assert server.docker_container == "cisco-nso-dev"
    
    def test_server_init_with_custom_values(self):
        """커스텀 값으로 서버 초기화"""
        server = NSOServer(
            base_url="http://custom:8080/restconf/data",
            username="custom_user",
            password="custom_pass",
            docker_container="custom-nso",
            timeout=60
        )
        
        assert server.base_url == "http://custom:8080/restconf/data"
        assert server.username == "custom_user"
        assert server.docker_container == "custom-nso"
        assert server.timeout == 60


class TestNSOServerGetDevices:
    """get_devices 도구 테스트"""
    
    def test_get_devices_returns_list(self, mock_nso_client, sample_devices):
        """장비 목록 반환 테스트"""
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        devices = server.get_devices()
        
        assert devices == sample_devices
        mock_nso_client.get_devices.assert_called_once()
    
    def test_get_devices_empty(self, mock_nso_client):
        """빈 장비 목록 테스트"""
        mock_nso_client.get_devices.return_value = []
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        devices = server.get_devices()
        
        assert devices == []


class TestNSOServerGetConfig:
    """get_config 도구 테스트"""
    
    def test_get_config_full(self, mock_nso_client):
        """전체 설정 조회 테스트"""
        mock_nso_client._fetch_config.return_value = {
            "interface": {"GigabitEthernet0/0": {}},
            "router": {"bgp": {"as-number": 65001}}
        }
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        config = server.get_config("PE1")
        
        assert "interface" in config
        mock_nso_client._fetch_config.assert_called_once_with("PE1", "")
    
    def test_get_config_with_path(self, mock_nso_client):
        """특정 경로 설정 조회 테스트"""
        mock_nso_client._fetch_config.return_value = {
            "bgp": {"as-number": 65001}
        }
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        config = server.get_config("PE1", "router/bgp")
        
        mock_nso_client._fetch_config.assert_called_once_with("PE1", "router/bgp")


class TestNSOServerRunCommand:
    """run_command 도구 테스트"""
    
    def test_run_command_success(self, mock_nso_client, sample_running_config):
        """CLI 명령 실행 성공 테스트"""
        mock_nso_client._run_command.return_value = sample_running_config
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        result = server.run_command("PE1", "show running-config")
        
        assert "hostname PE1" in result
        mock_nso_client._run_command.assert_called_once_with("PE1", "show running-config")


class TestNSOServerExportConfigs:
    """export_batfish_configs 도구 테스트"""
    
    def test_export_configs_creates_directories(self, mock_nso_client):
        """디렉토리 생성 테스트"""
        mock_nso_client.get_devices.return_value = ["PE1"]
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        # Docker 명령 모킹
        with patch.object(server, '_run_nso_docker_cmd') as mock_docker:
            mock_docker.return_value = "!\nversion 15.7\nhostname PE1\nend"
            
            with tempfile.TemporaryDirectory() as tmpdir:
                result = server.export_batfish_configs(
                    devices=["PE1"],
                    output_dir=tmpdir,
                    export_xml=False
                )
                
                configs_dir = Path(tmpdir) / "configs"
                assert configs_dir.exists()
                assert result["status"] == "completed"
    
    def test_export_configs_saves_cfg_file(self, mock_nso_client):
        """CFG 파일 저장 테스트"""
        mock_nso_client.get_devices.return_value = ["PE1"]
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        with patch.object(server, '_run_nso_docker_cmd') as mock_docker:
            mock_docker.return_value = "!\nversion 15.7\nhostname PE1\n!\ninterface GigabitEthernet0/0\nend"
            
            with tempfile.TemporaryDirectory() as tmpdir:
                result = server.export_batfish_configs(
                    devices=["PE1"],
                    output_dir=tmpdir,
                    export_xml=False
                )
                
                cfg_path = Path(tmpdir) / "configs" / "PE1.cfg"
                assert cfg_path.exists()
                
                content = cfg_path.read_text()
                assert "hostname PE1" in content
                assert result["results"][0]["success"] is True
    
    def test_export_configs_with_xml(self, mock_nso_client):
        """XML 추출 포함 테스트"""
        mock_nso_client.get_devices.return_value = ["PE1"]
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        with patch.object(server, '_run_nso_docker_cmd') as mock_docker:
            # CFG와 XML 응답을 순서대로 반환
            mock_docker.side_effect = [
                "!\nversion 15.7\nhostname PE1\nend",
                "<config><device><name>PE1</name></device></config>"
            ]
            
            with tempfile.TemporaryDirectory() as tmpdir:
                result = server.export_batfish_configs(
                    devices=["PE1"],
                    output_dir=tmpdir,
                    export_xml=True
                )
                
                cfg_path = Path(tmpdir) / "configs" / "PE1.cfg"
                xml_path = Path(tmpdir) / "xml" / "PE1.xml"
                
                assert cfg_path.exists()
                assert xml_path.exists()
                assert result["results"][0]["xml_path"] is not None
    
    def test_export_configs_all_devices(self, mock_nso_client):
        """전체 장비 추출 테스트"""
        mock_nso_client.get_devices.return_value = ["PE1", "PE2", "CE1"]
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        with patch.object(server, '_run_nso_docker_cmd') as mock_docker:
            mock_docker.return_value = "!\nversion 15.7\nhostname TEST\nend"
            
            with tempfile.TemporaryDirectory() as tmpdir:
                result = server.export_batfish_configs(
                    devices=None,  # 전체 장비
                    output_dir=tmpdir,
                    export_xml=False
                )
                
                assert result["total"] == 3
                assert result["success"] == 3
    
    def test_export_configs_handles_error(self, mock_nso_client):
        """오류 처리 테스트"""
        mock_nso_client.get_devices.return_value = ["PE1"]
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        with patch.object(server, '_run_nso_docker_cmd') as mock_docker:
            mock_docker.return_value = "Error: syntax error"
            
            with tempfile.TemporaryDirectory() as tmpdir:
                result = server.export_batfish_configs(
                    devices=["PE1"],
                    output_dir=tmpdir,
                    export_xml=False
                )
                
                assert result["results"][0]["success"] is False
                assert result["results"][0]["error"] is not None


class TestNSOServerCleanConfig:
    """_clean_config 메서드 테스트"""
    
    def test_clean_config_removes_nso_prompts(self):
        """NSO 프롬프트 제거 테스트"""
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        
        raw_config = """admin@ncs# devices device PE1 live-status exec show running-config
result
Building configuration...

!
version 15.7
hostname PE1
!
end
admin@ncs#"""
        
        cleaned = server._clean_config(raw_config)
        
        assert "admin@ncs#" not in cleaned
        assert "Building configuration" not in cleaned
        assert "hostname PE1" in cleaned
    
    def test_clean_config_removes_banner(self):
        """Banner 제거 테스트"""
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        
        raw_config = """!
version 15.7
hostname PE1
banner motd ^C
This is a banner
with multiple lines
^C
!
end"""
        
        cleaned = server._clean_config(raw_config)
        
        assert "This is a banner" not in cleaned
        assert "hostname PE1" in cleaned


class TestNSOServerCleanXML:
    """_clean_xml_output 메서드 테스트"""
    
    def test_clean_xml_removes_prompts(self):
        """XML에서 프롬프트 제거 테스트"""
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        
        raw_xml = """admin@ncs# show running-config devices device PE1 | display xml
<config xmlns="http://tail-f.com/ns/config/1.0">
  <devices xmlns="http://tail-f.com/ns/ncs">
    <device>
      <name>PE1</name>
    </device>
  </devices>
</config>
admin@ncs#"""
        
        cleaned = server._clean_xml_output(raw_xml)
        
        assert "admin@ncs#" not in cleaned
        assert "<config" in cleaned
        assert "<name>PE1</name>" in cleaned


class TestNSOServerMCPToolCall:
    """MCP 도구 호출 테스트"""
    
    @pytest.mark.asyncio
    async def test_handle_get_devices_tool(self, mock_nso_client, sample_devices):
        """get_devices 도구 호출 테스트"""
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        result = await server._handle_tool_call("nso.get_devices", {})
        
        assert "devices" in result
        assert result["devices"] == sample_devices
    
    @pytest.mark.asyncio
    async def test_handle_get_config_tool(self, mock_nso_client):
        """get_config 도구 호출 테스트"""
        mock_nso_client._fetch_config.return_value = {"router": {"bgp": {}}}
        
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        server._client = mock_nso_client
        
        result = await server._handle_tool_call("nso.get_config", {
            "device": "PE1",
            "config_path": "router/bgp"
        })
        
        assert "router" in result
    
    @pytest.mark.asyncio
    async def test_handle_unknown_tool(self):
        """알 수 없는 도구 호출 테스트"""
        server = NSOServer(
            base_url="http://test:8080",
            username="test",
            password="test"
        )
        
        result = await server._handle_tool_call("nso.unknown", {})
        
        assert "error" in result
        assert "Unknown tool" in result["error"]


class TestConfigExportResult:
    """ConfigExportResult 데이터클래스 테스트"""
    
    def test_default_values(self):
        """기본값 테스트"""
        result = ConfigExportResult(device="PE1", success=False)
        
        assert result.device == "PE1"
        assert result.success is False
        assert result.cfg_path is None
        assert result.xml_path is None
        assert result.cfg_size == 0
        assert result.xml_size == 0
        assert result.error is None
    
    def test_success_result(self):
        """성공 결과 테스트"""
        result = ConfigExportResult(
            device="PE1",
            success=True,
            cfg_path="/path/to/PE1.cfg",
            cfg_size=1024
        )
        
        assert result.success is True
        assert result.cfg_path == "/path/to/PE1.cfg"
        assert result.cfg_size == 1024
