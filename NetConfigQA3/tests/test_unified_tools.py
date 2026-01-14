"""
Unified Tools Unit Tests

통합 도구 7개의 기능을 테스트합니다.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.unified_tools import (
    network_query,
    network_verify,
    network_change,
    telemetry_query,
    lab_manage,
    approval_request,
    help_guide,
    get_unified_tools,
    get_tool_count,
    approve_request,
    _pending_approvals,
)


class TestNetworkQuery:
    """network_query 도구 테스트"""
    
    def test_query_device_list(self, mock_nso_client):
        """장비 목록 조회"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_server.get_devices.return_value = ["PE1", "PE2", "P1"]
            mock_get.return_value = mock_server
            
            result = network_query.invoke({"category": "device"})
            
            assert "devices" in result
            assert result["count"] == 3
    
    def test_query_single_device(self, mock_nso_client):
        """단일 장비 정보 조회"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_server.get_device_info.return_value = {"name": "PE1", "address": "10.0.0.1"}
            mock_get.return_value = mock_server
            
            result = network_query.invoke({"category": "device", "device": "PE1"})
            
            assert result["name"] == "PE1"
    
    def test_query_interfaces(self, mock_nso_client, sample_interfaces):
        """인터페이스 조회"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_server.get_interfaces.return_value = sample_interfaces
            mock_get.return_value = mock_server
            
            result = network_query.invoke({"category": "interface", "device": "PE1"})
            
            assert result["device"] == "PE1"
            assert "interfaces" in result
    
    def test_query_interface_requires_device(self):
        """인터페이스 조회 시 device 필수"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_get.return_value = mock_server
            
            result = network_query.invoke({"category": "interface"})
            
            assert "error" in result
            assert "device parameter required" in result["error"]
    
    def test_query_routing_bgp(self):
        """BGP 라우팅 조회"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_server.client.get_bgp_neighbors.return_value = [{"neighbor": "10.1.1.2"}]
            mock_server.client.get_bgp_as_number.return_value = 65001
            mock_get.return_value = mock_server
            
            result = network_query.invoke({
                "category": "routing",
                "device": "PE1",
                "params": {"protocol": "bgp"}
            })
            
            assert result["protocol"] == "bgp"
            assert result["as_number"] == 65001
    
    def test_query_unknown_category(self):
        """알 수 없는 카테고리 - LangChain이 Literal 타입 검증"""
        # LangChain @tool 데코레이터가 Literal 타입을 검증하여
        # 허용되지 않는 카테고리는 ValidationError 발생
        with pytest.raises(Exception):  # pydantic ValidationError
            network_query.invoke({"category": "unknown"})


class TestNetworkVerify:
    """network_verify 도구 테스트"""
    
    def test_verify_not_initialized(self):
        """Batfish 미초기화 상태"""
        with patch('agent.unified_tools.get_batfish_server') as mock_get:
            mock_server = MagicMock()
            mock_server._initialized = False
            mock_get.return_value = mock_server
            
            result = network_verify.invoke({
                "test_type": "reachability",
                "params": {"src": "PE1", "dst": "10.1.1.1"}
            })
            
            assert "error" in result
            assert "not initialized" in result["error"].lower()
    
    def test_verify_reachability(self):
        """도달성 검증"""
        with patch('agent.unified_tools.get_batfish_server') as mock_get:
            mock_server = MagicMock()
            mock_server._initialized = True
            mock_server.check_reachability.return_value = {
                "reachable": True,
                "src": "PE1",
                "dst": "10.2.2.2"
            }
            mock_get.return_value = mock_server
            
            result = network_verify.invoke({
                "test_type": "reachability",
                "params": {"src": "PE1", "dst": "10.2.2.2"}
            })
            
            assert result["reachable"] is True
    
    def test_verify_traceroute(self):
        """경로 추적"""
        with patch('agent.unified_tools.get_batfish_server') as mock_get:
            mock_server = MagicMock()
            mock_server._initialized = True
            mock_server.traceroute.return_value = {
                "path": ["PE1", "P1", "PE2"],
                "hops": 3
            }
            mock_get.return_value = mock_server
            
            result = network_verify.invoke({
                "test_type": "traceroute",
                "params": {"src": "PE1", "dst": "10.2.2.2"}
            })
            
            assert result["hops"] == 3


class TestNetworkChange:
    """network_change 도구 테스트"""
    
    def test_change_dry_run(self):
        """Dry-run 테스트"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_get.return_value = mock_server
            
            result = network_change.invoke({
                "action": "dry_run",
                "device": "PE1",
                "config_path": "acl/100",
                "config_value": {"permit": "10.1.1.0/24"}
            })
            
            assert result["status"] == "simulated"
            assert result["action"] == "dry_run"
    
    def test_change_commit_requires_approval(self):
        """Commit은 승인 필요"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_get.return_value = mock_server
            
            result = network_change.invoke({
                "action": "commit",
                "device": "PE1",
                "config_path": "acl/100"
            })
            
            assert result["status"] == "requires_approval"
    
    def test_change_diff(self):
        """Diff 테스트"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_server.get_config.return_value = {"current": "value"}
            mock_get.return_value = mock_server
            
            result = network_change.invoke({
                "action": "diff",
                "device": "PE1",
                "config_path": "acl/100"
            })
            
            assert result["status"] == "success"
            assert "current_config" in result


class TestTelemetryQuery:
    """telemetry_query 도구 테스트"""
    
    def test_query_logs(self):
        """로그 조회"""
        with patch('agent.unified_tools.get_telemetry_server') as mock_get:
            mock_server = MagicMock()
            mock_server.query_logs.return_value = {
                "status": "stub",
                "logs": [{"message": "test"}],
                "count": 1
            }
            mock_get.return_value = mock_server
            
            result = telemetry_query.invoke({
                "source": "logs",
                "filters": {"device": "PE1"}
            })
            
            assert "logs" in result
    
    def test_query_metrics(self):
        """메트릭 조회"""
        with patch('agent.unified_tools.get_telemetry_server') as mock_get:
            mock_server = MagicMock()
            mock_server.query_metrics.return_value = {
                "status": "stub",
                "metrics": [],
                "count": 0
            }
            mock_get.return_value = mock_server
            
            result = telemetry_query.invoke({
                "source": "metrics",
                "filters": {"device": "PE1"}
            })
            
            assert "metrics" in result


class TestLabManage:
    """lab_manage 도구 테스트"""
    
    def test_show_inventory(self):
        """인벤토리 조회"""
        with patch('agent.unified_tools.get_pnetlab_server') as mock_get:
            mock_server = MagicMock()
            mock_server.show_inventory.return_value = {
                "status": "success",
                "nodes": [{"name": "PE1"}],
                "total_nodes": 1
            }
            mock_get.return_value = mock_server
            
            result = lab_manage.invoke({"action": "show_inventory"})
            
            assert result["status"] == "success"
            assert "nodes" in result
    
    def test_export_configs(self):
        """cfg 추출"""
        with patch('agent.unified_tools.get_nso_server') as mock_get:
            mock_server = MagicMock()
            mock_server.export_batfish_configs.return_value = {
                "status": "completed",
                "success": 3,
                "failed": 0
            }
            mock_get.return_value = mock_server
            
            result = lab_manage.invoke({
                "action": "export_configs",
                "params": {"output_dir": "./snapshot"}
            })
            
            assert result["status"] == "completed"
    
    def test_init_batfish(self):
        """Batfish 초기화"""
        with patch('agent.unified_tools.get_batfish_server') as mock_get:
            mock_server = MagicMock()
            mock_server.init_snapshot.return_value = {
                "status": "initialized",
                "nodes": ["PE1", "PE2"]
            }
            mock_get.return_value = mock_server
            
            result = lab_manage.invoke({
                "action": "init_batfish",
                "params": {"snapshot_path": "./snapshot"}
            })
            
            assert result["status"] == "initialized"
    
    def test_init_batfish_requires_path(self):
        """snapshot_path 필수"""
        with patch('agent.unified_tools.get_batfish_server') as mock_get:
            mock_server = MagicMock()
            mock_get.return_value = mock_server
            
            result = lab_manage.invoke({
                "action": "init_batfish",
                "params": {}
            })
            
            assert "error" in result
            assert "snapshot_path" in result["error"]


class TestApprovalRequest:
    """approval_request 도구 테스트"""
    
    def test_create_approval_request(self):
        """승인 요청 생성"""
        result = approval_request.invoke({
            "action_type": "commit",
            "description": "ACL 규칙 추가",
            "affected_devices": ["PE1"],
            "risk_assessment": "low"
        })
        
        assert result["status"] == "pending"
        assert "request_id" in result
        assert result["request_id"].startswith("REQ-")
    
    def test_approve_request(self):
        """승인 요청 승인"""
        # 먼저 요청 생성
        create_result = approval_request.invoke({
            "action_type": "commit",
            "description": "테스트 변경",
            "affected_devices": ["PE1"],
            "risk_assessment": "low"
        })
        
        request_id = create_result["request_id"]
        
        # 승인
        approve_result = approve_request(request_id, True, "Approved by admin")
        
        assert approve_result["status"] == "approved"
        assert approve_result["reason"] == "Approved by admin"
    
    def test_reject_request(self):
        """승인 요청 거부"""
        create_result = approval_request.invoke({
            "action_type": "commit",
            "description": "위험한 변경",
            "affected_devices": ["PE1", "PE2"],
            "risk_assessment": "high"
        })
        
        request_id = create_result["request_id"]
        
        reject_result = approve_request(request_id, False, "Too risky")
        
        assert reject_result["status"] == "rejected"
        assert reject_result["reason"] == "Too risky"


class TestHelpGuide:
    """help_guide 도구 테스트"""
    
    def test_help_tools(self):
        """도구 목록 도움말"""
        result = help_guide.invoke({"topic": "tools"})
        
        assert "network_query" in result
        assert "network_verify" in result
    
    def test_help_examples(self):
        """예시 도움말"""
        result = help_guide.invoke({"topic": "examples"})
        
        assert "network_query" in result
        assert "장비 목록" in result or "device" in result
    
    def test_help_troubleshooting(self):
        """문제 해결 도움말"""
        result = help_guide.invoke({"topic": "troubleshooting"})
        
        assert "Batfish" in result
    
    def test_help_best_practices(self):
        """권장 사항 도움말"""
        result = help_guide.invoke({"topic": "best_practices"})
        
        assert "검증" in result or "dry_run" in result


class TestToolExports:
    """도구 내보내기 테스트"""
    
    def test_get_unified_tools(self):
        """통합 도구 목록"""
        tools = get_unified_tools()
        
        assert len(tools) == 7
    
    def test_get_tool_count(self):
        """도구 수"""
        count = get_tool_count()
        
        assert count == 7
