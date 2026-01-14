"""
ToolConfig Unit Tests

ToolConfig 및 Ablation Presets 테스트
"""

import pytest
import sys
from pathlib import Path

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.tool_config import (
    ToolConfig,
    RunMode,
    ABLATION_PRESETS,
    get_preset,
    list_presets,
    ToolProvider,
)


class TestToolConfig:
    """ToolConfig 기본 테스트"""
    
    def test_default_config(self):
        """기본 설정 테스트"""
        config = ToolConfig()
        
        assert config.run_mode == RunMode.DEV
        assert config.enable_nso is True
        assert config.enable_batfish is True
        assert config.enable_cache is True
        assert config.cache_ttl == 300
    
    def test_custom_config(self):
        """커스텀 설정 테스트"""
        config = ToolConfig(
            run_mode=RunMode.ADMIN,
            enable_cache=False,
            max_tool_calls=50
        )
        
        assert config.run_mode == RunMode.ADMIN
        assert config.enable_cache is False
        assert config.max_tool_calls == 50
    
    def test_eval_mode_disables_lab(self):
        """eval 모드에서 lab 비활성화"""
        config = ToolConfig(run_mode=RunMode.EVAL)
        
        assert config.enable_lab_manage is False
        assert config.enable_pnetlab is False


class TestToolConfigExperimentName:
    """to_experiment_name 테스트"""
    
    def test_full_config_name(self):
        """전체 기능 활성화 시 이름"""
        config = ToolConfig()
        
        name = config.to_experiment_name()
        
        assert name == "full"
    
    def test_no_cache_name(self):
        """캐시 비활성화 시 이름"""
        config = ToolConfig(enable_cache=False)
        
        name = config.to_experiment_name()
        
        assert "no_cache" in name
    
    def test_no_batfish_name(self):
        """Batfish 비활성화 시 이름"""
        config = ToolConfig(enable_batfish=False)
        
        name = config.to_experiment_name()
        
        assert "no_batfish" in name
    
    def test_multiple_disabled(self):
        """여러 기능 비활성화 시 이름"""
        config = ToolConfig(
            enable_cache=False,
            enable_batfish=False,
            enable_telemetry=False
        )
        
        name = config.to_experiment_name()
        
        assert "no_cache" in name
        assert "no_batfish" in name
        assert "no_telemetry" in name


class TestToolConfigEnabledTools:
    """get_enabled_tools 테스트"""
    
    def test_all_tools_enabled(self):
        """모든 도구 활성화"""
        config = ToolConfig()
        
        tools = config.get_enabled_tools()
        
        assert "network_query" in tools
        assert "network_verify" in tools
        assert "help_guide" in tools
        assert len(tools) == 7
    
    def test_some_tools_disabled(self):
        """일부 도구 비활성화"""
        config = ToolConfig(
            enable_network_verify=False,
            enable_telemetry_query=False
        )
        
        tools = config.get_enabled_tools()
        
        assert "network_query" in tools
        assert "network_verify" not in tools
        assert "telemetry_query" not in tools
        assert "help_guide" in tools  # 항상 포함
    
    def test_help_guide_always_included(self):
        """help_guide는 항상 포함"""
        config = ToolConfig(
            enable_network_query=False,
            enable_network_verify=False,
            enable_network_change=False,
            enable_telemetry_query=False,
            enable_lab_manage=False,
            enable_approval=False
        )
        
        tools = config.get_enabled_tools()
        
        assert "help_guide" in tools
        assert len(tools) == 1


class TestToolConfigSerialization:
    """직렬화 테스트"""
    
    def test_to_dict(self):
        """딕셔너리 변환"""
        config = ToolConfig(
            run_mode=RunMode.ADMIN,
            enable_cache=False
        )
        
        data = config.to_dict()
        
        assert data["run_mode"] == "admin"
        assert data["cache"]["enabled"] is False
        assert "servers" in data
        assert "tools" in data
    
    def test_from_dict(self):
        """딕셔너리에서 생성"""
        data = {
            "run_mode": "eval",
            "servers": {"nso": True, "batfish": False},
            "cache": {"enabled": False, "ttl": 600}
        }
        
        config = ToolConfig.from_dict(data)
        
        assert config.run_mode == RunMode.EVAL
        assert config.enable_batfish is False
        assert config.enable_cache is False
        assert config.cache_ttl == 600
    
    def test_roundtrip(self):
        """직렬화 왕복 테스트"""
        original = ToolConfig(
            run_mode=RunMode.ADMIN,
            enable_cache=False,
            max_tool_calls=50
        )
        
        data = original.to_dict()
        restored = ToolConfig.from_dict(data)
        
        assert restored.run_mode == original.run_mode
        assert restored.enable_cache == original.enable_cache
        assert restored.max_tool_calls == original.max_tool_calls


class TestAblationPresets:
    """ABLATION_PRESETS 테스트"""
    
    def test_full_preset(self):
        """full 프리셋"""
        config = get_preset("full")
        
        assert config.enable_nso is True
        assert config.enable_batfish is True
        assert config.enable_cache is True
    
    def test_no_cache_preset(self):
        """no_cache 프리셋"""
        config = get_preset("no_cache")
        
        assert config.enable_cache is False
    
    def test_no_batfish_preset(self):
        """no_batfish 프리셋"""
        config = get_preset("no_batfish")
        
        assert config.enable_batfish is False
        assert config.enable_network_verify is False
    
    def test_minimal_preset(self):
        """minimal 프리셋"""
        config = get_preset("minimal")
        
        assert config.enable_batfish is False
        assert config.enable_telemetry is False
        assert config.enable_cache is False
    
    def test_eval_mode_preset(self):
        """eval_mode 프리셋"""
        config = get_preset("eval_mode")
        
        assert config.run_mode == RunMode.EVAL
        assert config.enable_lab_manage is False
    
    def test_unknown_preset_raises(self):
        """알 수 없는 프리셋"""
        with pytest.raises(KeyError):
            get_preset("unknown_preset")
    
    def test_list_presets(self):
        """프리셋 목록"""
        presets = list_presets()
        
        assert "full" in presets
        assert "no_cache" in presets
        assert "no_batfish" in presets
        assert len(presets) >= 10


class TestToolProvider:
    """ToolProvider 테스트"""
    
    def test_provider_full_config(self):
        """전체 설정 시 도구 제공"""
        config = ToolConfig()
        provider = ToolProvider(config)
        
        tools = provider.get_langchain_tools()
        
        assert len(tools) == 7
    
    def test_provider_limited_config(self):
        """제한된 설정 시 도구 제공"""
        config = ToolConfig(
            enable_network_verify=False,
            enable_telemetry_query=False,
            enable_lab_manage=False
        )
        provider = ToolProvider(config)
        
        tools = provider.get_langchain_tools()
        
        # network_query, network_change, approval_request, help_guide
        assert len(tools) == 4
    
    def test_provider_tool_count(self):
        """도구 수 확인"""
        config = ToolConfig()
        provider = ToolProvider(config)
        
        count = provider.get_tool_count()
        
        assert count == 7
    
    def test_provider_tool_names(self):
        """도구 이름 목록"""
        config = ToolConfig()
        provider = ToolProvider(config)
        
        names = provider.get_tool_names()
        
        assert "network_query" in names
        assert "help_guide" in names


class TestRunMode:
    """RunMode Enum 테스트"""
    
    def test_mode_values(self):
        """모드 값"""
        assert RunMode.ADMIN.value == "admin"
        assert RunMode.DEV.value == "dev"
        assert RunMode.EVAL.value == "eval"
    
    def test_mode_from_string(self):
        """문자열에서 모드 생성"""
        assert RunMode("admin") == RunMode.ADMIN
        assert RunMode("dev") == RunMode.DEV
        assert RunMode("eval") == RunMode.EVAL
