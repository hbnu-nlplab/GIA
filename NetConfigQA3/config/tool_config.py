"""
Tool Configuration for Ablation Study

도구 설정 및 Ablation Study를 위한 on/off 토글 제공

주요 기능:
- 서버별 on/off: enable_nso, enable_batfish, enable_telemetry, enable_pnetlab
- 도구별 on/off: enable_network_verify, enable_telemetry_query 등
- 모드: admin / dev / eval
- Ablation 프리셋
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Literal
from enum import Enum


class RunMode(Enum):
    """실행 모드"""
    ADMIN = "admin"   # 모든 기능 사용 가능
    DEV = "dev"       # lab.manage 읽기 전용만 허용
    EVAL = "eval"     # lab.manage 완전 비활성화


@dataclass
class ToolConfig:
    """
    도구 설정 - Ablation Study를 위한 on/off 토글
    
    Attributes:
        run_mode: 실행 모드 (admin/dev/eval)
        
        # 서버 활성화
        enable_nso: NSO 서버 활성화
        enable_batfish: Batfish 서버 활성화
        enable_telemetry: Telemetry 서버 활성화
        enable_pnetlab: PNETLab 서버 활성화
        
        # 도구 활성화
        enable_network_query: network_query 도구
        enable_network_verify: network_verify 도구 (Batfish)
        enable_network_change: network_change 도구 (NSO 변경)
        enable_telemetry_query: telemetry_query 도구
        enable_lab_manage: lab_manage 도구
        enable_approval: approval_request 도구
        
        # 캐시 설정
        enable_cache: 쿼리 캐시 활성화
        cache_ttl: 캐시 TTL (초)
        
        # 예산 설정
        max_tool_calls: 최대 도구 호출 수
        max_tokens: 최대 토큰 수
        
        # Skills 설정
        enable_core_skill: Core Policy 스킬
        enable_runbook_skills: Runbook 스킬
        
        # 승인 게이트
        require_approval_for_commit: commit 시 승인 필요
        require_approval_for_rollback: rollback 시 승인 필요
        auto_approve_dry_run: dry_run 자동 승인
        
        # 로깅
        log_tool_calls: 도구 호출 로깅
        log_token_usage: 토큰 사용량 로깅
    """
    
    # 실행 모드
    run_mode: RunMode = RunMode.DEV
    
    # === 서버 활성화 ===
    enable_nso: bool = True
    enable_batfish: bool = True
    enable_telemetry: bool = True
    enable_pnetlab: bool = True
    
    # === 도구 활성화 ===
    enable_network_query: bool = True
    enable_network_verify: bool = True
    enable_network_change: bool = True
    enable_telemetry_query: bool = True
    enable_lab_manage: bool = True
    enable_approval: bool = True
    
    # === 캐시 설정 ===
    enable_cache: bool = True
    cache_ttl: int = 300  # 5분
    
    # === 예산 설정 ===
    max_tool_calls: int = 20
    max_tokens: int = 10000
    
    # === Skills 설정 ===
    enable_core_skill: bool = True
    enable_runbook_skills: bool = True
    
    # === 승인 게이트 ===
    require_approval_for_commit: bool = True
    require_approval_for_rollback: bool = True
    auto_approve_dry_run: bool = True
    
    # === 로깅 ===
    log_tool_calls: bool = True
    log_token_usage: bool = True
    
    def __post_init__(self):
        """모드에 따른 설정 적용"""
        if self.run_mode == RunMode.EVAL:
            # eval 모드: lab.manage 완전 비활성화
            self.enable_lab_manage = False
            self.enable_pnetlab = False
        elif self.run_mode == RunMode.DEV:
            # dev 모드: lab.manage 읽기 전용만 허용
            # (실제 제한은 lab_manage 함수에서 처리)
            pass
    
    def to_experiment_name(self) -> str:
        """
        실험 이름 생성 (Ablation Study용)
        
        Returns:
            실험 설정을 반영한 이름 (예: "no_cache_no_batfish")
        """
        parts = []
        
        if not self.enable_cache:
            parts.append("no_cache")
        if not self.enable_batfish or not self.enable_network_verify:
            parts.append("no_batfish")
        if not self.enable_telemetry or not self.enable_telemetry_query:
            parts.append("no_telemetry")
        if not self.enable_approval:
            parts.append("no_approval")
        if not self.enable_runbook_skills:
            parts.append("no_runbook")
        if self.run_mode == RunMode.EVAL:
            parts.append("eval_mode")
        
        return "_".join(parts) if parts else "full"
    
    def get_enabled_tools(self) -> List[str]:
        """활성화된 도구 목록 반환"""
        tools = []
        
        if self.enable_network_query:
            tools.append("network_query")
        if self.enable_network_verify:
            tools.append("network_verify")
        if self.enable_network_change:
            tools.append("network_change")
        if self.enable_telemetry_query:
            tools.append("telemetry_query")
        if self.enable_lab_manage:
            tools.append("lab_manage")
        if self.enable_approval:
            tools.append("approval_request")
        
        # help_guide는 항상 포함
        tools.append("help_guide")
        
        return tools
    
    def get_enabled_servers(self) -> List[str]:
        """활성화된 서버 목록 반환"""
        servers = []
        
        if self.enable_nso:
            servers.append("nso")
        if self.enable_batfish:
            servers.append("batfish")
        if self.enable_telemetry:
            servers.append("telemetry")
        if self.enable_pnetlab:
            servers.append("pnetlab")
        
        return servers
    
    def to_dict(self) -> Dict[str, Any]:
        """설정을 딕셔너리로 변환"""
        return {
            "run_mode": self.run_mode.value,
            "servers": {
                "nso": self.enable_nso,
                "batfish": self.enable_batfish,
                "telemetry": self.enable_telemetry,
                "pnetlab": self.enable_pnetlab,
            },
            "tools": {
                "network_query": self.enable_network_query,
                "network_verify": self.enable_network_verify,
                "network_change": self.enable_network_change,
                "telemetry_query": self.enable_telemetry_query,
                "lab_manage": self.enable_lab_manage,
                "approval_request": self.enable_approval,
            },
            "cache": {
                "enabled": self.enable_cache,
                "ttl": self.cache_ttl,
            },
            "budget": {
                "max_tool_calls": self.max_tool_calls,
                "max_tokens": self.max_tokens,
            },
            "skills": {
                "core": self.enable_core_skill,
                "runbook": self.enable_runbook_skills,
            },
            "approval_gate": {
                "commit": self.require_approval_for_commit,
                "rollback": self.require_approval_for_rollback,
                "auto_dry_run": self.auto_approve_dry_run,
            },
            "logging": {
                "tool_calls": self.log_tool_calls,
                "token_usage": self.log_token_usage,
            },
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolConfig":
        """딕셔너리에서 설정 생성"""
        servers = data.get("servers", {})
        tools = data.get("tools", {})
        cache = data.get("cache", {})
        budget = data.get("budget", {})
        skills = data.get("skills", {})
        approval_gate = data.get("approval_gate", {})
        logging = data.get("logging", {})
        
        return cls(
            run_mode=RunMode(data.get("run_mode", "dev")),
            enable_nso=servers.get("nso", True),
            enable_batfish=servers.get("batfish", True),
            enable_telemetry=servers.get("telemetry", True),
            enable_pnetlab=servers.get("pnetlab", True),
            enable_network_query=tools.get("network_query", True),
            enable_network_verify=tools.get("network_verify", True),
            enable_network_change=tools.get("network_change", True),
            enable_telemetry_query=tools.get("telemetry_query", True),
            enable_lab_manage=tools.get("lab_manage", True),
            enable_approval=tools.get("approval_request", True),
            enable_cache=cache.get("enabled", True),
            cache_ttl=cache.get("ttl", 300),
            max_tool_calls=budget.get("max_tool_calls", 20),
            max_tokens=budget.get("max_tokens", 10000),
            enable_core_skill=skills.get("core", True),
            enable_runbook_skills=skills.get("runbook", True),
            require_approval_for_commit=approval_gate.get("commit", True),
            require_approval_for_rollback=approval_gate.get("rollback", True),
            auto_approve_dry_run=approval_gate.get("auto_dry_run", True),
            log_tool_calls=logging.get("tool_calls", True),
            log_token_usage=logging.get("token_usage", True),
        )


# =============================================================================
# Ablation Study Presets
# =============================================================================

ABLATION_PRESETS: Dict[str, ToolConfig] = {
    # 모든 기능 활성화
    "full": ToolConfig(),
    
    # 캐시 비활성화
    "no_cache": ToolConfig(enable_cache=False),
    
    # Batfish 비활성화
    "no_batfish": ToolConfig(
        enable_batfish=False,
        enable_network_verify=False
    ),
    
    # Telemetry 비활성화
    "no_telemetry": ToolConfig(
        enable_telemetry=False,
        enable_telemetry_query=False
    ),
    
    # 승인 게이트 비활성화
    "no_approval": ToolConfig(
        enable_approval=False,
        require_approval_for_commit=False,
        require_approval_for_rollback=False
    ),
    
    # Runbook Skills 비활성화
    "no_runbook": ToolConfig(enable_runbook_skills=False),
    
    # 최소 기능 (네트워크 조회만)
    "minimal": ToolConfig(
        enable_batfish=False,
        enable_network_verify=False,
        enable_telemetry=False,
        enable_telemetry_query=False,
        enable_cache=False,
        enable_runbook_skills=False
    ),
    
    # 읽기 전용 (변경 불가)
    "query_only": ToolConfig(
        enable_network_change=False,
        enable_approval=False,
        require_approval_for_commit=False
    ),
    
    # 평가 모드 (Lab 기능 비활성화)
    "eval_mode": ToolConfig(run_mode=RunMode.EVAL),
    
    # 개발 모드
    "dev_mode": ToolConfig(run_mode=RunMode.DEV),
    
    # 관리자 모드
    "admin_mode": ToolConfig(run_mode=RunMode.ADMIN),
}


def get_preset(name: str) -> ToolConfig:
    """
    프리셋 이름으로 ToolConfig 반환
    
    Args:
        name: 프리셋 이름
        
    Returns:
        ToolConfig 인스턴스
        
    Raises:
        KeyError: 프리셋이 없을 경우
    """
    if name not in ABLATION_PRESETS:
        raise KeyError(f"Unknown preset: {name}. Available: {list(ABLATION_PRESETS.keys())}")
    return ABLATION_PRESETS[name]


def list_presets() -> List[str]:
    """사용 가능한 프리셋 목록 반환"""
    return list(ABLATION_PRESETS.keys())


# =============================================================================
# Tool Provider (멀티에이전트 연결용)
# =============================================================================

class ToolProvider:
    """
    도구 제공자 - 멀티에이전트에서 사용
    
    ToolConfig에 따라 활성화된 도구만 제공합니다.
    
    Usage:
        provider = ToolProvider(config)
        tools = provider.get_langchain_tools()  # LangChain 도구로 변환
    """
    
    def __init__(self, config: ToolConfig):
        """
        Args:
            config: ToolConfig 인스턴스
        """
        self.config = config
    
    def get_langchain_tools(self) -> List:
        """
        LangChain Tool 객체 리스트 반환
        
        Returns:
            활성화된 도구 리스트
        """
        from agent.unified_tools import (
            network_query, network_verify, network_change,
            telemetry_query, lab_manage, approval_request, help_guide
        )
        
        tools = []
        
        if self.config.enable_network_query:
            tools.append(network_query)
        if self.config.enable_network_verify:
            tools.append(network_verify)
        if self.config.enable_network_change:
            tools.append(network_change)
        if self.config.enable_telemetry_query:
            tools.append(telemetry_query)
        if self.config.enable_lab_manage:
            tools.append(lab_manage)
        if self.config.enable_approval:
            tools.append(approval_request)
        
        # help_guide는 항상 포함
        tools.append(help_guide)
        
        return tools
    
    def get_tool_count(self) -> int:
        """활성화된 도구 수 반환"""
        return len(self.get_langchain_tools())
    
    def get_tool_names(self) -> List[str]:
        """활성화된 도구 이름 목록"""
        return [tool.name for tool in self.get_langchain_tools()]
