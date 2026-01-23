"""
Skills-Controlled MCP Tools

LangChain Skills 패턴을 적용하여 Skills가 필요한 MCP 도구만 노출합니다.

핵심 아이디어:
- Skill을 로드하면 해당 Skill이 필요로 하는 도구만 활성화
- 불필요한 도구를 MCP 레벨에서 제외하여 토큰 절감
- Dynamic Tool Registration 패턴 사용
"""

import sys
from pathlib import Path

# 프로젝트 루트를 경로에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field

from agent.skill_loader import SkillLoader, Skill
from config.tool_config import ToolConfig


class SkillMCPMapping:
    """
    Skill과 MCP 도구 간의 매핑
    
    각 Skill은 requires_tools에 필요한 도구를 선언합니다.
    이 매핑을 통해 동적으로 MCP 도구를 활성화/비활성화합니다.
    """
    
    # Unified Tools → MCP Tools 매핑 (클래스 변수)
    TOOL_TO_MCP_MAPPING = {
        # network_query → NSO MCP 도구들
        "network_query": [
            "nso_get_devices",
            "nso_get_config",
            "nso_get_device_info"
        ],
        
        # network_verify → Batfish MCP 도구들
        "network_verify": [
            "batfish_init",
            "batfish_verify_reachability",
            "batfish_traceroute",
            "batfish_bgp_sessions"
        ],
        
        # network_change → NSO 변경 도구들
        "network_change": [
            "nso_dry_run",
            "nso_commit",
            "nso_rollback"
        ],
        
        # lab_manage → PNETLab + NSO export 도구들
        "lab_manage": [
            "pnetlab_inventory",
            "pnetlab_get_status",
            "nso_export_configs",
            "batfish_init"
        ],
        
        # telemetry_query → Telemetry MCP 도구들
        "telemetry_query": [
            "telemetry_get_logs",
            "telemetry_get_metrics",
            "telemetry_get_flows"
        ]
    }
    
    @classmethod
    def get_required_mcp_tools(cls, skills: List[Skill]) -> Set[str]:
        """
        Skills에서 필요한 MCP 도구 목록 추출
        
        Args:
            skills: 로드된 Skill 리스트
            
        Returns:
            MCP 도구 이름 Set
        """
        mcp_tools = set()
        
        for skill in skills:
            for unified_tool in skill.requires_tools:
                # Unified Tool → MCP Tools
                if unified_tool in cls.TOOL_TO_MCP_MAPPING:
                    mcp_tools.update(cls.TOOL_TO_MCP_MAPPING[unified_tool])
        
        return mcp_tools
    
    @classmethod
    def get_all_mcp_tools(cls) -> Set[str]:
        """모든 MCP 도구 목록"""
        all_tools = set()
        for tools in cls.TOOL_TO_MCP_MAPPING.values():
            all_tools.update(tools)
        return all_tools


class SkillControlledMCPServer:
    """
    Skills에 의해 제어되는 MCP 서버
    
    Skills가 로드되면 해당 Skills가 필요로 하는 MCP 도구만 노출합니다.
    
    Usage:
        loader = SkillLoader()
        skills = loader.load_skills_for_task("BGP 세션이 Down입니다")
        
        server = SkillControlledMCPServer(skills)
        enabled_tools = server.get_enabled_tools()
        # ['nso_get_config', 'batfish_verify_reachability', ...]
    """
    
    def __init__(self, skills: List[Skill]):
        """
        Args:
            skills: 로드된 Skill 리스트
        """
        self.skills = skills
        self.required_mcp_tools = SkillMCPMapping.get_required_mcp_tools(skills)
        self.all_mcp_tools = SkillMCPMapping.get_all_mcp_tools()
    
    def get_enabled_tools(self) -> List[str]:
        """활성화된 MCP 도구 목록"""
        return sorted(list(self.required_mcp_tools))
    
    def get_disabled_tools(self) -> List[str]:
        """비활성화된 MCP 도구 목록"""
        disabled = self.all_mcp_tools - self.required_mcp_tools
        return sorted(list(disabled))
    
    def should_expose_tool(self, tool_name: str) -> bool:
        """특정 MCP 도구를 노출해야 하는지 여부"""
        return tool_name in self.required_mcp_tools
    
    def get_stats(self) -> Dict[str, Any]:
        """통계"""
        return {
            "loaded_skills": len(self.skills),
            "skill_names": [s.name for s in self.skills],
            "enabled_tools": len(self.required_mcp_tools),
            "disabled_tools": len(self.all_mcp_tools) - len(self.required_mcp_tools),
            "total_tools": len(self.all_mcp_tools),
            "reduction_rate": (
                (len(self.all_mcp_tools) - len(self.required_mcp_tools)) 
                / len(self.all_mcp_tools) * 100
                if self.all_mcp_tools else 0
            )
        }


# LangChain 패턴: load_skill 도구 (선택적)
try:
    from langchain_core.tools import tool as langchain_tool
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    langchain_tool = None


def load_skill(skill_name: str) -> str:
    """
    Skill을 동적으로 로드하고 필요한 MCP 도구를 활성화합니다.
    
    Available skills:
    - core_policy: 기본 정책 및 안전성 원칙
    - bgp_troubleshooting: BGP 장애 진단
    - acl_verification: ACL 검증
    - reachability_check: 도달성 검사
    
    Returns:
        Skill의 내용과 활성화된 도구 목록
    """
    from agent.skill_loader import SkillLoader
    
    loader = SkillLoader(skills_dir="skills/")
    all_skills = loader.load_all_skills()
    
    # Skill 찾기
    skill = next((s for s in all_skills if s.name == skill_name), None)
    
    if not skill:
        return f"❌ Skill '{skill_name}' not found. Available: {[s.name for s in all_skills]}"
    
    # MCP 도구 활성화
    server = SkillControlledMCPServer([skill])
    enabled = server.get_enabled_tools()
    
    return f"""
✅ Loaded Skill: {skill.name}

📚 Description: {skill.description}

🔧 Enabled MCP Tools: {enabled}

📖 Content:
{skill.content[:500]}...

Use the enabled tools to accomplish your task.
    """


def create_skill_controlled_mcp_config(task: str) -> Dict[str, Any]:
    """
    Task에 필요한 Skills를 로드하고 MCP 설정을 생성합니다.
    
    Args:
        task: Task 설명
        
    Returns:
        MCP 서버 설정 (활성화된 도구 목록 포함)
    """
    from agent.skill_loader import load_skills_for_task
    
    # Task별 Skills 로드
    skills = load_skills_for_task(task)
    
    # Skills-controlled MCP 서버
    server = SkillControlledMCPServer(skills)
    
    return {
        "skills": [s.name for s in skills],
        "enabled_mcp_tools": server.get_enabled_tools(),
        "disabled_mcp_tools": server.get_disabled_tools(),
        "stats": server.get_stats(),
        "system_prompt": SkillLoader().build_system_prompt(skills)
    }


if __name__ == "__main__":
    # 데모
    from agent.skill_loader import SkillLoader, load_skills_for_task
    
    print("=" * 80)
    print("📊 Skills-Controlled MCP Tools Demo")
    print("=" * 80)
    print()
    
    tasks = [
        "장비 목록을 보여주세요",
        "PE1과 PE2 간 BGP 세션이 Down입니다",
        "CE01에서 10.0.3.10으로 ping이 안 됩니다"
    ]
    
    for i, task in enumerate(tasks, 1):
        print(f"{i}. Task: \"{task}\"")
        print("-" * 80)
        
        config = create_skill_controlled_mcp_config(task)
        
        print(f"   로드된 Skills: {config['skills']}")
        print(f"   활성화된 MCP 도구: {len(config['enabled_mcp_tools'])}개")
        print(f"   비활성화된 도구: {len(config['disabled_mcp_tools'])}개")
        print(f"   절감율: {config['stats']['reduction_rate']:.1f}%")
        print()
        print(f"   Enabled Tools:")
        for tool in config['enabled_mcp_tools']:
            print(f"      ✅ {tool}")
        print()
    
    print("=" * 80)
