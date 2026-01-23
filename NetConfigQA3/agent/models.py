"""
Task Models
에이전트 간 데이터 전달을 위한 모델 정의
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class TaskIntent(str, Enum):
    """작업 의도 분류"""
    QUERY = "query"           # 조회 (읽기 전용)
    VERIFY = "verify"         # 검증 (Batfish 분석)
    CHANGE = "change"         # 설정 변경
    LIFECYCLE = "lifecycle"   # 장비 라이프사이클 (생성/삭제/등록)
    TROUBLESHOOT = "troubleshoot"  # 문제 해결


class RiskLevel(str, Enum):
    """위험도 분류"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TaskPassage:
    """
    Planner Agent가 생성하는 작업 분석 결과
    
    Executor Agent에게 전달되어 효율적인 도구 선택과 실행을 안내합니다.
    """
    # 작업 분석
    task_analysis: str = ""
    intent: TaskIntent = TaskIntent.QUERY
    
    # 스킬 선택
    required_skills: List[str] = field(default_factory=list)
    
    # 도구 선택
    required_tools: List[str] = field(default_factory=list)
    
    # 실행 힌트
    workflow_hint: str = ""
    estimated_steps: int = 1
    
    # 안전성
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    
    # 메타데이터
    confidence: float = 0.0
    
    def to_prompt_context(self) -> str:
        """System Prompt에 주입할 컨텍스트 생성"""
        lines = [
            "## Task Analysis (by Planner)",
            f"- **의도**: {self.intent.value}",
            f"- **분석**: {self.task_analysis}",
            f"- **워크플로우**: {self.workflow_hint}",
            f"- **예상 단계**: {self.estimated_steps}",
            f"- **위험도**: {self.risk_level.value}",
        ]
        
        if self.requires_approval:
            lines.append("- ⚠️ **승인 필요**: 이 작업은 approval_request() 호출이 필요합니다.")
        
        lines.append(f"\n**사용 가능한 도구**: {', '.join(self.required_tools)}")
        
        return "\n".join(lines)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskPassage":
        """딕셔너리에서 TaskPassage 생성"""
        # intent 변환
        intent_str = data.get("intent", "query")
        try:
            intent = TaskIntent(intent_str)
        except ValueError:
            intent = TaskIntent.QUERY
        
        # risk_level 변환
        risk_str = data.get("risk_level", "low")
        try:
            risk_level = RiskLevel(risk_str)
        except ValueError:
            risk_level = RiskLevel.LOW
        
        return cls(
            task_analysis=data.get("task_analysis", ""),
            intent=intent,
            required_skills=data.get("required_skills", []),
            required_tools=data.get("required_tools", []),
            workflow_hint=data.get("workflow_hint", ""),
            estimated_steps=data.get("estimated_steps", 1),
            risk_level=risk_level,
            requires_approval=data.get("requires_approval", False),
            confidence=data.get("confidence", 0.0)
        )


@dataclass
class SkillSummary:
    """스킬 요약 (Planner에게 제공)"""
    name: str
    description: str
    tags: List[str] = field(default_factory=list)
    
    def to_option(self) -> str:
        """선택지 형태로 변환"""
        return f"- `{self.name}`: {self.description}"


@dataclass
class ToolSummary:
    """도구 요약 (Planner에게 제공)"""
    name: str
    description: str
    actions: List[str] = field(default_factory=list)
    
    def to_option(self) -> str:
        """선택지 형태로 변환"""
        actions_str = f" (actions: {', '.join(self.actions)})" if self.actions else ""
        return f"- `{self.name}`: {self.description}{actions_str}"
