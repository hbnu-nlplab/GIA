"""
Task Planner Agent
사용자 요청을 분석하여 필요한 스킬과 도구를 결정합니다.
"""

import json
import logging
from typing import List, Dict, Any, Optional

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from .models import TaskPassage, SkillSummary, ToolSummary, TaskIntent, RiskLevel
from .skill_loader import SkillLoader
from config.settings import settings

logger = logging.getLogger(__name__)


# =============================================================================
# 사용 가능한 도구 정의 (요약)
# =============================================================================

AVAILABLE_TOOLS: List[ToolSummary] = [
    ToolSummary(
        name="network_query",
        description="NSO에서 네트워크 설정 정보 조회 (장비, 인터페이스, 라우팅, VRF, ACL)",
        actions=["device", "interface", "routing", "vrf", "security", "acl"]
    ),
    ToolSummary(
        name="network_verify",
        description="Batfish로 네트워크 분석/검증 (연결성, 경로, BGP)",
        actions=["reachability", "traceroute", "bgp_session", "route_table", "loop_check"]
    ),
    ToolSummary(
        name="network_change",
        description="NSO로 설정 변경 및 장비 등록/삭제 (⚠️ commit/rollback/delete는 승인 필요)",
        actions=["dry_run", "commit", "rollback", "diff", "register_device", "delete_device", "sync_from", "fetch_host_keys"]
    ),
    ToolSummary(
        name="telemetry_query",
        description="동적 텔레메트리 데이터 조회 (로그, 메트릭, 플로우)",
        actions=["logs", "metrics", "flows"]
    ),
    ToolSummary(
        name="lab_manage",
        description="PNETLab 토폴로지 관리 (개별 장비 추가/삭제, 연결, Batfish 초기화)",
        actions=["show_inventory", "get_status", "add_node", "delete_node", "start_node", "stop_node", 
                 "add_network", "delete_network", "connect_interface", "disconnect_interface",
                 "export_configs", "init_batfish"]
    ),
    ToolSummary(
        name="approval_request",
        description="위험 작업에 대한 승인 요청 (commit, rollback, delete 전에 필요)",
        actions=[]
    ),
    ToolSummary(
        name="help_guide",
        description="도구 사용법과 예시 조회",
        actions=["tools", "examples", "troubleshooting", "best_practices"]
    ),
    ToolSummary(
        name="device_workflow",
        description="PNETLab-NSO 통합 워크플로우 (장비 추가/삭제 자동화, 토폴로지 동기화)",
        actions=["add", "delete", "sync_topology"]
    ),
]


# =============================================================================
# Planner System Prompt
# =============================================================================

PLANNER_SYSTEM_PROMPT = """당신은 네트워크 운영 작업을 분석하는 Planner입니다.

## 역할
사용자 요청을 분석하여 Executor Agent가 효율적으로 작업할 수 있도록 다음을 결정합니다:
1. 작업 의도 분류
2. 필요한 Skills 선택
3. 필요한 Tools 선택
4. 워크플로우 힌트 제공

## 의도 분류 (intent)
- `query`: 정보 조회 (장비 목록, 설정 확인 등)
- `verify`: 네트워크 검증 (연결성, BGP, 라우팅 분석)
- `change`: 설정 변경 (ACL, 인터페이스 등)
- `lifecycle`: 장비 라이프사이클 (생성, 삭제, 등록)
- `troubleshoot`: 문제 진단 (오류 분석, 원인 파악)

## 사용 가능한 Skills
{skills_options}

## 사용 가능한 Tools
{tools_options}

## 위험도 판단
- `low`: 읽기 전용 작업
- `medium`: 장비 시작/중지, 연결 변경
- `high`: 장비 삭제, 설정 커밋, 롤백
- `critical`: 전체 네트워크 영향

## 출력 형식 (JSON)
```json
{{
  "task_analysis": "작업에 대한 간단한 설명",
  "intent": "query|verify|change|lifecycle|troubleshoot",
  "required_skills": ["skill_name1", "skill_name2"],
  "required_tools": ["tool_name1", "tool_name2"],
  "workflow_hint": "추천 실행 순서 (예: show_inventory → add_node → start_node)",
  "estimated_steps": 3,
  "risk_level": "low|medium|high|critical",
  "requires_approval": false,
  "confidence": 0.95
}}
```

## 규칙
1. 항상 `core_policy` 스킬은 필수 포함
2. commit, rollback, delete_device, delete_node 작업은 `requires_approval: true`
3. 필요한 도구만 최소한으로 선택
4. 응답은 반드시 JSON 형식만

응답에서 JSON 외의 텍스트는 포함하지 마세요."""


# =============================================================================
# TaskPlanner Class
# =============================================================================

class TaskPlanner:
    """
    사용자 요청을 분석하여 TaskPassage를 생성합니다.
    
    Usage:
        planner = TaskPlanner()
        passage = planner.plan("새 라우터를 추가해줘")
        print(passage.required_tools)  # ["lab_manage"]
    """
    
    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0):
        """
        Args:
            model: 사용할 LLM 모델
            temperature: 생성 온도 (0 = 결정적)
        """
        self.model = model
        self.temperature = temperature
        self.skill_loader = SkillLoader()
        self._llm = None
    
    @property
    def llm(self):
        """LLM 지연 초기화"""
        if self._llm is None:
            if not LANGCHAIN_AVAILABLE:
                raise RuntimeError("LangChain not available")
            self._llm = ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                api_key=settings.openai.api_key
            )
        return self._llm
    
    def _get_skills_options(self) -> str:
        """사용 가능한 스킬 목록을 옵션 형태로 반환"""
        skills = self.skill_loader.load_all_skills()
        summaries = [
            SkillSummary(
                name=s.name,
                description=s.description,
                tags=s.tags
            )
            for s in skills
        ]
        return "\n".join(s.to_option() for s in summaries)
    
    def _get_tools_options(self) -> str:
        """사용 가능한 도구 목록을 옵션 형태로 반환"""
        return "\n".join(t.to_option() for t in AVAILABLE_TOOLS)
    
    def _build_system_prompt(self) -> str:
        """System Prompt 생성"""
        return PLANNER_SYSTEM_PROMPT.format(
            skills_options=self._get_skills_options(),
            tools_options=self._get_tools_options()
        )
    
    def plan(self, user_request: str) -> TaskPassage:
        """
        사용자 요청을 분석하여 TaskPassage 생성
        
        Args:
            user_request: 사용자 요청 문자열
            
        Returns:
            TaskPassage: 분석 결과
        """
        logger.info(f"Planning task: {user_request[:50]}...")
        
        try:
            # LLM 호출
            messages = [
                SystemMessage(content=self._build_system_prompt()),
                HumanMessage(content=user_request)
            ]
            
            response = self.llm.invoke(messages)
            response_text = response.content.strip()
            
            # JSON 파싱
            # 코드 블록 제거
            if response_text.startswith("```"):
                lines = response_text.split("\n")
                response_text = "\n".join(lines[1:-1])
            
            data = json.loads(response_text)
            
            # TaskPassage 생성
            passage = TaskPassage.from_dict(data)
            
            # 항상 core_policy 포함
            if "core_policy" not in passage.required_skills:
                passage.required_skills.insert(0, "core_policy")
            
            logger.info(f"Plan created: intent={passage.intent.value}, tools={passage.required_tools}")
            return passage
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            # 기본 Passage 반환
            return self._fallback_passage(user_request)
        except Exception as e:
            logger.error(f"Planning error: {e}")
            return self._fallback_passage(user_request)
    
    def _fallback_passage(self, user_request: str) -> TaskPassage:
        """파싱 실패 시 기본 Passage 반환"""
        logger.warning("Using fallback passage")
        
        # 간단한 키워드 기반 폴백
        request_lower = user_request.lower()
        
        # 의도 추론
        if any(kw in request_lower for kw in ["추가", "생성", "만들", "add", "create"]):
            intent = TaskIntent.LIFECYCLE
            tools = ["lab_manage", "network_change"]
            skills = ["core_policy", "device_lifecycle_playbook"]
        elif any(kw in request_lower for kw in ["삭제", "제거", "delete", "remove"]):
            intent = TaskIntent.LIFECYCLE
            tools = ["lab_manage", "network_change", "approval_request"]
            skills = ["core_policy", "device_lifecycle_playbook"]
        elif any(kw in request_lower for kw in ["등록", "register", "nso"]):
            intent = TaskIntent.LIFECYCLE
            tools = ["network_change"]
            skills = ["core_policy", "nso_playbook"]
        elif any(kw in request_lower for kw in ["ping", "연결", "reach", "통신"]):
            intent = TaskIntent.VERIFY
            tools = ["network_verify"]
            skills = ["core_policy", "batfish_playbook"]
        elif any(kw in request_lower for kw in ["변경", "수정", "change", "modify"]):
            intent = TaskIntent.CHANGE
            tools = ["network_change", "approval_request"]
            skills = ["core_policy", "nso_playbook"]
        else:
            intent = TaskIntent.QUERY
            tools = ["network_query"]
            skills = ["core_policy"]
        
        return TaskPassage(
            task_analysis=f"분석 실패로 기본값 사용: {user_request[:50]}",
            intent=intent,
            required_skills=skills,
            required_tools=tools,
            workflow_hint="",
            estimated_steps=1,
            risk_level=RiskLevel.LOW,
            confidence=0.3
        )


# =============================================================================
# 편의 함수
# =============================================================================

def plan_task(user_request: str) -> TaskPassage:
    """사용자 요청에 대한 TaskPassage 생성 (편의 함수)"""
    planner = TaskPlanner()
    return planner.plan(user_request)


if __name__ == "__main__":
    # 테스트
    import sys
    logging.basicConfig(level=logging.INFO)
    
    test_queries = [
        "새 라우터를 추가해줘",
        "PE1의 인터페이스 목록 보여줘",
        "PE1에서 PE2로 ping이 되나요?",
        "장비를 NSO에 등록해줘",
    ]
    
    planner = TaskPlanner()
    
    for query in test_queries:
        print(f"\n{'='*60}")
        print(f"Query: {query}")
        passage = planner.plan(query)
        print(f"Intent: {passage.intent.value}")
        print(f"Skills: {passage.required_skills}")
        print(f"Tools: {passage.required_tools}")
        print(f"Workflow: {passage.workflow_hint}")
        print(f"Risk: {passage.risk_level.value}")
