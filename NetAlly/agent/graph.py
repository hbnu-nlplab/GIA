"""
LabMate 2-Agent Orchestrator Graph

Agent 1: Orchestrator (작은 모델) - Skills 선택
Agent 2: Executor (큰 모델) - 도구 실행
"""
import os
from typing import List, Dict, Any, Literal, Optional
from typing_extensions import TypedDict
from dotenv import load_dotenv

from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from agent.llm_provider import LLMProvider, LLMConfig
from agent.tools import get_tools as get_legacy_tools
from agent.mcp_tools import get_tools as get_mcp_tools
from agent.skill_loader import get_skill_catalog, load_skills, get_loader

load_dotenv()


# =============================================================================
# State
# =============================================================================

class OrchestratorState(TypedDict):
    """2-Agent Orchestrator State"""
    # 입력
    question: str
    answer_type: str
    
    # Orchestrator 출력
    selected_skills: List[str]
    reasoning: str
    
    # 필터링된 도구
    enabled_tools: List[str]
    skill_prompt: str
    
    # Executor 출력
    messages: List[Any]
    final_answer: str
    
    # 메타
    step_count: int
    is_complete: bool


# =============================================================================
# Orchestrator Agent (작은 모델)
# =============================================================================

ORCHESTRATOR_SYSTEM = """You are a network troubleshooting planner.

Your job is to analyze the user's question and select the most relevant skills.

{catalog}

## Instructions
1. Analyze what information is needed to answer the question
2. Select 1-3 relevant skills from the catalog
3. Always include "core" skill

## Output Format (JSON only)
```json
{{
  "selected_skills": ["core", "config_query"],
  "reasoning": "Need to query device configuration"
}}
```
"""


def create_orchestrator_node(llm):
    """Orchestrator 노드 생성"""
    
    def orchestrator(state: OrchestratorState) -> OrchestratorState:
        question = state.get("question", "")
        
        # Skill 카탈로그 가져오기
        catalog = get_skill_catalog()
        system = ORCHESTRATOR_SYSTEM.format(catalog=catalog)
        
        # LLM 호출
        messages = [
            SystemMessage(content=system),
            HumanMessage(content=f"Question: {question}\n\nSelect skills:")
        ]
        
        response = llm.invoke(messages)
        content = response.content
        
        # JSON 파싱
        import json
        import re
        
        json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group())
                selected = result.get("selected_skills", ["core"])
                reasoning = result.get("reasoning", "")
            except:
                selected = ["core"]
                reasoning = "Parse error, using core only"
        else:
            selected = ["core"]
            reasoning = "No JSON found, using core only"
        
        # Core 항상 포함
        if "core" not in selected:
            selected.insert(0, "core")
        
        return {
            **state,
            "selected_skills": selected,
            "reasoning": reasoning,
        }
    
    return orchestrator


# =============================================================================
# Tool Filter Node
# =============================================================================

def filter_tools_node(state: OrchestratorState) -> OrchestratorState:
    """Skills를 가이드 프롬프트로만 반영 (도구 접근 제어는 하지 않음)."""
    selected_skills = state.get("selected_skills", ["core"])
    
    # Skills 로드
    skills = load_skills(selected_skills)

    loader = get_loader()
    # Executor용 Skill 프롬프트
    skill_prompt = loader.build_executor_prompt(skills)
    runtime_tools = get_runtime_tools()
    
    return {
        **state,
        "enabled_tools": [t.name for t in runtime_tools],
        "skill_prompt": skill_prompt,
    }


def get_tool_backend() -> str:
    """Tool backend selector.

    - mcp (default): MCP-backed tools
    - legacy: in-process LangChain tools
    """
    return os.getenv("NETALLY_TOOL_BACKEND", "mcp").strip().lower()


def get_runtime_tools() -> List[Any]:
    backend = get_tool_backend()
    if backend == "legacy":
        return get_legacy_tools()
    return get_mcp_tools()


# =============================================================================
# Executor Agent (큰 모델)
# =============================================================================

EXECUTOR_SYSTEM = """You are a network configuration Q&A assistant.

{skill_prompt}

## Task
Answer the question using the available tools.
Format your answer according to the answer_type: {answer_type}

## Answer Formats
- text: Plain text string
- numeric: Number
- set: JSON array ["a", "b"]
- map: JSON object {{"key": "value"}}
- boolean: true or false
"""


def create_executor_node(llm):
    """Executor 노드 생성"""
    
    def executor(state: OrchestratorState) -> OrchestratorState:
        question = state.get("question", "")
        answer_type = state.get("answer_type", "text")
        skill_prompt = state.get("skill_prompt", "")
        messages = state.get("messages", [])
        
        # 런타임 백엔드의 전체 도구를 바인딩
        tools = get_runtime_tools()
        llm_with_tools = llm.bind_tools(tools) if tools else llm
        
        # 첫 호출이면 시스템 프롬프트 추가
        if not messages:
            system = EXECUTOR_SYSTEM.format(
                skill_prompt=skill_prompt,
                answer_type=answer_type
            )
            messages = [
                SystemMessage(content=system),
                HumanMessage(content=question)
            ]
        
        # LLM 호출
        response = llm_with_tools.invoke(messages)
        messages = messages + [response]
        
        # 도구 호출 여부
        has_tool_calls = hasattr(response, "tool_calls") and response.tool_calls
        is_complete = not has_tool_calls
        
        # 최종 답변
        final_answer = response.content if is_complete else ""
        
        step_count = state.get("step_count", 0) + 1
        
        return {
            **state,
            "messages": messages,
            "final_answer": final_answer,
            "is_complete": is_complete,
            "step_count": step_count,
        }
    
    return executor


def executor_should_continue(state: OrchestratorState) -> Literal["tools", "end"]:
    """Executor 루프 조건"""
    if state.get("is_complete", False):
        return "end"
    if state.get("step_count", 0) >= 10:
        return "end"
    return "tools"


# =============================================================================
# Graph Builder
# =============================================================================

def create_orchestrated_graph(
    orchestrator_backend: str = "openai",
    orchestrator_model: str = "gpt-4o-mini",
    executor_backend: str = "vllm",
    executor_model: str = "gpt-oss-20b",
):
    """2-Agent Orchestrator 그래프 생성"""
    
    # Orchestrator LLM (작은 모델)
    orch_config = LLMConfig(backend=orchestrator_backend, model=orchestrator_model)
    orch_llm = LLMProvider.create(orch_config)
    
    # Executor LLM (큰 모델)
    exec_config = LLMConfig(backend=executor_backend, model=executor_model)
    exec_llm = LLMProvider.create(exec_config)
    
    # 도구
    all_tools = get_runtime_tools()
    tool_node = ToolNode(all_tools)
    
    # 그래프 빌더
    builder = StateGraph(OrchestratorState)
    
    # 노드 추가
    builder.add_node("orchestrator", create_orchestrator_node(orch_llm))
    builder.add_node("filter_tools", filter_tools_node)
    builder.add_node("executor", create_executor_node(exec_llm))
    builder.add_node("tools", tool_node)
    
    # 엣지
    builder.add_edge(START, "orchestrator")
    builder.add_edge("orchestrator", "filter_tools")
    builder.add_edge("filter_tools", "executor")
    builder.add_conditional_edges(
        "executor",
        executor_should_continue,
        {"tools": "tools", "end": END}
    )
    builder.add_edge("tools", "executor")
    
    return builder.compile()


# =============================================================================
# Default Graph (LangGraph Studio용)
# =============================================================================

# 기본 설정으로 그래프 생성
graph = create_orchestrated_graph(
    orchestrator_backend="openai",
    orchestrator_model="gpt-4o-mini",
    executor_backend="openai",  # vLLM이 없으면 OpenAI 사용
    executor_model="gpt-4o-mini",
)


# =============================================================================
# 편의 함수
# =============================================================================

async def run_question(question: str, answer_type: str = "text") -> str:
    """질문 실행"""
    initial_state = {
        "question": question,
        "answer_type": answer_type,
        "selected_skills": [],
        "reasoning": "",
        "enabled_tools": [],
        "skill_prompt": "",
        "messages": [],
        "final_answer": "",
        "step_count": 0,
        "is_complete": False,
    }
    
    result = await graph.ainvoke(initial_state)
    return result.get("final_answer", "")


if __name__ == "__main__":
    import asyncio
    
    test_q = "p1 장비의 hostname은 무엇인가요?"
    result = asyncio.run(run_question(test_q, "text"))
    print(f"Q: {test_q}")
    print(f"A: {result}")
