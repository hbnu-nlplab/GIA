"""
LabMate Agent State Definition
"""
from typing import Optional, List, Dict, Any
from typing_extensions import TypedDict
from langchain_core.messages import BaseMessage
from pydantic import Field


class AgentState(TypedDict):
    """LabMate Agent의 상태 정의
    
    LangGraph의 StateGraph에서 사용되는 상태 스키마입니다.
    """
    # 대화 메시지 히스토리
    messages: List[BaseMessage]
    
    # 현재 질문 정보
    question: str
    answer_type: str  # text, numeric, set, map, boolean
    
    # 도구 호출 정보
    tool_calls: List[Dict[str, Any]]
    tool_results: List[Dict[str, Any]]
    
    # 증거 및 추론
    evidence: str
    reasoning: str
    
    # 최종 답변
    final_answer: str
    
    # 상태 플래그
    is_complete: bool
    needs_more_info: bool
    
    # 메트릭
    step_count: int
    token_count: int


class EvalInput(TypedDict):
    """평가용 입력 포맷"""
    question_id: str
    question: str
    answer_type: str
    gold: str
    level: str
    category: str


class EvalResult(TypedDict):
    """평가 결과 포맷"""
    question_id: str
    question: str
    answer_type: str
    gold: str
    pred: str
    is_correct: bool
    level: str
    category: str
    metrics: Dict[str, Any]
