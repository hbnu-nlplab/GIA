"""
Tool Usage Scorer - 에이전트의 도구 사용 평가

LangGraph State의 messages에서 tool_calls를 추출하여
에이전트가 적절한 도구를 사용했는지 평가합니다.

NetAlly Implementation Plan v2의 Phase 4 구현
"""

from typing import Dict, Any, List, Set


# 레벨별 권장 도구 매핑
LEVEL_TOOL_RECOMMENDATIONS = {
    "L1": {
        "description": "단일 장비 단순 조회 - 도구 선택 자유",
        "recommended": ["network_query"],
        "required": []  # 필수는 아님
    },
    "L2": {
        "description": "다중 장비 집계 - NSO 조회 권장",
        "recommended": ["network_query"],
        "required": []
    },
    "L3": {
        "description": "교차 검증 - NSO 또는 Batfish 사용 권장",
        "recommended": ["network_query", "network_verify"],
        "required": []
    },
    "L4": {
        "description": "도달성 분석 - Batfish 필수",
        "recommended": ["network_verify"],
        "required": ["network_verify"]  # Batfish 필수!
    },
    "L5": {
        "description": "What-If 분석 - Batfish 필수",
        "recommended": ["network_verify"],
        "required": ["network_verify"]  # Batfish What-If 필수!
    }
}


def extract_tool_calls(messages: List[Any]) -> List[str]:
    """
    LangGraph messages에서 tool call 이름 추출
    
    Args:
        messages: LangGraph State의 messages 리스트 (AIMessage, ToolMessage 등)
        
    Returns:
        호출된 도구 이름 리스트
    """
    tool_calls = []
    
    for msg in messages:
        # AIMessage with tool_calls
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                if isinstance(tc, dict):
                    tool_calls.append(tc.get("name", ""))
                elif hasattr(tc, "name"):
                    tool_calls.append(tc.name)
        
        # ToolMessage (도구 응답)
        if hasattr(msg, "name") and hasattr(msg, "content"):
            # ToolMessage는 이미 실행된 도구의 결과
            pass  # 응답은 추적 용도로만 사용
    
    return [t for t in tool_calls if t]  # 빈 문자열 제거


def evaluate_tool_usage(
    messages: List[Any],
    question_level: str,
    expected_tools: List[str] = None
) -> Dict[str, Any]:
    """
    에이전트의 도구 사용 평가
    
    Args:
        messages: LangGraph State의 messages
        question_level: 질문 레벨 (L1, L2, L3, L4, L5)
        expected_tools: (선택) 기대하는 특정 도구 목록
        
    Returns:
        평가 결과 딕셔너리
    """
    # 1. Tool calls 추출
    tool_calls = extract_tool_calls(messages)
    unique_tools = list(set(tool_calls))
    
    # 2. 레벨별 권장/필수 도구 확인
    level_config = LEVEL_TOOL_RECOMMENDATIONS.get(question_level, {})
    recommended = set(level_config.get("recommended", []))
    required = set(level_config.get("required", []))
    
    # 3. 평가 지표 계산
    used_tools_set = set(unique_tools)
    
    # 필수 도구 사용 여부
    used_required = required.intersection(used_tools_set)
    required_satisfied = len(used_required) == len(required) if required else True
    
    # 권장 도구 사용 여부
    used_recommended = recommended.intersection(used_tools_set)
    recommendation_score = len(used_recommended) / max(len(recommended), 1)
    
    # 특정 기대 도구 사용 여부 (옵션)
    expected_satisfied = True
    if expected_tools:
        expected_set = set(expected_tools)
        used_expected = expected_set.intersection(used_tools_set)
        expected_satisfied = len(used_expected) == len(expected_set)
    
    # 4. 결과 반환
    return {
        # 기본 정보
        "question_level": question_level,
        "tool_calls": tool_calls,
        "unique_tools": unique_tools,
        "tool_count": len(tool_calls),
        
        # 필수 도구 평가
        "required_tools": list(required),
        "used_required": list(used_required),
        "required_satisfied": required_satisfied,
        
        # 권장 도구 평가
        "recommended_tools": list(recommended),
        "used_recommended": list(used_recommended),
        "recommendation_score": recommendation_score,
        
        # 종합 점수
        "tool_usage_score": 1.0 if required_satisfied else 0.5,
        "used_verification_tool": "network_verify" in used_tools_set,
        "used_query_tool": "network_query" in used_tools_set,
        
        # 특정 기대 도구 (옵션)
        "expected_satisfied": expected_satisfied
    }


def score_batch(
    results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    배치 평가 결과 집계
    
    Args:
        results: evaluate_tool_usage 결과 리스트
        
    Returns:
        집계된 평가 지표
    """
    if not results:
        return {"error": "No results to score"}
    
    total = len(results)
    required_satisfied_count = sum(1 for r in results if r.get("required_satisfied", False))
    used_verify_count = sum(1 for r in results if r.get("used_verification_tool", False))
    used_query_count = sum(1 for r in results if r.get("used_query_tool", False))
    
    # 레벨별 집계
    by_level = {}
    for r in results:
        level = r.get("question_level", "Unknown")
        if level not in by_level:
            by_level[level] = {"total": 0, "required_satisfied": 0}
        by_level[level]["total"] += 1
        if r.get("required_satisfied", False):
            by_level[level]["required_satisfied"] += 1
    
    return {
        "total_samples": total,
        "required_satisfied_rate": required_satisfied_count / total,
        "verification_tool_usage_rate": used_verify_count / total,
        "query_tool_usage_rate": used_query_count / total,
        "by_level": {
            level: {
                "total": data["total"],
                "required_satisfied_rate": data["required_satisfied"] / data["total"]
            }
            for level, data in by_level.items()
        }
    }
