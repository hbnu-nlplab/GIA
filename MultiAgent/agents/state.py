from typing import TypedDict, List, Optional

class AgentState(TypedDict):
    id: str
    question: str
    original_passage: str
    gold_answer: str
    options: str
    dataset_type: str
    context: str            # 원본 지문 혹은 관련 컨텍스트
    
    current_passage: str    # 계속 수정되는 지문
    round_count: int        # 반복 횟수 체크
    history: List[str]      # 로그 기록
    candidate_answer: str   # Debate 1에서 도출한 1차 정답
    
    pro_argument: str       # 정답 옹호 근거
    con_argument: str       # 반박 및 오답 가능성
    final_answer: str       # 최종 결정된 정답