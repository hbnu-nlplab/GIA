from typing import TypedDict, List, Optional

class NetAgentState(TypedDict):
    # 1. 기본 입력 정보
    question: str
    context: str
    dataset_type: str
    options: Optional[str]
    
    # 2. 에이전트 간 공유 데이터
    raw_data: str
    current_passage: str
    candidate_answer: str
    final_answer: str


    pro_argument: str  # Agent 4의 옹호 논리
    con_argument: str  # Agent 5의 비판 논리    
    # 3. 루프 제어 변수 (기본값 대응을 위해 필수 포함)
    hop_count: int
    inner_turn_count: int
    outer_loop_count: int
    
    # 4. 토론 및 피드백 상태
    status: str
    critic_feedback: str
    feedback_to_collector: str
    
    # 5. 이력 및 기타
    history: List[dict]
    # 이전 코드와의 호환성을 위해 유지 (사용하지 않더라도 에러 방지용)
    device_db: dict 
    next_hop_device: Optional[str]