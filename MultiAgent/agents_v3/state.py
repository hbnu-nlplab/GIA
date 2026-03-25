"""
state.py
--------
LangGraph 상태 정의 모듈.
NetAgentState는 모든 에이전트 노드 간에 공유되는 단일 상태 딕셔너리의 스키마다.
각 노드는 이 상태를 읽고 일부 키만 업데이트하여 반환한다.
"""
from typing import TypedDict, List, Optional

class NetAgentState(TypedDict):
    # 1. 기본 입력 정보
    question: str          # 사용자 질문 (원문)
    context: str           # 원본 컨텍스트 (설정 파일 전체 등)
    dataset_type: str      # 데이터셋 종류: "netconfig" | "multiple_choice" | "short_answer" | "descriptive"
    options: Optional[str] # 객관식 선택지 (multiple_choice일 때만 사용)
    level: Optional[str]   # 난이도 레벨: "L1"~"L5" (netconfig 전용, L4/L5는 전체 토폴로지 컨텍스트 사용)

    # 2. 에이전트 간 공유 데이터
    raw_data: str          # Agent 1(Collector)이 추출한 원시 정보
    current_passage: str   # Agent 2(Verifier)가 정제한 패시지
    candidate_answer: str  # Agent 3(Synthesizer)가 생성한 후보 답변
    final_answer: str      # 최종 확정 답변 (Critic이 ACCEPT 판정 시 채워짐)
    debate1_answer: str    # 1차 토론(Debate 1) 단계에서의 답변 스냅샷
    proponent_responses: list  # Agent 4(Supporter)의 누적 옹호 응답 리스트
    critic_feedbacks: list     # Agent 5(Critic)의 누적 비판 피드백 리스트

    pro_argument: str       # Agent 4의 옹호 논리 (최신 라운드)
    proponent_status: str   # Agent 4의 판정: "DEFEND" | "CONCEDE"
    con_argument: str       # Agent 5의 비판 논리 (최신 라운드)

    # 3. 루프 제어 변수
    hop_count: int           # 현재 미사용 (레거시 호환용)
    inner_turn_count: int    # Supporter ↔ Skeptic 내부 반복 횟수 (최대 3회)
    outer_loop_count: int    # Collector로 되돌아가는 외부 반복 횟수 (최대 3회)

    # 4. 토론 및 피드백 상태
    status: str              # Critic 판정 결과: "ACCEPT" | "CONTINUE_DEBATE" | "NEED_MORE_INFO"
    critic_feedback: str     # Critic이 Synthesizer/Supporter에게 전달하는 비판 내용
    feedback_to_collector:str # Critic이 Collector에게 전달하는 재수집 지시사항

    # 5. 이력 및 기타
    history: List[dict]          # 전체 대화 이력 (현재 미사용)
    device_db: dict              # 이전 코드와의 호환성을 위해 유지 (사용하지 않더라도 에러 방지용)
    next_hop_device: Optional[str]  # 레거시 호환용 필드
