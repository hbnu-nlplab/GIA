"""
debate2.py
----------
2차 토론(Debate 2) 에이전트 정의 모듈.

파이프라인: Supporter → Critic

- Agent 4 (Supporter): Synthesizer의 후보 답변을 패시지 근거로 옹호
- Agent 5 (Critic):    패시지 + 후보 답변 + 옹호를 종합 평가하여 판정

판정 결과(status):
- ACCEPT: 답변이 패시지로 충분히 뒷받침됨 → 토론 종료
- REVISE: 답변에 오류/논리 비약 존재 → synthesizer_feedback을 담아 Synthesizer 재호출 (최대 3회)
"""

import json
import re
import logging
from contextlib import contextmanager
from agents_v3.model_loader import get_models, USE_LOCAL, invoke_with_tokens
import threading

logger = logging.getLogger("agents_v3")

# GPU 접근 직렬화 락 — 로컬 GPU 모드에서만 유효 (클라우드 API 모드에서는 사용 안 함)
_gpu_lock = threading.Lock()

@contextmanager
def gpu_lock():
    """USE_LOCAL=True일 때만 락을 획득한다. 클라우드 모드에서는 즉시 통과."""
    if USE_LOCAL:
        with _gpu_lock:
            yield
    else:
        yield


def _get_text(response):
    """LangChain 객체 또는 일반 텍스트에서 문자열만 안전하게 추출"""
    return response.content if hasattr(response, 'content') else str(response)


def _add_tokens(state: dict, model_key: str, in_tok: int, out_tok: int) -> dict:
    """token_usage에 모델별 토큰을 누적하여 반환한다."""
    tok = state.get("token_usage", {"model_a": {"input": 0, "output": 0},
                                     "model_b": {"input": 0, "output": 0}})
    m = tok.get(model_key, {"input": 0, "output": 0})
    return {**tok, model_key: {"input": m["input"] + in_tok, "output": m["output"] + out_tok}}


# ==========================================
# 🛡️ Agent 4: Supporter (옹호)
# ==========================================
def supporter_node(state: dict):
    """
    Synthesizer의 후보 답변을 패시지 근거로 옹호한다.

    Critic의 이전 피드백이 있으면 그것도 반영하여 반박 논리를 보강한다.

    상태 업데이트:
        pro_argument (str):         최신 옹호 논리
        proponent_responses (list): 누적 옹호 이력
    """
    item_id     = state.get('id', '?')
    inner_turn  = state.get('inner_turn_count', 0)
    candidate   = state.get('candidate_answer', '')
    logger.info(
        "[Supporter][%s] START | inner_turn=%d | candidate_answer=%.200s",
        item_id, inner_turn, candidate
    )
    models = get_models()
    llm = models['A']

    critic_feedback = state.get("synthesizer_feedback", "")

    system_prompt = """You are a Supporter Network Engineer.
Your job is to defend the Candidate Answer using evidence from the Passage.

RULES:
1. Find the exact line(s) in the Passage that support the Candidate Answer. Quote them directly.
2. If there is Critic Feedback from a previous round, address each point specifically using Passage evidence.
3. Do NOT change the Candidate Answer — only justify why it is correct.
4. If a value in the Candidate Answer appears verbatim in the Passage, cite it as direct evidence.
5. Be concise and technical. No vague claims — every assertion must reference a specific Passage line."""

    prompt = f"""{system_prompt}

Question: {state.get('question')}
Passage: {state.get('current_passage')}
Candidate Answer: {state.get('candidate_answer')}
Previous Critic Feedback: {critic_feedback if critic_feedback else "None"}"""

    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"\nOptions: {options_str}"

    with gpu_lock():
        response, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='A')
    response_text = _get_text(response)

    # <think> 블록 제거 후 저장
    argument = re.sub(r"<think>.*?</think>", "", response_text, flags=re.DOTALL).strip()

    logger.info(
        "[Supporter][%s] DONE | inner_turn=%d | model_a tokens(in=%d out=%d) | pro_argument=%.300s",
        item_id, inner_turn, in_tok, out_tok, argument
    )
    return {
        "pro_argument": argument,
        "proponent_responses": state.get("proponent_responses", []) + [argument],
        "token_usage": _add_tokens(state, "model_a", in_tok, out_tok),
    }


# ==========================================
# ⚖️ Agent 5: Critic (판정)
# ==========================================
def skeptic_node(state: dict):
    """
    패시지 + 후보 답변 + Supporter 옹호를 종합하여 판정한다.

    판정:
    - ACCEPT: 답변이 패시지로 충분히 뒷받침됨 → 종료
    - REVISE: 답변에 오류/논리 비약 → synthesizer_feedback을 담아 Synthesizer 재호출

    상태 업데이트:
        status (str):               "ACCEPT" | "REVISE"
        con_argument (str):         비판 내용
        synthesizer_feedback (str): Synthesizer 재생성 지시사항 (REVISE 시)
        critic_feedbacks (list):    누적 비판 이력
        final_answer (str):         ACCEPT 시 candidate_answer 확정
        inner_turn_count (int):     루프 카운터 +1
    """
    item_id    = state.get('id', '?')
    inner_turn = state.get('inner_turn_count', 0)
    logger.info(
        "[Critic][%s] START | inner_turn=%d | candidate_answer=%.200s",
        item_id, inner_turn, state.get('candidate_answer', '')
    )
    models = get_models()
    llm = models.get('B', models['A'])

    system_prompt = """You are a Network Answer Critic. Evaluate the Candidate Answer using the Passage and Supporter's defense.

### EVALUATION ORDER:
1. Read Question + Passage + Candidate Answer first.
2. Find the exact line(s) in the Passage that support or contradict the answer.
3. Read the Supporter's defense — check if their cited Passage lines are accurate.

### ACCEPT criteria (all must hold):
- The exact value/config line answering the question appears in the Passage.
- The Candidate Answer matches that line precisely (no hallucinated values).
- For set/map answers: all items in the answer appear in the Passage.
- For numeric answers: the count matches the number of relevant lines in the Passage.

### REVISE criteria (any one triggers REVISE):
- The Candidate Answer contains a value (IP, number, name) NOT found verbatim in the Passage.
- The Candidate Answer is "null"/0/{}/[] but the Passage contains the relevant feature/lines.
- The Candidate Answer undercounts items visible in the Passage.
- The Candidate Answer uses "unknown" or placeholder values instead of inferring from config.
- The Supporter's cited evidence does not actually match what the Passage says.

### OUTPUT FORMAT (valid JSON only, no markdown, no preamble):
{
    "status": "ACCEPT" | "REVISE",
    "evidence_quote": "<exact line(s) from Passage supporting the answer, or 'NOT FOUND'>",
    "con_argument": "<technical critique of what is wrong with the answer, empty string if ACCEPT. Do NOT dictate what the correct answer should be — only explain the flaw.>"
}"""

    prompt = f"""{system_prompt}

Question: {state.get('question')}
Passage: {state.get('current_passage')}
Candidate Answer: {state.get('candidate_answer')}
Supporter's Defense: {state.get('pro_argument')}"""

    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"\nOptions: {options_str}"

    with gpu_lock():
        response, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='B')
    response_text = _get_text(response)

    # JSON 파싱
    evidence_quote = ""
    try:
        clean_text = re.sub(r"<think>.*?</think>", "", response_text, flags=re.DOTALL).strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()

        json_match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        result = json.loads(json_match.group(0) if json_match else clean_text)

        status             = result.get("status", "ACCEPT").upper()
        if status not in ("ACCEPT", "REVISE"):
            status = "ACCEPT"
        evidence_quote       = result.get("evidence_quote", "")
        con_argument         = result.get("con_argument", "")
        synthesizer_feedback = result.get("synthesizer_feedback", "")

    except (json.JSONDecodeError, AttributeError) as e:
        logger.warning("[Critic][%s] JSON parse failed: %s → defaulting to ACCEPT", item_id, e)
        status               = "ACCEPT"
        con_argument         = response_text
        synthesizer_feedback = ""

    if status == "ACCEPT":
        logger.info(
            "[Critic][%s] ACCEPT | inner_turn=%d | evidence=%.200s",
            item_id, inner_turn, evidence_quote
        )
    else:
        logger.warning(
            "[Critic][%s] REVISE | inner_turn=%d | con_argument=%.200s | feedback=%.200s",
            item_id, inner_turn, con_argument, synthesizer_feedback
        )

    _inner_turn = state.get("inner_turn_count", 0)
    _retry_log = state.get("synthesizer_retry_log", [])
    if status == "REVISE":
        _retry_log = _retry_log + [{"round": _inner_turn + 1, "feedback": synthesizer_feedback}]

    logger.info(
        "[Critic][%s] DONE | status=%s | model_b tokens(in=%d out=%d)",
        item_id, status, in_tok, out_tok
    )
    return {
        "status": status,
        "con_argument": con_argument,
        "synthesizer_feedback": synthesizer_feedback,
        "critic_feedbacks": state.get("critic_feedbacks", []) + [response_text],
        "final_answer": state.get("candidate_answer") if status == "ACCEPT" else "",
        "inner_turn_count": _inner_turn + 1,
        "synthesizer_retry_log": _retry_log,
        "token_usage": _add_tokens(state, "model_b", in_tok, out_tok),
    }
