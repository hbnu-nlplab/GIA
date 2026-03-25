"""
debate2.py
----------
2차 토론(Debate 2) 에이전트 정의 모듈.

파이프라인: Supporter → Skeptic

- Agent 4 (Supporter/Proponent): Synthesizer가 생성한 후보 답변을 패시지 근거로 옹호
- Agent 5 (Skeptic/Critic):      패시지와 답변의 일치 여부를 검증하고 상태(status)를 판정

판정 결과(status):
- ACCEPT:           답변이 패시지로 충분히 뒷받침됨 → 토론 종료
- CONTINUE_DEBATE:  패시지는 관련 있으나 답변에 논리적 비약 존재 → Supporter 재호출 (최대 3회)
- NEED_MORE_INFO:   패시지 자체가 불충분 → Collector 재호출 (최대 3회)
"""

import json
import re
from contextlib import contextmanager
from agents_v3.model_loader import get_models, USE_LOCAL
import threading

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


# ==========================================
# 🛡️ Agent 4: Proponent (옹호 및 근거 보강)
# ==========================================
def supporter_node(state: dict):
    """
    Synthesizer(Agent 3)의 후보 답변을 패시지 근거로 검토하고 DEFEND 또는 CONCEDE를 판정한다.

    판정 결과:
    - DEFEND:  패시지 근거로 답변을 충분히 방어 가능 → Critic에게 전달
    - CONCEDE: Critic의 지적이 타당하고 답변이 틀렸음을 인정 → Synthesizer 재호출 트리거

    상태 업데이트:
        proponent_status (str):     "DEFEND" | "CONCEDE"
        pro_argument (str):         최신 라운드의 옹호/인정 논리
        proponent_responses (list): 누적 옹호 응답 이력
    """
    print("\n🛡️ [Agent 4: Proponent] 답변 검토 — DEFEND or CONCEDE")
    models = get_models()
    llm = models['A']

    critic_feedback = state.get("critic_feedback", "")
    is_first_round = not critic_feedback  # Critic 피드백이 없으면 첫 라운드

    system_prompt = """You are a Proponent Network Engineer reviewing a Candidate Answer against a Passage.

TASK: Decide whether to DEFEND or CONCEDE the Candidate Answer based on the Passage evidence.

RULES:
1. First, verify the Candidate Answer yourself against the Passage — find the exact lines that support or contradict it.
2. If the Passage clearly supports the Candidate Answer → DEFEND.
   - Cite the exact supporting line(s) from the Passage.
   - If there is Critic Feedback, refute it with technical facts from the Passage.
3. If the Critic Feedback reveals a genuine error AND the Passage confirms the error → CONCEDE.
   - Only CONCEDE when you can find evidence in the Passage that the Candidate Answer is wrong.
   - Do NOT CONCEDE just because the Critic sounds confident — require Passage evidence.
4. On the first round (no Critic Feedback yet) → always DEFEND.

OUTPUT FORMAT (valid JSON only, no markdown):
{
    "proponent_status": "DEFEND" | "CONCEDE",
    "argument": "Your reasoning: cite Passage lines for DEFEND, or explain what is wrong for CONCEDE."
}"""

    prompt = f"""{system_prompt}

Passage: {state.get('current_passage')}
Candidate Answer: {state.get('candidate_answer')}
Critic Feedback: {critic_feedback if critic_feedback else "None (first round — DEFEND by default)"}"""

    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"\nOptions: {options_str}"

    with gpu_lock():
        response = llm.invoke(prompt)
    response_text = _get_text(response)

    # JSON 파싱
    proponent_status = "DEFEND"
    argument = response_text.strip()
    try:
        clean = re.sub(r"<think>.*?</think>", "", response_text, flags=re.DOTALL).strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        elif clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        json_match = re.search(r'\{.*\}', clean, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group(0))
            raw_status = result.get("proponent_status", "DEFEND").upper()
            proponent_status = raw_status if raw_status in ("DEFEND", "CONCEDE") else "DEFEND"
            argument = result.get("argument", argument)
    except (json.JSONDecodeError, AttributeError) as e:
        print(f"⚠️ [Warning] Proponent output parsing failed: {e} — defaulting to DEFEND")
        proponent_status = "DEFEND"

    # 첫 라운드는 항상 DEFEND (Critic 피드백 없이 CONCEDE 불가)
    if is_first_round and proponent_status == "CONCEDE":
        print("  ⚠️ CONCEDE on first round overridden → DEFEND")
        proponent_status = "DEFEND"

    # CONCEDE 시 inner_turn_count 증가 (Skeptic을 거치지 않으므로 여기서 직접 카운트)
    # 이를 통해 check_proponent_status에서 무한 루프 방지
    new_inner_turn_count = state.get("inner_turn_count", 0)
    if proponent_status == "CONCEDE":
        new_inner_turn_count += 1
        print(f"  🔁 CONCEDE turn count: {new_inner_turn_count}")

    print(f"+++++++++++++++++ Proponent: {proponent_status}")
    return {
        "proponent_status": proponent_status,
        "pro_argument": argument,
        "proponent_responses": state.get("proponent_responses", []) + [response_text],
        "inner_turn_count": new_inner_turn_count
    }


# ==========================================
# ⚖️ Agent 5: Critic (비판 및 상태 판정)
# ==========================================
def skeptic_node(state: dict):
    """
    패시지와 후보 답변의 일치 여부를 검증하고 토론 진행 여부를 판정한다.

    검증 절차:
    1. 패시지 우선 검증: 질문에 답하는 정확한 값/설정 라인이 패시지에 있는지 확인
    2. 의무적 인용 테스트: ACCEPT를 주려면 반드시 패시지에서 근거 문장을 복사해야 함
    3. 하드 룰 적용:
       - 패시지가 비어있거나 다른 장비 설정이면 → NEED_MORE_INFO
       - 답변의 IP/숫자가 패시지에 없으면 → CONTINUE_DEBATE
       - 답변이 "[NONE]"이면 → NEED_MORE_INFO

    출력 형식: JSON 객체
    {
        "status": "ACCEPT" | "CONTINUE_DEBATE" | "NEED_MORE_INFO",
        "evidence_quote": "패시지에서 복사한 근거 문장",
        "con_argument": "답변이 틀리거나 패시지가 불충분한 이유",
        "feedback_to_agent1": "Agent 1에게 전달할 재수집 지시사항"
    }

    상태 업데이트:
        status (str):              판정 결과
        critic_feedback (str):     비판 내용 (다음 Supporter에게 전달)
        con_argument (str):        비판 의견 전용 필드
        critic_feedbacks (list):   누적 비판 이력
        final_answer (str):        ACCEPT인 경우 candidate_answer를 복사, 아니면 빈 문자열
        inner_turn_count (int):    내부 루프 카운터 +1
    """
    print("⚖️ [Agent 5: Critic] 최종 검증 및 비판 의견 제시")
    models = get_models()
    llm = models.get('B', models['A'])  # B 모델 우선 사용 (Collector와 동일한 모델로 일관성 확보)

    system_prompt = """You are a Network Answer Auditor. Your sole job is to verify whether the Passage contains sufficient evidence for the Candidate Answer.

### STEP 1 — PASSAGE-FIRST VERIFICATION (Do this BEFORE reading Agent 4's defense)
Read the Question and Passage only. Ask yourself:
- Can I find the exact value or configuration line in the Passage that directly answers the Question?
- Does the device mentioned in the Question match the device described in the Passage?

### STEP 2 — QUOTATION TEST
To give status "ACCEPT", find the line(s) from the Passage that support the answer and copy them into evidence_quote.
If the answer is a simple value (hostname, version number, etc.) and it clearly appears in the Passage → ACCEPT immediately.

### HARD RULES (override everything, including Agent 4's defense):
1. **Empty/Irrelevant Passage**: If Passage is empty, "[NONE]", whitespace-only, or describes a different device than the Question → NEED_MORE_INFO. Agent 4's defense CANNOT override this.
2. **Unverifiable Values**: If the Candidate Answer contains IPs or identifiers that do NOT appear verbatim in the Passage → CONTINUE_DEBATE.
3. **Wrong Device**: If the Passage config block belongs to a different device than asked → NEED_MORE_INFO.
4. **Refusal Answer**: If the Candidate Answer says "I cannot answer", "no information", "[NONE]" → NEED_MORE_INFO.
5. **Agent 4 says "passage is missing"**: If Agent 4's defense admits the passage lacks info → NEED_MORE_INFO immediately.
6. **Simple match = ACCEPT**: If the question asks for a single value (hostname, version, AS number, etc.) and that exact value appears in the Passage → ACCEPT. Do NOT apply extra scrutiny to obvious matches.
6. **Null for text type**: If the Candidate Answer is "null" but the Passage does NOT contain "[FEATURE_NOT_FOUND]" and is not empty → CONTINUE_DEBATE. "null" is only valid when the passage explicitly shows the feature is absent.
7. **Empty map for map type**: If the Candidate Answer is "{}" (empty object) but the Passage contains interface configuration lines → NEED_MORE_INFO. An empty map is only valid if the passage is also empty.
8. **Unknown/null values in map**: If the Candidate Answer is a map that contains "unknown" or "null" as any value → CONTINUE_DEBATE. The agent must infer values from config (e.g., VRF default, shutdown state) instead of using placeholders.
9. **Zero for numeric type**: If the Candidate Answer is 0 but the Passage contains countable items (interface lines, route lines, vrf blocks, etc.) → CONTINUE_DEBATE. Zero is only valid when the passage is empty or the feature is genuinely absent.
10. **Undercounting check**: For numeric answers, verify the count against the passage. If the passage visibly contains more items than the answer claims → CONTINUE_DEBATE.

### DECISION CRITERIA:
- **ACCEPT**: You found the exact supporting line in Passage AND the answer matches it precisely.
- **CONTINUE_DEBATE**: Passage exists and is relevant, but answer has logical leaps or unverifiable values.
- **NEED_MORE_INFO**: Passage is missing, empty, wrong device, or fundamentally insufficient.

### OUTPUT FORMAT:
You MUST output ONLY a valid JSON object. No markdown, no preamble.
{
    "status": "ACCEPT" | "CONTINUE_DEBATE" | "NEED_MORE_INFO",
    "evidence_quote": "The exact line(s) copied from Passage that support the answer. Write 'NOT FOUND' if you cannot find it.",
    "con_argument": "Detailed technical critique of why the answer is wrong or why the passage is insufficient.",
    "feedback_to_agent1": "Specific instructions for Agent 1 to find the missing data (e.g., 'Look for hostname leaf1 and BGP neighbor commands'). Required if status is not ACCEPT."
}"""

    # 평가 대상: 패시지 vs 답변 (우선 평가)
    # 참고용: Supporter의 옹호 의견 (CONTINUE_DEBATE 업그레이드 시에만 고려)
    prompt = f"""{system_prompt}

--- EVALUATE THIS FIRST (Passage vs Answer) ---
Question: {state.get('question')}
Passage: {state.get('current_passage')}
Candidate Answer (Agent 3): {state.get('candidate_answer')}

--- CONSIDER THIS SECOND (for CONTINUE_DEBATE upgrade only) ---
Proponent's Defense (Agent 4): {state.get('pro_argument')}"""

    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    with gpu_lock():
        response = llm.invoke(prompt)
    response_text = _get_text(response)

    # JSON 파싱: 마크다운 코드블록 및 <think> 태그 제거 후 파싱
    try:
        clean_text = response_text.strip()
        # reasoning 모델의 사고 과정 제거
        clean_text = re.sub(r"<think>.*?</think>", "", clean_text, flags=re.DOTALL).strip()
        # 마크다운 코드블록 제거
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()

        # 응답 내에서 JSON 객체 부분만 추출하여 파싱
        json_match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group(0))
            except json.JSONDecodeError:
                result = json.loads(clean_text)
        else:
            result = json.loads(clean_text)

        # 유효하지 않은 status 값은 ACCEPT로 폴백
        status = result.get("status", "ACCEPT").upper()
        if status not in ["ACCEPT", "CONTINUE_DEBATE", "NEED_MORE_INFO"]:
            status = "ACCEPT"
        con_argument = result.get("con_argument", "")
        feedback_to_agent1 = result.get("feedback_to_agent1", "")

    except (json.JSONDecodeError, AttributeError) as e:
        # JSON 파싱 실패 시 안전한 기본값으로 CONTINUE_DEBATE 반환
        print(f"⚠️ [Warning] Critic output parsing failed: {e}")
        status = "CONTINUE_DEBATE"
        con_argument = response_text
        feedback_to_agent1 = "Re-extract the relevant configuration block for the target device."

    print(f"+++++++++++++++++ Status: {status}")

    return {
        "status": status,
        "critic_feedback": con_argument,       # 다음 Supporter에게 전달할 비판 내용
        "con_argument": con_argument,          # 비판 의견 전용 필드 (결과 저장용)
        "critic_feedbacks": state.get("critic_feedbacks", []) + [response_text],  # 누적 이력
        "final_answer": state.get('candidate_answer') if status == "ACCEPT" else "",  # ACCEPT만 확정
        "inner_turn_count": state.get("inner_turn_count", 0) + 1,  # 내부 루프 카운터 증가
        "feedback_to_collector": feedback_to_agent1  # Fix 3: NEED_MORE_INFO 시 Collector에 전달
    }
