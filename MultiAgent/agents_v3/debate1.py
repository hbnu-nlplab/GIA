"""
debate1.py
----------
1차 토론(Debate 1) 에이전트 정의 모듈.

파이프라인: Collector → Verifier → Synthesizer

- Agent 1 (Collector):   질문에 관련된 원시 정보를 컨텍스트에서 추출
- Agent 2 (Verifier):    추출된 정보에서 불필요한 내용을 제거하여 정제
- Agent 3 (Synthesizer): 정제된 패시지를 바탕으로 후보 답변 생성
"""

import re
import json
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
    """LangChain 응답 객체 또는 일반 문자열에서 텍스트 내용만 안전하게 추출한다."""
    return response.content if hasattr(response, 'content') else str(response)


def _add_tokens(state: dict, model_key: str, in_tok: int, out_tok: int) -> dict:
    """token_usage에 모델별 토큰을 누적하여 반환한다."""
    tok = state.get("token_usage", {"model_a": {"input": 0, "output": 0},
                                     "model_b": {"input": 0, "output": 0}})
    m = tok.get(model_key, {"input": 0, "output": 0})
    return {**tok, model_key: {"input": m["input"] + in_tok, "output": m["output"] + out_tok}}


def _extract_from_tags(text: str, start_tag="[START]", end_tag="[DONE]") -> str:
    """
    LLM 응답에서 [START]...[DONE] 태그 사이의 내용을 추출하고 정제한다.

    처리 순서:
    1. <think>...</think> 블록 제거 (Qwen3 등 reasoning 모델의 사고 과정 제거)
    2. 두 번째 [START] 이후 내용 추출 (모델이 예시를 먼저 출력하는 경우 대응)
    3. [DONE] 이전까지만 사용
    4. "Context:", "Passage:", "Answer:" 등 레이블 헤더 제거

    Args:
        text: LLM 원시 응답 텍스트
        start_tag: 추출 시작 태그 (기본값: "[START]")
        end_tag: 추출 종료 태그 (기본값: "[DONE]")
    Returns:
        str: 정제된 내용 (레이블 없는 순수 값)
    """
    logger.debug("[extract_from_tags] raw_len=%d | preview=%.100s", len(text), text.replace('\n', '↵'))

    # Step 1: <think>...</think> 블록 제거
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Step 2: [START] 기준으로 분할하여 두 번째 등장 이후 내용 선택
    # (모델이 포맷 예시를 먼저 출력한 뒤 실제 답을 출력하는 경우 대응)
    start_parts = text.split(start_tag)
    target_content = ""
    if len(start_parts) >= 3:
        target_content = start_parts[2]   # 두 번째 [START] 이후
    elif len(start_parts) == 2:
        target_content = start_parts[1]   # 첫 번째 [START] 이후
    else:
        target_content = text             # [START]가 없으면 전체 사용

    # Step 3: [DONE] 이전까지만 사용
    if end_tag in target_content:
        target_content = target_content.split(end_tag)[0]
    target_content = target_content.strip()

    # Step 4: "Context:", "Passage:", "Answer:", "Result:" 등 레이블 헤더 제거
    cleaned = re.sub(r"^\s*(Context|Passage|Answer|Result)\s*:\s*", "", target_content,
                     flags=re.IGNORECASE | re.MULTILINE)
    cleaned = cleaned.strip()
    logger.debug("[extract_from_tags] parsed=%.200s", cleaned.replace('\n', '↵'))
    return cleaned


# ==========================================
# 🕵️ Agent 1: Collector Node
# ==========================================
def collector_node(state: dict):
    """
    컨텍스트(설정 파일 전체)에서 질문과 관련된 원시 정보를 추출한다.

    데이터셋 타입별로 다른 수집 전략을 사용한다:
    - descriptive:     포괄적인 기술 설명과 인과관계 수집
    - short_answer:    정확한 사실 값이 담긴 문장/단락 직접 복사
    - multiple_choice: 선택지(A~D) 각각과 관련된 내용 추출
    - netconfig:       질문에서 언급된 특정 장비의 원시 설정 블록만 추출

    상태 업데이트:
        raw_data (str): 추출된 원시 정보
        outer_loop_count (int): 외부 루프 카운터 +1 (Collector 재호출 횟수 추적)
    """
    item_id      = state.get('id', '?')
    outer_loop   = state.get('outer_loop_count', 0)
    dataset_type = state.get("dataset_type", "descriptive")
    level        = state.get("level", "")
    logger.info(
        "[Collector][%s] START | outer_loop=%d | level=%s | dataset_type=%s | "
        "question=%.120s",
        item_id, outer_loop, level, dataset_type, state.get('question', '')
    )
    models = get_models()
    llm = models.get('B', models['A'])  # B 모델 우선 사용, 없으면 A 폴백

    # 데이터셋 타입별 수집 전략 프롬프트
    COLLECTOR_PROMPTS = {
        "descriptive": """Focus on gathering comprehensive technical explanations and cause-effect relationships from the context.""",

        "short_answer": """Focus on finding the exact sentence or paragraph that contains the specific factual answer. Do not miss technical values. Do not rephrase the sentence; copy the relevant content directly from the context.""",

        "multiple_choice": "Identify and extract all parts of the context that relate to the provided question and options (A, B, C, D) to compare them based on your knowledge.",

        "netconfig": """
DEVICE BOUNDARY: The context separates devices using these markers:
  === START OF CONFIG: HOSTNAME ===
  ...configuration lines...
  === END OF CONFIG: HOSTNAME ===

Your output is scored by a Verifier on 4 criteria. Follow these rules to maximize your score:

[C1 — Device Match: you MUST preserve device identity]
- AGGREGATE questions (e.g., "which devices have X", "how many devices", "list all devices"): Extract the relevant section from EVERY device block. Do NOT pick just 1-2 devices.
- Single-device questions: Find the EXACT hostname mentioned in the question.
- ALWAYS include the === START OF CONFIG: HOSTNAME === and === END OF CONFIG: HOSTNAME === boundary markers for each extracted block.
- ALWAYS include the "hostname <name>" line from inside each block.

[C2 — Feature/Command Presence: extract the exact section asked about]
- Identify the specific command or section the question targets (e.g., "router bgp", "interface X", "ip route", "line vty", "ip ssh", "clock timezone", "aaa authentication", "vrf definition").
- For AGGREGATE questions: scan EVERY device block and extract the relevant section (or mark [FEATURE_NOT_FOUND] per device if absent).
- Extract ALL lines of that section completely.
- Also extract: negation lines ("no aaa new-model", "no ip routing") — they prove a feature is disabled.
- If the specific command is completely absent from the target block, write: [FEATURE_NOT_FOUND]

[C3 — Completeness: never truncate]
- Extract the COMPLETE configuration block — do not stop early.
- Include lines before "hostname" (e.g., "version 15.7", "boot" lines).
- COUNT questions (e.g., "how many interfaces/routes/VRFs"): extract EVERY countable line — all "interface X", "ip route", "network", "vrf definition", "route-target", "router bgp", "neighbor" lines.
- MAP questions (e.g., "list all interfaces and their X"): extract EVERY interface block completely including "shutdown", "ip vrf forwarding", "ip address" lines — their absence is meaningful.
- AGGREGATE questions: you MUST cover ALL devices, not a subset.

[C4 — Format Integrity: raw config only]
- Output ONLY raw configuration lines verbatim. Do NOT convert to natural language.
- No commentary, no explanations, no JSON wrappers, no metadata.
""",

        "netconfig_topo": """
DEVICE BOUNDARY: The context separates devices using these markers:
  === START OF CONFIG: HOSTNAME ===
  ...configuration lines...
  === END OF CONFIG: HOSTNAME ===

This is a TOPOLOGY-LEVEL question (L4/L5) requiring full network simulation.
Your output is scored by a Verifier on 4 criteria. Follow these rules:

[C1 — Device Match]
- Extract ALL device blocks. Preserve ALL === START OF CONFIG === and === END OF CONFIG === markers.
- Every device's "hostname <name>" line must appear in your output.

[C2 — Feature/Command Presence]
For each device, extract ALL routing-relevant sections:
  - hostname
  - ALL interface blocks: ip address, ip unnumbered, mpls ip, shutdown, ip vrf forwarding
  - ALL static routes: ip route ...
  - ALL routing protocol blocks: router ospf, router bgp, neighbor, network, redistribute, area
  - ALL VRF definitions: vrf definition, rd, route-target import/export

[C3 — Completeness]
- Do NOT filter or skip any device. Every device's full routing config is needed for path simulation.

[C4 — Format Integrity]
- Output ONLY raw configuration lines verbatim. No natural language. No commentary.
"""
    }

    # L4/L5는 전체 토폴로지 추출 전략 사용
    if dataset_type == "netconfig" and level in ("L4", "L5"):
        effective_type = "netconfig_topo"
    else:
        effective_type = dataset_type
    base_strategy = COLLECTOR_PROMPTS.get(effective_type, COLLECTOR_PROMPTS["descriptive"])

    if dataset_type == "multiple_choice":
        system_prompt = f"""You are a Telecom Knowledge Collector.
TASK: {base_strategy}
- Do not lose technical precision.

### OUTPUT FORMAT (MANDATORY):
[START]
<background knowledge here>
[DONE]

CRITICAL RULES:
- You MUST output [START] and [DONE] tags. No exceptions.
- Between the tags, write concise factual background knowledge (2-5 sentences) relevant to the question and options.
- Do NOT state which option is correct. Do NOT answer the question.
- Do NOT copy the question or options verbatim."""
    else:
        system_prompt = f"""You are a Network Info Collector.
TASK: {base_strategy}
- Do not summarize or lose technical precision.

### OUTPUT FORMAT (MANDATORY):
[START]
Context:
<the relevant content here, verbatim>
[DONE]

CRITICAL RULES:
- You MUST output [START] and [DONE] tags. No exceptions.
- Between the tags, output ONLY content copied verbatim from the context.
- Do NOT answer the question.
"""

    feedback = state.get("feedback_to_collector", "")
    options_str = state.get('options', '')
    feedback_str = f"\n[Critic Feedback]: {feedback}" if feedback else ""

    if dataset_type == "multiple_choice":
        prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nOptions: {options_str}{feedback_str}"
    else:
        prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nContext: {state['context']}{feedback_str}"

    with gpu_lock():
        response, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='B')
    raw_res = _get_text(response)

    extracted = _extract_from_tags(raw_res)

    if len(extracted.strip()) < 30:
        logger.warning("[Collector][%s] Extraction too short (%d chars) → fallback to full context",
                       item_id, len(extracted.strip()))
        extracted = state["context"]

    logger.info(
        "[Collector][%s] DONE  | raw_data_len=%d chars | model_b tokens(in=%d out=%d) | preview=%.200s",
        item_id, len(extracted), in_tok, out_tok, extracted.replace('\n', '↵')
    )
    return {
        "raw_data": extracted,
        "outer_loop_count": state.get("outer_loop_count", 0) + 1,
        "token_usage": _add_tokens(state, "model_b", in_tok, out_tok),
    }


# ==========================================
# ✂️ Agent 2: Verifier Node (Scoring-based Relevance Checker)
# ==========================================

# 점수 기반 관련성 판단 기준
# 각 항목의 최대 점수 합계: 10점
# PASS 임계값: 6점 이상
VERIFIER_PASS_THRESHOLD = 6

VERIFIER_RUBRIC = """You are a Network Config Verifier. Score the Extracted Context against the Question using the rubric below.
Output ONLY a valid JSON object. No markdown, no preamble, no explanation outside the JSON.

## SCORING RUBRIC (total 10 points)

[C1] Device Match (0–3 pts)
  3 = The exact hostname(s) mentioned in the question appear in the extracted context.
  1 = Hostname is partially matched or unclear.
  0 = The extracted context is for a different device, or no hostname is present.
  - For TRACEROUTE/PATH/WHAT-IF questions (L4/L5): multiple device hostnames are expected.
    3 = At least 3 device hostnames are present in the extracted context.
    1 = Only 1–2 device hostnames are present.
    0 = No hostname found.

[C2] Feature / Command Presence (0–4 pts)
  4 = The specific command or configuration section asked about is present (e.g., "router bgp", "interface GigabitEthernet", "ip route", "clock timezone").
  2 = A related section exists but the specific command is missing.
  0 = The extracted context has no lines related to the feature asked.
  - IMPORTANT for TRACEROUTE/PATH/WHAT-IF questions (L4/L5):
    These questions require static routing configuration — NOT runtime command output.
    Do NOT expect or require "traceroute", "debug", "show" command outputs.
    4 = Routing-relevant config lines are present: "ip address", "ip route", "router ospf",
        "router bgp", "neighbor", "network", "mpls ip", or "route-target".
    2 = Some interface or IP address lines exist but routing protocol config is missing.
    0 = No routing-relevant lines at all.

[C3] Completeness (0–2 pts)
  - For TRACEROUTE/PATH/WHAT-IF questions (L4/L5):
      2 = The extracted context covers ALL devices listed in [All Devices] (if provided).
      1 = Some devices are missing from the extracted context.
      0 = Most devices are missing.
  - For AGGREGATE questions (containing "which device", "how many device", "all device", "what device", "each device"):
      2 = The extracted context covers ALL devices listed in [All Devices] (if provided).
      1 = Some devices are missing from the extracted context.
      0 = Most devices are missing.
  - For single-device questions:
      2 = The relevant configuration block is extracted completely (enough lines to answer the question).
      1 = Partial extraction — some relevant lines present but the block is truncated.
      0 = Only 1–2 lines, or the context is too sparse to answer the question.

[C4] Format Integrity (0–1 pt)
  1 = Output is raw config lines verbatim (not paraphrased into natural language).
  0 = The extracted context has been converted to sentences or summaries.

## OUTPUT FORMAT (strict JSON):
{
  "scores": {
    "C1_device_match": <0|1|3>,
    "C2_feature_presence": <0|2|4>,
    "C3_completeness": <0|1|2>,
    "C4_format_integrity": <0|1>
  },
  "total": <sum of scores, 0–10>,
  "failed_criteria": ["<C1|C2|C3|C4> reason", ...],
  "feedback": "<specific re-extraction instruction for the Collector if total < 6, else empty string>"
}"""

VERIFIER_RUBRIC_GENERAL = """You are a QA Verifier. Score the Extracted Context against the Question using the rubric below.
Output ONLY a valid JSON object. No markdown, no preamble, no explanation outside the JSON.

## SCORING RUBRIC (total 10 points)

[C1] Question Relevance (0–4 pts)
  4 = The extracted context directly contains information needed to answer the question.
  2 = The context is related to the topic but does not directly address the question.
  0 = The context is off-topic or unrelated to the question.

[C2] Key Information Coverage (0–4 pts)
  - For descriptive questions: coverage of concepts, causes, or explanations the question asks about.
    4 = All key concepts or explanations required to answer are present.
    2 = Some relevant content is present but important details are missing.
    0 = No relevant content for the question.
  - For short_answer questions: presence of the specific factual value (number, name, date, etc.).
    4 = The exact answer value or the sentence containing it is present in the context.
    2 = Related content exists but the precise answer value is not clearly stated.
    0 = The answer value is absent.
  - For multiple_choice questions: coverage of content related to the options (A, B, C, D).
    4 = The context contains information relevant to at least the correct option and one distractor.
    2 = Only partial option coverage (only one option addressed).
    0 = No content relevant to any option.

[C3] Completeness (0–1 pt)
  1 = The extracted context is sufficiently complete — not truncated mid-sentence or mid-paragraph.
  0 = The context is cut off or too sparse to be useful.

[C4] No Hallucination (0–1 pt)
  1 = The extracted context appears to be a faithful excerpt from the source (no fabricated content).
  0 = The context contains text that does not match the source or appears to be generated/paraphrased beyond recognition.

## OUTPUT FORMAT (strict JSON):
{
  "scores": {
    "C1_question_relevance": <0|2|4>,
    "C2_key_info_coverage": <0|2|4>,
    "C3_completeness": <0|1>,
    "C4_no_hallucination": <0|1>
  },
  "total": <sum of scores, 0–10>,
  "failed_criteria": ["<C1|C2|C3|C4> reason", ...],
  "feedback": "<specific re-extraction instruction for the Collector if total < 6, else empty string>"
}"""


def verifier_node(state: dict):
    """
    Collector가 추출한 raw_data를 점수 기반으로 관련성 검증한다.

    채점 항목 (총 10점, 임계값 6점):
        C1 Device Match       0/1/3점  — 질문의 장비가 추출 결과에 있는가
        C2 Feature Presence   0/2/4점  — 질문이 묻는 커맨드/섹션이 존재하는가
        C3 Completeness       0/1/2점  — 블록이 충분히 완전한가
        C4 Format Integrity   0/1점    — raw config 형태인가 (자연어 변환 아닌가)

    PASS (total >= 6): raw_data를 current_passage로 전달, verifier_status = "RELEVANT"
    FAIL (total <  6): feedback_to_collector에 실패 항목 기반 재추출 지시, verifier_status = "IRRELEVANT"

    상태 업데이트:
        verifier_status (str):       "RELEVANT" | "IRRELEVANT"
        current_passage (str):       raw_data 그대로 (RELEVANT일 때)
        feedback_to_collector (str): 재추출 지시사항 (IRRELEVANT일 때)
    """
    item_id  = state.get('id', '?')
    raw_data = state.get('raw_data', '').strip()
    logger.info("[Verifier][%s] START | raw_data_len=%d chars", item_id, len(raw_data))

    # 빈 값 → LLM 호출 없이 즉시 FAIL
    if not raw_data or raw_data == '[NONE]':
        logger.warning("[Verifier][%s] raw_data empty → IRRELEVANT (score: 0/10)", item_id)
        _feedback = "Extraction was empty. Re-identify the target device from the question and extract its full configuration block verbatim."
        _round = state.get("outer_loop_count", 0)
        return {
            "verifier_status": "IRRELEVANT",
            "current_passage": "",
            "feedback_to_collector": _feedback,
            "collector_retry_log": state.get("collector_retry_log", []) + [{"round": _round, "feedback": _feedback}],
        }

    if '[FEATURE_NOT_FOUND]' in raw_data:
        logger.info("[Verifier][%s] [FEATURE_NOT_FOUND] detected → RELEVANT (instant pass)", item_id)
        return {"verifier_status": "RELEVANT", "current_passage": raw_data}

    dataset_type = state.get("dataset_type", "descriptive")

    # gold context가 있는 타입(short_answer, descriptive)은 Verifier 채점 없이 즉시 통과
    if dataset_type in ("short_answer", "descriptive"):
        logger.info("[Verifier][%s] dataset_type=%s → RELEVANT (instant pass, gold context)", item_id, dataset_type)
        return {"verifier_status": "RELEVANT", "current_passage": raw_data}

    models = get_models()
    llm = models['A']

    # netconfig 타입은 설정 파일 전용 rubric, 나머지는 범용 rubric 사용
    if dataset_type in ("netconfig", "netconfig_topo"):
        rubric = VERIFIER_RUBRIC
        all_device_names = state.get("all_device_names", [])
        device_list_str = (
            f"\n[All Devices in Topology]: {', '.join(all_device_names)}"
            if all_device_names else ""
        )
        prompt = f"{rubric}\n\nQuestion: {state['question']}{device_list_str}\nExtracted Context:\n{raw_data}"
    else:
        rubric = VERIFIER_RUBRIC_GENERAL
        prompt = f"{rubric}\n\n[Question Type]: {dataset_type}\nQuestion: {state['question']}\nExtracted Context:\n{raw_data}"

    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"\nOptions: {options_str}"

    with gpu_lock():
        _resp, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='A')
    response = _get_text(_resp)

    # JSON 파싱
    scores = {}
    try:
        clean = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
        if clean.startswith("```"):
            clean = re.sub(r"^```[a-z]*\n?", "", clean).rstrip("```").strip()
        json_match = re.search(r'\{.*\}', clean, re.DOTALL)
        result = json.loads(json_match.group(0) if json_match else clean)

        scores   = result.get("scores", {})
        total    = int(result.get("total", 0))
        failed   = result.get("failed_criteria", [])
        feedback = result.get("feedback", "Re-extract the relevant device configuration block.")

    except Exception as e:
        logger.warning("[Verifier][%s] JSON parse failed: %s → defaulting to RELEVANT", item_id, e)
        total    = VERIFIER_PASS_THRESHOLD  # 파싱 실패 시 통과 처리 (안전 폴백)
        failed   = []
        feedback = ""

    passed = total >= VERIFIER_PASS_THRESHOLD
    # netconfig: C1_device_match / C2_feature_presence, 범용: C1_question_relevance / C2_key_info_coverage
    c1 = scores.get("C1_device_match", scores.get("C1_question_relevance", "?"))
    c2 = scores.get("C2_feature_presence", scores.get("C2_key_info_coverage", "?"))
    c3 = scores.get("C3_completeness", "?")
    c4 = scores.get("C4_format_integrity", scores.get("C4_no_hallucination", "?"))
    if passed:
        logger.info(
            "[Verifier][%s] PASS | score=%d/10 | C1=%s C2=%s C3=%s C4=%s",
            item_id, total, c1, c2, c3, c4,
        )
    else:
        logger.warning(
            "[Verifier][%s] FAIL | score=%d/10 | C1=%s C2=%s C3=%s C4=%s | failed=%s | feedback=%.200s",
            item_id, total, c1, c2, c3, c4, failed, feedback,
        )

    _tok_updated = _add_tokens(state, "model_a", in_tok, out_tok)

    if passed:
        return {
            "verifier_status": "RELEVANT",
            "current_passage": raw_data,
            "feedback_to_collector": "",
            "token_usage": _tok_updated,
        }
    else:
        _round = state.get("outer_loop_count", 0)
        return {
            "verifier_status": "IRRELEVANT",
            "current_passage": "",
            "feedback_to_collector": feedback,
            "collector_retry_log": state.get("collector_retry_log", []) + [{"round": _round, "feedback": feedback}],
            "token_usage": _tok_updated,
        }


# ==========================================
# 💡 Agent 3: Synthesizer Node
# ==========================================
def synthesizer_node(state: dict):
    """
    Verifier가 정제한 패시지(current_passage)를 기반으로 최종 후보 답변을 생성한다.

    데이터셋 타입별 출력 형식:
    - descriptive:     1-2문장의 기술적 설명
    - short_answer:    컨텍스트에서 정확히 추출한 값 (패라프레이징 금지)
    - multiple_choice: "option N: [답변 텍스트]" 형식
    - netconfig:       answer_type에 맞는 형식 (text/numeric/set/map/bool/ip)
                       정보 없으면 타입별 기본값 반환 (null/0/[]/{}/ false/"No path")

    상태 업데이트:
        candidate_answer (str): 생성된 후보 답변
        debate1_answer (str):   1차 토론 답변 스냅샷 (나중에 비교용)
    """
    item_id      = state.get('id', '?')
    inner_turn   = state.get('inner_turn_count', 0)
    dataset_type = state.get("dataset_type", "descriptive")
    passage_len  = len(state.get('current_passage', ''))
    sfb          = state.get('synthesizer_feedback', '')
    logger.info(
        "[Synthesizer][%s] START | inner_turn=%d | passage_len=%d chars | has_feedback=%s",
        item_id, inner_turn, passage_len, bool(sfb)
    )
    if sfb:
        logger.info("[Synthesizer][%s] Critic feedback: %.300s", item_id, sfb)
    models = get_models()
    llm = models['A']

    # 데이터셋별 답변 생성 규칙 프롬프트
    PROMPTS = {
        "descriptive": """You are a Network Info Synthesizer for descriptive questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",

        "short_answer": """You are an extractive QA model.
TASK: Extract the shortest exact span from the passage that directly answers the question.

RULES:
1. Copy the MINIMUM span verbatim — the shortest text that directly and completely answers the question.
2. Do NOT output a full sentence if the answer is a phrase or clause. Trim surrounding subject/verb.
   - "when?" → output only the temporal phrase  (e.g., "after the completion of X")
   - "what?" → output only the noun phrase       (e.g., "an IUR-ENHANCED-RELOCATION-FAILURE message to RNS-A")
   - "who?"  → output only the entity name       (e.g., "RNS-B")
3. Do NOT add or remove articles (a/an/the), leading pronouns (it/they), or any word not in the passage.
4. Do NOT paraphrase — use exact wording from the passage, character for character.
5. Do NOT add explanation, reasoning, or any text outside the extracted span.
6. If the answer requires a destination or recipient (e.g., "to RNS-A"), include it.
7. Output ONLY the extracted span — nothing else.""",

        "multiple_choice": """You are a Network Info Synthesizer for multiple-choice questions.
TASK: Answer the question based on the provided passage and your expert knowledge.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.). If the passage conflicts with established standards, trust the standards.
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in your answer.
5. You MUST always select one of the provided options. Never output an empty string.""",

        "netconfig": """You are a Network Info Synthesizer for short-answer questions.
        TASK:
    1. Search the Context for the specific value requested.
    2. If the Context is "[NONE]" or the information is not found, the Passage must be "[NONE]".
    If the passage is [NONE] or you cannot find accurate information, answer [NONE]

    Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. output the raw answer value in ONE line:
   - text type: Output the EXACT value as it appears in the config. PRESERVE original case (e.g., "Leaf1" not "leaf1", "PE1" not "pe1").
     * Feature absent/disabled: If the feature command is NOT present in the config (e.g., no `clock timezone` command → timezone is null; `no aaa new-model` or no `aaa authentication` command → AAA is "not set"). Do NOT hallucinate default values (e.g., do NOT output "UTC" for timezone, do NOT output "local" for AAA auth if the command is missing).
     * If "[FEATURE_NOT_FOUND]" is in the passage, output: not set
     * If the feature is explicitly negated (e.g., "no aaa new-model"), output: not configured
     * NETWORK PATH questions (e.g., "list the path from X to Y", "order of devices"): Output ONLY device hostnames separated by → (e.g., "pe2→p3→p2→pe1"). Use EXACT hostname case from configs. Do NOT include IP addresses. If destination is directly reachable from source (single hop), output just the source device name (e.g., "pe2"). If no route exists at all, output: No path
     * LINK FAILURE / CONNECTIVITY questions (e.g., "The 'X-Y' link ... is down. Is it possible to communicate..."): Output EXACTLY "Possible" OR "Impossible (Reason: <FAILURE_TYPE> at <device>)". Example: "Impossible (Reason: NO_ROUTE at pe1)". Do NOT output "true", "false", "yes", "no".
     * AGGREGATE questions (e.g., "device with the most/fewest interfaces", "BGP AS numbers of all devices", "iBGP Full-Mesh status"): Compute the answer across ALL device configs in the passage and format as specified in the question (e.g., "pe1: AS 65000, pe2: AS 65000" or "OK").
     * If the question is about the leaf and there is none, output: (e.g. "leafX: AS None")
   - numeric/number type: Count carefully using these rules:
     * Interface count: Count ALL interface entries in the config (GigabitEthernet, FastEthernet, Loopback, Tunnel, etc.) — do NOT skip any interface type. Each "interface X" line = 1 interface.
     * Routing table entries: Count ALL route sources — each "network" statement + each "ip route" (static) + each redistributed protocol block. Connected interfaces also contribute routes.
     * Route Target count: Count BOTH "route-target import" AND "route-target export" lines together (NOT just one direction).
     * VRF count: Count all "vrf definition X" or "ip vrf X" blocks.
     * BGP AS number: Extract the number directly after "router bgp" (e.g., "router bgp 65000" → 65000). This is a single value, not a count.
     * Hop count (path from A to B): Trace the path step by step using next-hop / neighbor information across all device configs in the passage. Count each intermediate device as 1 hop.
     * Output ONLY the final integer or decimal. No units, no explanation.
   - set type: JSON array format (e.g., ["item1", "item2"])
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., ["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]
   - map type: JSON object format. Build the map by enumerating ALL interfaces. Apply these inference rules:
     * Interface STATUS map: if "shutdown" is present → "down", if absent or "no shutdown" → "up"
     * VRF BINDING map: if "ip vrf forwarding X" is present → X, if absent → "default" (every interface not explicitly assigned is in the default VRF)
     * IP ADDRESS map: if "ip address A.B.C.D M.M.M.M" → "A.B.C.D/prefix", if absent → "" (empty string)
     * Route-target/VRF map: extract key-value pairs explicitly from config
     * NEVER output "unknown" or "null" as a value — apply the inference rules above instead.
     * Include ALL interfaces (GigabitEthernet, Loopback, etc.). Do NOT skip interfaces.
     * Empty map {} is forbidden — if passage is relevant, you MUST enumerate the interfaces.
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., {"GigabitEthernet0/0": "...", "GigabitEthernet0/1": "...", "Loopback0": "..."}
   - boolean type: true or false
   - ip type: example: "ip address 172.16.1.2 255.255.255.0" -> Output: "172.16.1.2/24". If there is a Loopback interface, use the Loopback IP and list it LAST. If there's no Setting: "GigabitEthernet0/0: "

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.

3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set, list: []
   - map: {}
   - boolean: false
   - path: No path
   """,

        "netconfig_topo": """You are a Network Routing Simulator. Your task is to answer L4/L5 network analysis questions by simulating routing behavior from static device configurations.

CONTEXT: You are given the complete configuration of ALL devices in the network topology. Use them to simulate routing.

# SIMULATION RULES:
1. ROUTING PATH (L4) — "list the path from X to Y":
   - Start at the SOURCE device. Check its routing table (static routes: "ip route", dynamic: BGP/OSPF neighbors, default route: "ip route 0.0.0.0 0.0.0.0 <next-hop>").
   - Identify which interface the next-hop IP belongs to, and which device is connected on that subnet.
   - Repeat hop-by-hop until you reach the destination IP or hit a dead end.
   - Output: device hostnames separated by → (e.g., "leaf2→pe1→p2→p3"). Use EXACT hostname case. Do NOT include IPs.
   - If no route exists to reach the destination: output "No path"
   - If destination IP belongs to an interface of a directly connected device: that device is the last hop.

2. WHAT-IF / FAULT ANALYSIS (L5) — "when link X-Y fails / device X is down":
   Follow these steps IN ORDER before writing the answer:

   [Step 1] Build the normal topology.
   - List every device and its active interfaces with IP/subnet.
   - List every routing entry (static "ip route", BGP neighbor, OSPF network) per device.

   [Step 2] Identify the normal path from source to destination.
   - Trace hop-by-hop using the routing tables built in Step 1.
   - Write the path as: src→...→dst

   [Step 3] Apply the failure.
   - Remove the specified link (both directions) or device from the topology.
   - Mark all interfaces/routes that become unavailable as a result.

   [Step 4] Re-trace the path after failure.
   - Starting from the source again, follow routing tables with the failed components removed.
   - If a device has no valid next-hop toward the destination → it has NO_ROUTE.
   - If an alternative path exists via a different next-hop → trace it fully.

   [Step 5] Determine the answer.
   - Blocking device: the first device in the path that has NO_ROUTE after failure.
   - Connectivity: "Possible (Alternative route: X→Y→Z)" if alternative path found, else "Impossible (Reason: NO_ROUTE at <device>)".
   - Count: count the number of affected routes/devices.

   [Step 6] Output ONE LINE — the final answer only (no steps, no explanation).


# Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. output the raw answer value in ONE line:
   - text type: Output the EXACT value as it appears in the config. PRESERVE original case (e.g., "Leaf1" not "leaf1", "PE1" not "pe1").
     * Feature absent/disabled: If the feature command is NOT present in the config (e.g., no `clock timezone` command → timezone is null; `no aaa new-model` or no `aaa authentication` command → AAA is "not set"). Do NOT hallucinate default values (e.g., do NOT output "UTC" for timezone, do NOT output "local" for AAA auth if the command is missing).
     * If "[FEATURE_NOT_FOUND]" is in the passage, output: not set
     * If the feature is explicitly negated (e.g., "no aaa new-model"), output: not configured
     * NETWORK PATH questions (e.g., "list the path from X to Y", "order of devices"): Output ONLY device hostnames separated by → (e.g., "pe2→p3→p2→pe1"). Use EXACT hostname case from configs. Do NOT include IP addresses. If destination is directly reachable from source (single hop), output just the source device name (e.g., "pe2"). If no route exists at all, output: No path
     * LINK FAILURE / CONNECTIVITY questions (e.g., "The 'X-Y' link ... is down. Is it possible to communicate..."): Output EXACTLY "Possible" OR "Impossible (Reason: <FAILURE_TYPE> at <device>)". Example: "Impossible (Reason: NO_ROUTE at pe1)". Do NOT output "true", "false", "yes", "no".
     * AGGREGATE questions (e.g., "device with the most/fewest interfaces", "BGP AS numbers of all devices", "iBGP Full-Mesh status"): Compute the answer across ALL device configs in the passage and format as specified in the question (e.g., "pe1: AS 65000, pe2: AS 65000" or "OK").
     * If the question is about the leaf and there is none, output: (e.g. "leafX: AS None")
   - numeric/number type: Count carefully using these rules:
     * Interface count: Count ALL interface entries in the config (GigabitEthernet, FastEthernet, Loopback, Tunnel, etc.) — do NOT skip any interface type. Each "interface X" line = 1 interface.
     * Routing table entries: Count ALL route sources — each "network" statement + each "ip route" (static) + each redistributed protocol block. Connected interfaces also contribute routes.
     * Route Target count: Count BOTH "route-target import" AND "route-target export" lines together (NOT just one direction).
     * VRF count: Count all "vrf definition X" or "ip vrf X" blocks.
     * BGP AS number: Extract the number directly after "router bgp" (e.g., "router bgp 65000" → 65000). This is a single value, not a count.
     * Hop count (path from A to B): Trace the path step by step using next-hop / neighbor information across all device configs in the passage. Count each intermediate device as 1 hop.
     * Output ONLY the final integer or decimal. No units, no explanation.
   - set type: JSON array format (e.g., ["item1", "item2"])
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., ["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]
   - map type: JSON object format. Build the map by enumerating ALL interfaces. Apply these inference rules:
     * Interface STATUS map: if "shutdown" is present → "down", if absent or "no shutdown" → "up"
     * VRF BINDING map: if "ip vrf forwarding X" is present → X, if absent → "default" (every interface not explicitly assigned is in the default VRF)
     * IP ADDRESS map: if "ip address A.B.C.D M.M.M.M" → "A.B.C.D/prefix", if absent → "" (empty string)
     * Route-target/VRF map: extract key-value pairs explicitly from config
     * NEVER output "unknown" or "null" as a value — apply the inference rules above instead.
     * Include ALL interfaces (GigabitEthernet, Loopback, etc.). Do NOT skip interfaces.
     * Empty map {} is forbidden — if passage is relevant, you MUST enumerate the interfaces.
     * ORDERING: List physical interfaces first (GigabitEthernet, FastEthernet, etc.), Loopback interfaces LAST.
       e.g., {"GigabitEthernet0/0": "...", "GigabitEthernet0/1": "...", "Loopback0": "..."}
   - boolean type: true or false
   - ip type: example: "ip address 172.16.1.2 255.255.255.0" -> Output: "172.16.1.2/24". If there is a Loopback interface, use the Loopback IP and list it LAST. If there's no Setting: "GigabitEthernet0/0: "

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.

3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set, list: []
   - map: {}
   - boolean: false
   - path: No path
"""
    }

    # L4/L5는 토폴로지 시뮬레이션 전략 사용
    level = state.get("level", "")
    if dataset_type == "netconfig" and level in ("L4", "L5"):
        effective_type = "netconfig_topo"
    else:
        effective_type = dataset_type

    base_system = PROMPTS.get(effective_type, PROMPTS["descriptive"])
    system_prompt = base_system + """
### OUTPUT FORMAT:
[START]
Answer:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nOptions: {state.get('options', 'N/A')}\nContext (Passage): {state.get('current_passage', '')}"
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    # Critic의 재생성 지시가 있으면 (REVISE 루프) 프롬프트에 포함
    synthesizer_feedback = state.get("synthesizer_feedback", "")
    if synthesizer_feedback:
        # 이전 라운드 답변 이력 구성 — 같은 답 반복 방지
        prev_answers = state.get("candidate_answers", [])
        if prev_answers:
            history_lines = "\n".join(
                f"  Round {entry['round']}: \"{entry['answer']}\" → REVISE"
                for entry in prev_answers
            )
            history_str = f"\n\n[Answer History - DO NOT repeat any of these]:\n{history_lines}"
        else:
            history_str = ""
        prompt += (
            f"{history_str}"
            f"\n\n[Critic Feedback - Revise your answer based on this critique]:\n{synthesizer_feedback}"
            f"\nDo NOT repeat any previously rejected answer. Fix the specific issue described above."
        )

    with gpu_lock():
        _resp, in_tok, out_tok = invoke_with_tokens(llm, prompt, role='A')
    response = _get_text(_resp)
    # "Answer:" 레이블을 제거하고 순수 답변 값만 추출
    answer_val = _extract_from_tags(response)

    round_num = state.get("inner_turn_count", 0) + 1
    logger.info(
        "[Synthesizer][%s] DONE | round=%d | model_a tokens(in=%d out=%d) | candidate_answer=%.300s",
        item_id, round_num, in_tok, out_tok, answer_val
    )
    return {
        "candidate_answer": answer_val,
        "debate1_answer": answer_val,
        "candidate_answers": state.get("candidate_answers", []) + [{"round": round_num, "answer": answer_val}],
        "token_usage": _add_tokens(state, "model_a", in_tok, out_tok),
    }
