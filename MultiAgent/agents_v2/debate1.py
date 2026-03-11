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
from agents_v2.model_loader import get_models
import threading

# GPU 접근 직렬화를 위한 전역 락 (로컬 모드에서 동시 GPU 접근 방지)
gpu_lock = threading.Lock()


def _get_text(response):
    """LangChain 응답 객체 또는 일반 문자열에서 텍스트 내용만 안전하게 추출한다."""
    return response.content if hasattr(response, 'content') else str(response)


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
    print("=" * 100)
    print("Full Content:", text)

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

    print("-" * 50)
    print("Target Content for Parsing:", target_content)

    # Step 4: "Context:", "Passage:", "Answer:", "Result:" 등 레이블 헤더 제거
    cleaned = re.sub(r"^\s*(Context|Passage|Answer|Result)\s*:\s*", "", target_content,
                     flags=re.IGNORECASE | re.MULTILINE)
    cleaned = cleaned.strip()

    print("=" * 100)
    print("Parsed Content:", cleaned)

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
    print(f"\n🕵️ [Agent 1: Collector] Strategy for: {state.get('dataset_type')}")
    models = get_models()
    llm = models.get('B', models['A'])  # B 모델 우선 사용, 없으면 A 폴백
    dataset_type = state.get("dataset_type", "descriptive")

    # 데이터셋 타입별 수집 전략 프롬프트
    COLLECTOR_PROMPTS = {
        "descriptive": """Focus on gathering comprehensive technical explanations and cause-effect relationships from the context.""",

        "short_answer": """Focus on finding the exact sentence or paragraph that contains the specific factual answer. Do not miss technical values. Do not rephrase the sentence; copy the relevant content directly from the context.""",

        "multiple_choice": "Identify and extract all parts of the context that relate to the provided options (A, B, C, D) to compare them.",

        "netconfig": """
1. Target Identification: Identify the EXACT device (hostname) mentioned in the question.
2. Direct Extraction: Extract the raw configuration lines of that device only.
3. Strict Boundary: Start from the hostname declaration and include all relevant parameters for that specific device block.
4. No Paraphrasing: DO NOT convert the configuration into natural language sentences.
5. No Additions: Do not add any commentary, explanations, or metadata.
6. Format: Output ONLY the raw configuration text as it appears in the source.

Write [NONE] if you cannot write a answer.
"""
    }

    base_strategy = COLLECTOR_PROMPTS.get(dataset_type, COLLECTOR_PROMPTS["descriptive"])

    system_prompt = f"""You are a Network Info Collector.
TASK: {base_strategy}
- Extract all relevant information VERBATIM.
- Do not summarize or lose technical precision.

### OUTPUT FORMAT:
[START]
Context:
[DONE]"""

    # Critic으로부터 받은 피드백이 있으면 프롬프트에 포함 (재수집 루프)
    feedback = state.get("feedback_to_collector", "")
    options_str = state.get('options', '')
    feedback_str = f"\n[Critic Feedback]: {feedback}" if feedback else ""
    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nContext: {state['context']}"

    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    # GPU 락을 사용하여 동시 접근 방지 (로컬 모드에서 필요)
    with gpu_lock:
        response = llm.invoke(prompt)
    raw_res = _get_text(response)

    # 즉시 파싱하여 "Context:" 레이블이 없는 순수 데이터만 저장
    extracted = _extract_from_tags(raw_res)

    return {
        "raw_data": extracted,
        "outer_loop_count": state.get("outer_loop_count", 0) + 1  # 외부 루프 카운터 증가
    }


# ==========================================
# ✂️ Agent 2: Verifier Node
# ==========================================
def verifier_node(state: dict):
    """
    Collector가 추출한 원시 정보(raw_data)에서 질문과 무관한 줄을 제거한다.

    핵심 규칙:
    - 원본 텍스트를 한 글자도 수정하지 않음 (파라프레이징 금지)
    - 관련 있는 줄은 그대로 유지, 무관한 줄만 삭제
    - 출력은 요약이 아닌 원시 설정 라인들의 집합

    상태 업데이트:
        current_passage (str): 정제된 패시지 (Synthesizer에서 사용)
    """
    print("✂️ [Agent 2: Verifier] Cleaning irrelevant data...")
    models = get_models()
    llm = models['A']

    system_prompt = """You are a Network Info Verifier.
TASK: Filter irrelevant lines from the 'Extracted Context'.

RULES:
1. STRICT RESTRAINT: Do NOT change a single character of the original text.
2. DO NOT paraphrase. DO NOT create sentences.
3. If a line is irrelevant to the device or question, DELETE the entire line.
4. If a line is relevant, KEEP it exactly as it is (Raw Config Format).
5. Output must be a collection of RAW CONFIGURATION LINES, not a summary.

Write [NONE] if you cannot write a answer.

### OUTPUT FORMAT:
[START]
Passage:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nExtracted Context: {state.get('raw_data', '')}"
    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    with gpu_lock:
        response = _get_text(llm.invoke(prompt))
    refined = _extract_from_tags(response)
    return {"current_passage": refined}


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
    print("💡 [Agent 3: Synthesizer] Generating Answer...")
    models = get_models()
    llm = models['A']
    dataset_type = state.get("dataset_type", "descriptive")

    # 데이터셋별 답변 생성 규칙 프롬프트
    PROMPTS = {
        "descriptive": """You are a Network Info Synthesizer for descriptive questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",

        "short_answer": """You are a Network Info Synthesizer for short-answer questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Find the exact answer span in the context.
2. Output ONLY the extracted text in answer - no explanations, no reasoning, no thoughts.
3. Do NOT paraphrase - use exact wording from context.
4. If the answer is a value with a unit, include both.
5. You must answer using the information provided in the passage.""",

        "multiple_choice": """You are a Network Info Synthesizer for multiple-choice questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.).
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in answer.""",

        "netconfig": """You are a Network Info Synthesizer for short-answer questions.
        TASK:
    1. Search the Context for the specific value requested.
    2. If the Context is "[NONE]" or the information is not found, the Passage must be "[NONE]".
    If the passage is [NONE] or you cannot find accurate information, answer [NONE]

    Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. output the raw answer value in ONE line:
   - text type: Just the text value (e.g., "R1" or "10.0.0.1")
   - numeric/number type: Just the number (e.g., 5 or 10.5)
   - set type: JSON array format (e.g., ["item1", "item2"])
   - map type: JSON object format (e.g., {"key": "value"})
   - boolean type: true or false
   - ip type: example: "ip address 172.16.1.2 255.255.255.0" -> Output: "172.16.1.2/24"

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

    base_system = PROMPTS.get(dataset_type, PROMPTS["descriptive"])
    system_prompt = base_system + """
### OUTPUT FORMAT:
[START]
Answer:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nOptions: {state.get('options', 'N/A')}\nContext (Passage): {state.get('current_passage', '')}"
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    with gpu_lock:
        response = _get_text(llm.invoke(prompt))
    # "Answer:" 레이블을 제거하고 순수 답변 값만 추출
    answer_val = _extract_from_tags(response)

    return {
        "candidate_answer": answer_val,
        "debate1_answer": answer_val  # 1차 답변 스냅샷 저장
    }
