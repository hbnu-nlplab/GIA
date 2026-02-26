import re
from agents_v2.model_loader import get_models

def _get_text(response):
    return response.content if hasattr(response, 'content') else str(response)

# --- [수정] 모든 레이블(Context, Passage, Answer)을 처리하는 파싱 함수 ---
def _extract_from_tags(text: str, start_tag="[START]", end_tag="[DONE]") -> str:
    print("=" * 100)
    print("Full Content:", text)
    
    # 2번째 [START] 찾기 로직
    start_parts = text.split(start_tag)
    
    target_content = ""
    if len(start_parts) >= 3:
        # [START]가 2개 이상이면 2번째 [START] 이후의 내용을 취함
        target_content = start_parts[2]
    elif len(start_parts) == 2:
        # [START]가 1개뿐이면 그거라도 취함
        target_content = start_parts[1]
    else:
        # [START]가 없으면 전체 사용
        target_content = text

    # [DONE] 이전까지만 사용
    if end_tag in target_content:
        target_content = target_content.split(end_tag)[0]
        
    target_content = target_content.strip()
    
    print("-" * 50)
    print("Target Content for Parsing:", target_content)

    cleaned = re.sub(r"^\s*(Context|Passage|Answer|Result)\s*:\s*", "", target_content, flags=re.IGNORECASE | re.MULTILINE)
    cleaned = cleaned.strip()
    
    print("=" * 100)
    print("Parsed Content:", cleaned)
    
    return cleaned

# ==========================================
# 🕵️ Agent 1: Collector Node
# ==========================================
def collector_node(state: dict):
    print(f"\n🕵️ [Agent 1: Collector] Strategy for: {state.get('dataset_type')}")
    models = get_models()
    llm = models.get('B', models['A']) 
    dataset_type = state.get("dataset_type", "descriptive")

    # Agent 1용 데이터셋별 수집 전략 프롬프트
    COLLECTOR_PROMPTS = {
        "descriptive": """Focus on gathering comprehensive technical explanations and cause-effect relationships from the context.""",

        "short_answer": """Focus on finding the exact sentence or paragraph that contains the specific factual answer. Do not miss technical values. Do not rephrase the sentence; copy the relevant content directly from the context.""",

        "multiple_choice": "Identify and extract all parts of the context that relate to the provided options (A, B, C, D) to compare them.",

        "netconfig": """First find the device(or hostname) related to the question then, extract the configuration of that device. Strictly identify the target device's configuration block. Do not add any additional information.
        1. Locate the block starting with '[{state.get('target_device', 'TARGET')}.cfg]'.
        2. Search for the requested value (e.g., BSP, Hostname, IP) STRICTLY within that block first.
        3. If and only if the answer depends on a neighbor's IP or route, search other blocks, but clearly label them.
        4. If the target block exists but the specific setting is missing, do not borrow a similar setting from another device. Just report missing."""
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

    feedback = state.get("feedback_to_collector", "")
    options_str = state.get('options', '')
    feedback_str = f"\n[Critic Feedback]: {feedback}" if feedback else ""
    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nContext: {state['context']}"
    # print(" +++++++++++++ given context: ", state['context'][:100])

    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"
    response = llm.invoke(prompt)
    raw_res = _get_text(response)
    
    # [중요] 여기서 즉시 파싱하여 raw_data에 'Context:'가 없는 순수 데이터만 저장
    extracted = _extract_from_tags(raw_res)
    
    # outer_loop_count를 증가시켜 루프 제어
    return {
        "raw_data": extracted,
        "outer_loop_count": state.get("outer_loop_count", 0) + 1
    }

# ==========================================
# ✂️ Agent 2: Verifier Node
# ==========================================
def verifier_node(state: dict):
    print("✂️ [Agent 2: Verifier] Cleaning irrelevant data...")
    models = get_models()
    llm = models['A']

    system_prompt = """You are a Network Info Verifier.
TASK: Remove noise from the 'Extracted Context'.
- Keep only the technical facts directly required to answer the question.
- If the Collector provided unrelated device info, delete it.
- Maintain the original wording for the remaining parts.
- Don't answer the question. Just remove the noise.

### OUTPUT FORMAT:
[START]
Passage:
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nExtracted Context: {state.get('raw_data', '')}"
    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"
    response = _get_text(llm.invoke(prompt))
    refined = _extract_from_tags(response)
    return {"current_passage": refined}

# ==========================================
# 💡 Agent 3: Synthesizer Node
# ==========================================
def synthesizer_node(state: dict):
    print("💡 [Agent 3: Synthesizer] Generating Answer...")
    models = get_models()
    llm = models['A']
    dataset_type = state.get("dataset_type", "descriptive")

    # 데이터셋별 정답 생성 규칙 (Rules)
    PROMPTS = {
        "descriptive": """You are a Network Info Collector for descriptive questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",

        "short_answer": """You are a Network Info Collector for short-answer questions.
TASK: Answer the question based on the provided passage.
        
RULES:
1. Find the exact answer span in the context.
2. Output ONLY the extracted text in answer - no explanations, no reasoning, no thoughts.
3. Do NOT paraphrase - use exact wording from context.
4. If the answer is a value with a unit, include both.""",

        "multiple_choice": """You are a Network Info Collector for multiple-choice questions.
TASK: Answer the question based on the provided passage.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.).
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in answer.""",

        "netconfig": """You are a Network Info Collector for short-answer questions.
        TASK:
    1. Search the Context for the specific value requested.
    2. If the Context is "[NONE]" or the information is not found, the Passage must be "[NONE]". 
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

### INSTRUCTIONS:
- If the passage is [NONE] or you cannot find accurate information, answer [NONE].

### OUTPUT FORMAT:
[START]
Answer: 
[DONE]"""

    prompt = f"{system_prompt}\n\nQuestion: {state['question']}\nOptions: {state.get('options', 'N/A')}\nContext (Passage): {state.get('current_passage', '')}"
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"
        
    response = _get_text(llm.invoke(prompt))
    # [중요] 'Answer:' 레이블을 떼고 정답만 추출
    answer_val = _extract_from_tags(response)

    return {
        "candidate_answer": answer_val,
        "debate1_answer": answer_val
    }


