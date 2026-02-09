from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage
from .model_loader import get_models
import re
models = get_models()

def get_content(res):
    """Safe extraction of content from either string or AIMessage."""
    if isinstance(res, str):
        return res
    if hasattr(res, 'content'):
        return res.content
    return str(res)


def parse_response(content):
    content = get_content(content)
    print("=" * 100)
    print("Full Content:", content) 
    
    # 2번째 [START] 찾기 로직
    start_parts = content.split("[START]")
    
    target_content = ""
    if len(start_parts) >= 3:
        # [START]가 2개 이상이면 2번째 [START] 이후의 내용을 취함
        target_content = start_parts[2]
    elif len(start_parts) == 2:
        # [START]가 1개뿐이면 그거라도 취함
        target_content = start_parts[1]
    else:
        # [START]가 없으면 전체 사용
        target_content = content

    # [DONE] 이전까지만 사용
    if "[DONE]" in target_content:
        target_content = target_content.split("[DONE]")[0]
        
    target_content = target_content.strip()
    
    print("-" * 50)
    print("Target Content for Parsing:", target_content)

    # Passage: 와 Answer: 패턴 찾기
    pattern = re.compile(
        r"Passage:\s*(.*?)\s*Answer:\s*(.*)",
        re.DOTALL | re.IGNORECASE
    )

    m = pattern.search(target_content)
    
    passage = ""
    answer = ""

    if m:
        passage = m.group(1).strip()
        answer = m.group(2).strip()
    else:
        if "Answer:" in target_content:
            parts = target_content.split("Answer:")
            answer = parts[-1].strip()
            if "Passage:" in parts[0]:
                passage = parts[0].split("Passage:")[-1].strip()

    print("=" * 100)
    print("Parsed Passage:", passage)
    print("Parsed Answer:", answer)

    return passage, answer


def collector_node(state):
    dataset_type = state.get('dataset_type', 'descriptive')
    print(f"   [D1] Round {state['round_count']+1}: Collector gathering details ({dataset_type})...")
    
    # --- Prompt Definitions ---
    PROMPTS = {
        "descriptive": """You are a Network Info Collector for descriptive questions.
TASK: Construct current passage included the answer then, answer the question based on the passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your passage and answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",
        

        "short_answer": """You are a Network Info Collector for short-answer questions.
        TASK: Construct current passage included the answer then, answer the question based on the passage.
        
RULES:
1. Find the exact answer span in the context.
2. Output ONLY the extracted text in answer

- no explanations, no reasoning, no thoughts.
3. Do NOT paraphrase - use exact wording from context.
4. If the answer is a value with a unit, include both.""",
        

        "multiple_choice": """You are a Network Info Collector for multiple-choice questions.

        TASK: Construct current passage included the answer then, answer the question based on the passage.

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

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.
   
   
3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set: []
   - map: {}
   - boolean: false
   - If there is no route, answer ‘경로 없음’. """
}

    base_system = PROMPTS.get(dataset_type, PROMPTS["descriptive"])
    system_prompt = base_system + """

### INSTRUCTIONS:
- Do not write a passage if you don’t know accurate information about the question. Write [NONE] if you cannot write a factual good passage. (ex. Passage: [NONE])  

### OUTPUT FORMAT:
[START]
Passage:
Answer:
[DONE]
"""

    options_str = state.get('options', '')
    user_prompt = f"Question: {state['question']}\n"
    if dataset_type == "multiple_choice" and options_str:
        user_prompt += f"Options: {options_str}\n"
    user_prompt += f"Context: {state.get('context', '')}\n"
    user_prompt += f"Current Passage: {state['current_passage']}"

    res = models['A'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    p, a = parse_response(res)
    return {"current_passage": p, "candidate_answer": a}



def verifier_node(state):
    dataset_type = state.get('dataset_type', 'descriptive')
    print(f"   [D1] Round {state['round_count']+1}: Verifier checking facts ({dataset_type})...")
    
    PROMPTS = {
        "descriptive": """You are a Network Info Verifier for descriptive questions.
TASK: Scrutinize current passage that included the gold answer for errors then, answer the question based on the passage.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your passage and answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",
        

        "short_answer": """You are a Network Info Verifier for short-answer questions.
        TASK: Compare the correct passage and the candidate answers with the context to check for errors. If errors are found, output the corrected passage and the correct answer.
        
RULES:
1. Find the exact answer span in the context.
2. Output ONLY the extracted text in answer - no explanations, no reasoning, no thoughts.
3. Do NOT paraphrase - use exact wording from context.
4. If the answer is a value with a unit, include both.""",
        

        "multiple_choice": """You are a Network Info Verifier for multiple-choice questions.

        TASK: Compare the correct passage and the candidate answers to check for errors. If errors are found, output the corrected passage and the correct answer.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.).
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in answer. """,

        "netconfig": """You are a Network Info Verifier for short-answer questions.
    TASK: You must find the answer in the given context. Compare the correct passage, context and the candidate answers to check for errors. If errors are found, output the corrected passage and the correct answer.
    
    Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):
1. output the raw answer value in ONE line:
   - text type: Just the text value (e.g., "R1" or "10.0.0.1")
   - numeric/number type: Just the number (e.g., 5 or 10.5)
   - set type: JSON array format (e.g., ["item1", "item2"])
   - map type: JSON object format (e.g., {"key": "value"})
   - boolean type: true or false

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.
   
   
3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set: []
   - map: {}
   - boolean: false"""
    }

    base_system = PROMPTS.get(dataset_type, PROMPTS["descriptive"])
    system_prompt = base_system + """

### INSTRUCTIONS:
- Do not write a passage if you don’t know accurate information about the question. Write [NONE] if you cannot write a factual good passage. (ex. Passage: [NONE])  

### OUTPUT FORMAT:
[START]
Passage:
Answer:
[DONE]
"""

    options_str = state.get('options', '')
    user_prompt = f"Question: {state['question']}\n"
    if dataset_type == "multiple_choice" and options_str:
        user_prompt += f"Options: {options_str}\n"
    user_prompt += f"Context: {state.get('context', '')}\n"
    user_prompt += f"Current Passage: {state['current_passage']}\n"
    user_prompt += f"Candidate Answer: {state.get('candidate_answer', '')}"
    
    res = models['B'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    p, a = parse_response(res)
    return {"current_passage": p, "candidate_answer": a}


def synthesizer_node(state):
    dataset_type = state.get('dataset_type', 'descriptive')
    print(f"   [D1] Round {state['round_count']+1}: Synthesizer summarizing & answering ({dataset_type})...")
    
    PROMPTS = {
        "descriptive": """You are a Network Info Synthesizer for descriptive questions.
TASK: Consolidate the passage into a clear context and write the answer.

RULES:
1. Provide a complete technical answer in 1-2 sentences that includes both the direct answer and the technical reasoning.
2. Output ONLY your passage and answer. Do NOT include any meta-commentary like "analysis:", "thought:", or "reasoning:".
3. If the answer involves configurations, include the exact syntax (CLI, YAML, etc.) along with a brief explanation.
4. Match the expert-level depth and completeness expected in professional network engineering documentation.""",
        

        "short_answer": """You are a Network Info Synthesizer for short-answer questions.
        TASK: Consolidate the passage into a clear context and write the answer.
        
RULES:
1. Find the exact answer span in the context.
2. Output ONLY the extracted text in answer - no explanations, no reasoning, no thoughts.
3. Do NOT paraphrase - use exact wording from context.
4. If the answer is a value with a unit, include both.""",
        

        "multiple_choice": """You are a Network Info Synthesizer for multiple-choice questions.

        TASK: Consolidate the passage into a clear context and write the answer.

RULES:
1. Select the single best answer from the given options.
2. Use your expert knowledge of telecom standards (3GPP, IEEE, etc.).
3. Output your answer in this exact format: "option N: [answer text]"
4. Do NOT include any reasoning, thoughts, or explanations in answer.""",

        "netconfig": """You are a Network Info Synthesizer for short-answer questions.
        TASK: You must find the answer in the given context. Consolidate the passage into a clear context and write the answer.
        
        Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):
1. output the raw answer value in ONE line:
   - text type: Just the text value (e.g., "R1" or "10.0.0.1")
   - numeric/number type: Just the number (e.g., 5 or 10.5)
   - set type: JSON array format (e.g., ["item1", "item2"])
   - map type: JSON object format (e.g., {"key": "value"})
   - boolean type: true or false

2. CORE SEARCH RULES (CRITICAL)
- **Scope Restriction**: Identify the target device and search ONLY within its specific configuration block (e.g., between `<Leaf1.cfg>` and the next tag). IGNORE content outside this block.
- **No Inference**: Do NOT assume settings exist just because they appear on connected devices (e.g., configurations on a PE router do NOT imply the same settings on a Leaf switch).
- **Strict 'None' Handling**: If the specific command is missing in the target block, do NOT guess or use unrelated values (like IPs). Return the Empty Value defined below.
   
3. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set: []
   - map: {}
   - boolean: false"""
}

    base_synth = PROMPTS.get(dataset_type, PROMPTS["descriptive"])
    system_prompt = base_synth + f"""
### INSTRUCTIONS:
- Do not write a passage if you don’t know accurate information about the question. Write [NONE] if you cannot write a factual good passage.(ex. Passage: [NONE])  

### OUTPUT FORMAT:
[START]
Passage:
Answer:
[DONE]
"""

    options_str = state.get('options', '')
    user_prompt = f"Question: {state['question']}\n"
    if dataset_type == "multiple_choice" and options_str:
        user_prompt += f"Options: {options_str}\n"
    user_prompt += f"Context: {state.get('context', '')}\n"
    user_prompt += f"Current Passage: {state['current_passage']}\n"
    user_prompt += f"Candidate Answer: {state.get('candidate_answer', '')}"

    res = models['C'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    p, a = parse_response(res)
    
    return {
        "current_passage": p, 
        "candidate_answer": a,
        "round_count": state["round_count"] + 1
    }