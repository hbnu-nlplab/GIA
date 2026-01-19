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
        # Fallback
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
    print(f"   [D1] Round {state['round_count']+1}: Collector gathering details...")
    system_prompt = """You are a Network Info Collector.
Your task is to analyze the [Question] and [Current Passage] to construct a factual passage and derive an answer.

### 1. ANALYZE QUESTION TYPE & FORMAT ANSWER:
- **Multiple Choice**: IF the question contains options, choose the correct option and only write the number.
- **Short Answer**: IF the Question asks for a specific entity, provide the value.
- **Descriptive**: IF the Question asks to "explain", "describe", or "how", provide a concise explanation.

### 2. INSTRUCTIONS:
- Construct a concise 'Passage' strictly based on the provided gold context.
- If the context is insufficient, output "[NONE]".

### OUTPUT FORMAT:
[START]
Passage:
Answer:
[DONE]
"""

    options_str = state.get('options', '')
    if options_str:
        user_prompt = f"""
Question: {state['question']}
Options: {options_str}
Current Passage: {state['current_passage']}
"""
    else:
        user_prompt = f"""
Question: {state['question']}
Current Passage: {state['current_passage']}
"""

    print("Options:", options_str)

    res = models['A'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    p, a = parse_response(res)
    return {"current_passage": p, "candidate_answer": a}



def verifier_node(state):
    print(f"   [D1] Round {state['round_count']+1}: Verifier checking facts...")
    system_prompt = """You are a Strict Network Info Verifier.
Your task is to scrutinize the [Current Passage] and [Candidate Answer] for errors.

### INSTRUCTIONS:
1. **Verify Logic**: Ensure the Answer is logically supported by the Passage.
2. **Maintain Format**:
   - **Multiple Choice**: IF the question contains options ensure the output remains the option number.
   - **Short Answer**: keep it concise.
   - **Descriptive**: check for hallucinations.
3. **Correction**: Only modify the answer and passage if it is factually wrong.

### OUTPUT FORMAT:
[START]
Passage:
Answer:
[DONE]
"""


    options_str = state.get('options', '')
    if options_str:
        user_prompt = f"""
Question: {state['question']}
Options: {options_str}
Current Passage: {state['current_passage']}
Candidate Answer: {state.get('candidate_answer', '')}
"""
    else:
        user_prompt = f"""
Question: {state['question']}
Current Passage: {state['current_passage']}
Candidate Answer: {state.get('candidate_answer', '')}
"""
    
    res = models['B'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    p, a = parse_response(res)
    return {"current_passage": p, "candidate_answer": a}



def synthesizer_node(state):
    print(f"   [D1] Round {state['round_count']+1}: Synthesizer summarizing & answering...")
    system_prompt = """You are a Network Info Synthesizer.
Your task is to consolidate the info into a clear context and finalize the answer.

### INSTRUCTIONS:
1. **Finalize Answer**:
   - **Multiple Choice**: Output ONLY the option key.
   - **Short Answer**: Output the exact value/term.
   - **Descriptive**: Ensure the explanation is clear and concise.
2. **Refine Passage**: Polish the passage to be factual and context-rich.

### OUTPUT FORMAT:
[START]
Passage: 
Answer:
[DONE]
"""

    options_str = state.get('options', '')
    if options_str:
        user_prompt = f"""
Question: {state['question']}
Options: {options_str}
Current Passage: {state['current_passage']}
Candidate Answer: {state.get('candidate_answer', '')}
"""
    else:
        user_prompt = f"""
Question: {state['question']}
Current Passage: {state['current_passage']}
Candidate Answer: {state.get('candidate_answer', '')}
"""

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