
import json
import re
from agents_v2.model_loader import get_models
import threading
gpu_lock = threading.Lock()
def _get_text(response):
    """LangChain 객체 또는 일반 텍스트에서 문자열만 안전하게 추출"""
    return response.content if hasattr(response, 'content') else str(response)

# ==========================================
# 🛡️ Agent 4: Proponent (옹호 및 근거 보강)
# ==========================================
def supporter_node(state: dict):
    print("\n🛡️ [Agent 4: Proponent] 답변 옹호 및 논리 보강")
    models = get_models()
    llm = models['A'] 
    
    # 수정 포인트: 답변을 수정(Refine)하는 것이 아니라, Agent 3의 답이 왜 맞는지 'Passage'를 근거로 옹호함
    system_prompt = """You are a Proponent Network Engineer.
Your goal is to support and defend the 'Candidate Answer' provided by Agent 3.

RULES:
1. DO NOT change the Candidate Answer.
2. Use the provided 'Passage' as evidence to explain why the answer is correct and technically sound.
3. If there was previous Critic Feedback, refute it using technical facts from the Passage.

OUTPUT FORMAT:
[START]
(Your technical defense and supporting reasoning)
[DONE]"""

    critic_feedback = state.get("critic_feedback", "No feedback yet.")
    
    prompt = f"""{system_prompt}
    Passage: {state.get('current_passage')}
    Candidate Answer (Agent 3): {state.get('candidate_answer')}
    Previous Critic Feedback: {critic_feedback}
    """ 

    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"

    with gpu_lock:
        response = llm.invoke(prompt)
    response_text = _get_text(response)
    
    # 의견(Argument) 추출
    match = re.search(r"\[START\](.*?)\[DONE\]", response_text, re.DOTALL | re.IGNORECASE)
    argument = match.group(1).strip() if match else response_text.strip()
    
    print("+++++++++++++++++ Proponent Argument generated.")
    return {
        "pro_argument": argument, # 수정 대신 옹호 의견 필드에 저장
        "proponent_responses": state.get("proponent_responses", []) + [response_text]
    }

# ==========================================
# ⚖️ Agent 5: Critic (비판 및 상태 판정)
# ==========================================
def skeptic_node(state: dict):
    print("⚖️ [Agent 5: Critic] 최종 검증 및 비판 의견 제시")
    models = get_models()
    llm = models.get('B', models['A']) 
    
    # 수정 포인트: Proponent의 옹호 의견까지 참고하여 Agent 3의 답변을 비판적으로 검토
    system_prompt = """You are a Highly Critical Network Auditor. 
Your primary mission is to detect technical errors, hallucinations, and data collection failures. 
Do not be polite. If there is even a slight mismatch or missing evidence, REJECT the answer.

### CRITICAL AUDIT RULES:
1. **Empty Passage Penalty**: If the 'Passage' is empty, whitespace-only, or says "no information," you MUST set status to "NEED_MORE_INFO". NEVER 'ACCEPT' an empty passage.
2. **Anti-Hallucination**: Check if the 'Candidate Answer' contains specific values (IPs, version numbers) NOT found in the 'Passage'. If the answer contains sequential patterns (e.g., .1, .2, .3...) that aren't explicitly in the raw text, set status to "CONTINUE_DEBATE" and flag it as a hallucination.
3. **Refusal is not an Answer**: If Agent 3 says "I cannot answer" or "Please provide context," this is a failure. Set status to "NEED_MORE_INFO".
4. **Entity Alignment**: Ensure the device in the Question (e.g., leaf1) matches the device in the Passage. If the Passage describes 'leaf2' instead, set status to "NEED_MORE_INFO".

### DECISION CRITERIA:
1. **ACCEPT**: Only if the answer is a specific technical value 100% supported by the EXACT wording in the Passage.
2. **CONTINUE_DEBATE**: If the answer has logical leaps, contains suspected hallucinations, or if Agent 4's defense is just "the passage is missing info."
3. **NEED_MORE_INFO**: If the Passage is missing, irrelevant to the target device, or insufficient to prove the answer.

### OUTPUT FORMAT:
You MUST output ONLY a valid JSON object. No markdown, no preamble.
{
    "status": "ACCEPT" | "CONTINUE_DEBATE" | "NEED_MORE_INFO",
    "con_argument": "Detailed technical critique of why the answer is wrong or why the passage is insufficient.",
    "feedback_to_agent1": "Specific instructions for Agent 1 to find the missing data (e.g., 'Look for hostname leaf1 and BGP neighbor commands')."
}"""

    prompt = f"""{system_prompt}

Question: {state.get('question')}
Passage: {state.get('current_passage')}
Candidate Answer (Agent 3): {state.get('candidate_answer')}
Proponent's Defense (Agent 4): {state.get('pro_argument')}"""
    
    dataset_type = state.get("dataset_type", "descriptive")
    options_str = state.get('options', '')
    if dataset_type == "multiple_choice" and options_str:
        prompt += f"Options: {options_str}\n"
        
    with gpu_lock:
        response = llm.invoke(prompt)
    response_text = _get_text(response)
    
    try:
        clean_text = response_text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()

        json_match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group(0))
            except json.JSONDecodeError:
                result = json.loads(clean_text)
        else:
            result = json.loads(clean_text)
            
        status = result.get("status", "ACCEPT").upper()
        if status not in ["ACCEPT", "CONTINUE_DEBATE", "NEED_MORE_INFO"]:
            status = "ACCEPT"
        con_argument = result.get("con_argument", "")
        feedback_to_agent1 = result.get("feedback_to_agent1", "")
        
    except (json.JSONDecodeError, AttributeError) as e:
        print(f"⚠️ [Warning] Critic output parsing failed: {e}")
        # LLM이 JSON을 출력하지 않고 텍스트만 출력한 경우 이를 con_argument로 사용하고 status는 ACCEPT로 분류
        status = "ACCEPT"
        con_argument = response_text
        feedback_to_agent1 = ""

    print(f"+++++++++++++++++ Status: {status}")
    
    return {
        "status": status,
        "critic_feedback": con_argument, # 비판 내용을 피드백 필드에 저장
        "con_argument": con_argument,     # 비판 의견 전용 필드
        "critic_feedbacks": state.get("critic_feedbacks", []) + [response_text],
        "final_answer": state.get('candidate_answer') if status == "ACCEPT" else "",
        "inner_turn_count": state.get("inner_turn_count", 0) + 1
    }