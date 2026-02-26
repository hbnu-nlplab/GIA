import json
import re
from agents_v2.model_loader import get_models

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
    system_prompt = """You are a Skeptical Network Auditor. 
Review Agent 3's Answer and Agent 4's Defense based on the Passage.

DECISION CRITERIA:
1. ACCEPT: The answer is perfectly supported by the Passage.
2. CONTINUE_DEBATE: The answer or the defense has logical flaws that need more discussion.
3. NEED_MORE_INFO: The Passage itself lacks the information to verify the answer.

OUTPUT FORMAT:
You MUST output ONLY a valid JSON object. Do not include any other text, markdown formatting, or preamble.
The JSON must have the following structure:
{
    "status": "ACCEPT" | "CONTINUE_DEBATE" | "NEED_MORE_INFO",
    "con_argument": "Your technical critique of the answer and the proponent's defense",
    "feedback_to_agent1": "If status is NEED_MORE_INFO, specify what is missing"
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