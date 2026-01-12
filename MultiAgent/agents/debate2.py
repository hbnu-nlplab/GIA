from langchain_core.messages import HumanMessage
from .model_loader import get_models

models = get_models()

def supporter_node(state):
    # Model C (Editor -> Supporter): 긍정 근거 찾기
    print("   [D2] 🛡️ Supporter finding evidence...")
    prompt = f"""You are a Supporter. Find evidence in the Passage that supports the Answer.
    Passage: {state['current_passage']}
    Answer: {state['candidate_answer']}
    Explain WHY this answer is correct."""
    res = models['D'].invoke([HumanMessage(content=prompt)])
    return {"pro_argument": res.content.strip()}


def skeptic_node(state):
    # Model B (Auditor -> Skeptic): 오답 가능성 제기 및 최종 결론
    print("   [D2] ⚔️ Skeptic critiquing & deciding...")
    prompt = f"""You are a Skeptic. Critique the Supporter's argument and the Candidate Answer. Then, determine the Final Answer.
    
    Question: {state['question']}
    Candidate Answer: {state['candidate_answer']}
    Pro Argument: {state['pro_argument']}
    
    Task:
    1. Identify any flaws or limitations in the answer/argument. (Con Argument)
    2. Make a final decision. 
       - If the candidate answer is correct and supported by the passage/arguments, OUTPUT IT AS IS.
       - Only provide a corrected answer IF NECESSARY (e.g., if there are fatal flaws or hallucinations).
    
    Output Format:
    Critique: <critique_text>
    Final Answer: <final_answer_text>"""
    
    res = models['D'].invoke([HumanMessage(content=prompt)])
    content = res.content.strip()
    
    con_arg = content
    final_ans = state['candidate_answer'] # Default fallback
    
    if "Final Answer:" in content:
        parts = content.split("Final Answer:")
        con_arg = parts[0].replace("Critique:", "").strip()
        final_ans = parts[1].strip()
        
    return {"con_argument": con_arg, "final_answer": final_ans}
