import re
from langchain_core.messages import HumanMessage
from .model_loader import get_models

models = get_models()

def get_content(res):
    """Safe extraction of content."""
    if isinstance(res, str):
        return res
    if hasattr(res, 'content'):
        return res.content
    return str(res)



def supporter_node(state):
    print("   [D2] 🛡️ Supporter finding evidence...")
    prompt = f"""
    You are a Network Info Supporter. Find evidence in the Passage that supports the Answer.
    Passage: {state['current_passage']}
    Answer: {state['candidate_answer']}
    Options: {state['options']}
    Explain why this answer is correct.
    """
    res = models['D'].invoke([HumanMessage(content=prompt)])
    print("Supporter's Argument:", get_content(res).strip())
    return {"pro_argument": get_content(res).strip()}


def skeptic_node(state):
    print("   [D2] ⚔️ Skeptic critiquing & deciding...")
    prompt = f"""You are a Skeptic. Critique the Supporter's argument and the Candidate Answer. Then, determine the Final Answer.
    
    Question: {state['question']}
    Candidate Answer: {state['candidate_answer']}
    Opposite Argument: {state['pro_argument']}
    Options: {state['options']}

    Task:
    1. Identify any flaws or limitations.
    2. Make a final decision based on the critique. 
       - If the opposite answer is correct, output it as the Final Answer.
    3. Ensure the Final Answer is a short phrase or entity only. Remove unnecessary words.
    
    Final Answer:
    """
    
    res = models['E'].invoke([HumanMessage(content=prompt)])
    content = get_content(res).strip()
    print(content)
    con_arg = ""
    final_ans = state['candidate_answer']

    fa_match = re.search(r"Final Answer:\s*(.*)", content, re.IGNORECASE | re.DOTALL)
    if fa_match:
        final_ans = fa_match.group(1).strip()
    print("Final Answer:", final_ans)  
    return {"final_answer": final_ans}
