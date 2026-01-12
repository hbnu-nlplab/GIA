from langchain_core.messages import HumanMessage
from .model_loader import get_models

models = get_models()

def parse_response(content):
    """Helper to extract Passage and Answer from model output."""
    content = content.strip()
    passage = content
    answer = ""
    
    if "Answer:" in content:
        parts = content.split("Answer:")
        passage = parts[0].replace("Passage:", "").strip()
        answer = parts[1].strip()
        
    return passage, answer

def collector_node(state):
    print(f"   [D1] Round {state['round_count']+1}: Collector gathering details...")
    prompt = f"""You are a Network Info Collector.
    1. Detailedly expand the [Current Passage] to include all necessary technical details relative to the [Question].
    2. Provide a tentative Answer to the Question based on this extended passage.
    
    - Focus on retrieving specs, protocols, and technical nuances.
    
    Format:
    Passage: <expanded_passage>
    Answer: <tentative_answer>
    
    Question: {state['question']}
    Current Passage: {state['current_passage']}"""
    
    res = models['A'].invoke([HumanMessage(content=prompt)])
    p, a = parse_response(res.content)
    return {"current_passage": p, "candidate_answer": a}


def verifier_node(state):
    print(f"   [D1] Round {state['round_count']+1}: Verifier checking facts...")
    prompt = f"""You are a Strict Network Info Verifier.
    1. Scrutinize the [Current Passage] for hallucinations, logical errors, or technical inaccuracies.
    2. Verify the [Candidate Answer] against the passage.
    
    - Harshly remove any unverified or wrong information.
    - IF the passage and answer are already correct, KEEP THEM AS IS. Only modify if necessary.
    
    Format:
    Passage: <verified_passage>
    Answer: <verified_answer>
    
    Question: {state['question']}
    Current Passage: {state['current_passage']}
    Candidate Answer: {state.get('candidate_answer', '')}"""
    
    res = models['B'].invoke([HumanMessage(content=prompt)])
    p, a = parse_response(res.content)
    return {"current_passage": p, "candidate_answer": a}


def synthesizer_node(state):
    print(f"   [D1] Round {state['round_count']+1}: Synthesizer summarizing & answering...")
    prompt = f"""You are a Network Info Synthesizer.
    1. Consolidate the [Current Passage] into a clear, finalized context.
    2. Derive the final Candidate Answer to the Question.
    
    - Refine the Passage to be concise yet complete.
    - Provide the direct Answer to the Question based on this Passage.
    
    Format:
    Passage: <refined_passage>
    Answer: <concise_answer>
    
    Question: {state['question']}
    Current Passage: {state['current_passage']}"""
    
    res = models['C'].invoke([HumanMessage(content=prompt)])
    p, a = parse_response(res.content)
    
    return {
        "current_passage": p, 
        "candidate_answer": a,
        "round_count": state["round_count"] + 1
    }