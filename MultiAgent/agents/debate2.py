import re
from typing import Dict, Any, Optional
from langchain_core.messages import HumanMessage, SystemMessage
from .model_loader import get_models

models = get_models()

def get_content(res: Any) -> str:
    """Safe extraction of content."""
    if isinstance(res, str):
        return res
    if hasattr(res, 'content'):
        return res.content
    return str(res)


def parse_extracted_field(content: Any, label: str) -> str:
    """
    Extracts a specific field from the content, handling [START]/[DONE] tags.
    """
    full_content = get_content(content).strip()
    
    print("=" * 100)
    print(f"[{label}] Full Content:", full_content) 
    
    if not full_content:
        print(f"⚠️ Warning: Model returned an empty response for {label}!")
        return ""

    target_content = full_content
    # Extract content between [START] and [DONE] if present
    if "[START]" in target_content:
        # Use the LAST [START] as the beginning of the relevant parts
        target_content = target_content.split("[START]")[-1]
    
    if "[DONE]" in target_content:
        target_content = target_content.split("[DONE]")[0]
        
    target_content = target_content.strip()
    
    print("-" * 50)
    print(f"[{label}] Target Content for Parsing:", target_content)
    
    # Search for the label (e.g., "Final Answer:")
    # Handling variations like "Final Answer -", "Answer:", or just the field name
    pattern = re.compile(rf"{re.escape(label)}\s*[:\-]?\s*(.*)", re.IGNORECASE | re.DOTALL)
    match = pattern.search(target_content)
    
    extracted_val = ""
    if match:
        extracted_val = match.group(1).strip()
        # If the result still contains [DONE] or something, we should have already stripped it, 
        # but let's be safe.
    else:
        # Fallback: if label missing but content exists, use the entire target_content
        print(f"ℹ️ Label '{label}' not found, using target content as fallback.")
        extracted_val = target_content
        
    print("=" * 100)
    print(f"Parsed {label}:", extracted_val)

    return extracted_val


def supporter_node(state: Dict[str, Any]) -> Dict[str, Any]:
    print("   [D2] 🛡️ Supporter finding evidence...")
    dataset_type = state.get('dataset_type', 'descriptive')
    options_str = state.get('options', '')

    system_prompt = f"""
    You are a Network Info Supporter. Find evidence that supports the Answer.
    
    Context Information:
    Passage: {state['current_passage']}
    Answer: {state['candidate_answer']}
    Options: {state['options']}
    
### OUTPUT FORMAT:
[START]
Evidence: 
[DONE]
    """

    user_prompt = f"Question: {state['question']}\n"
    if dataset_type == "multiple_choice" and options_str:
        user_prompt += f"Options: {options_str}\n"
    user_prompt += f"Context: {state.get('context', '')}\n"
    user_prompt += f"Current Passage: {state['current_passage']}\n"
    user_prompt += f"Candidate Answer: {state['candidate_answer']}\n"
    
    res = models['D'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    
    content = get_content(res)
    evidence = parse_extracted_field(content, "Evidence")
    
    print("Supporter's Argument:", evidence[:100], "...")
    return {"pro_argument": evidence}


def skeptic_node(state: Dict[str, Any]) -> Dict[str, Any]:
    print("   [D2] ⚔️ Skeptic critiquing & deciding...")
    dataset_type = state.get('dataset_type', 'descriptive')
    options_str = state.get('options', '')

    PROMPTS = {
        "descriptive": """You are a Skeptic. Your goal is to determine the final correct answer.

    TASK:
    1. Internally analyze the Supporter's argument and identify flaws. (Do NOT output this analysis)
    2. Write ONLY the Final Answer for the question based on your analysis.

    RULES:
    1. Provide a complete technical answer in 1-2 sentences.
    2. CRITICAL: Output ONLY the result inside the Final Answer block. Do NOT include any "Critique:", "Analysis:", or "Reasoning:" text. 
    3. If the answer involves configurations, include the exact syntax.
    4. Match the expert-level depth of network engineering documentation.""",
        

        "short_answer": """You are a Skeptic. Your goal is to determine the final correct answer.

    TASK:
    1. Internally analyze the context to verify the answer.
    2. Output ONLY the extracted text in the Final Answer field.

    RULES:
    1. NO explanations, NO reasoning, NO critique text in the output.
    2. Do NOT paraphrase - use exact wording from context.
    3. If the answer is a value with a unit, include both.""",
        

        "multiple_choice": """You are a Skeptic. Your goal is to determine the final correct answer.

    TASK:
    1. Internally select the single best answer.
    2. Output ONLY the option format.

    RULES:
    1. Output format must be exactly: "option N: [answer text]"
    2. CRITICAL: Do NOT write any reasoning or critique. Just the option.""",
        

        "netconfig": """You are a Skeptic. Your goal is to determine the final correct answer.

     Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. output ONLY the raw answer value in ONE line:
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
- Write [NONE] there is no answer. 

### OUTPUT FORMAT:
[START]
Final Answer:
[DONE]
"""
    
    user_prompt = f"Question: {state['question']}\n"
    if dataset_type == "multiple_choice" and options_str:
        user_prompt += f"Options: {options_str}\n"
    user_prompt += f"Context: {state.get('context', '')}\n"
    user_prompt += f"Current Passage: {state['current_passage']}\n"
    user_prompt += f"Candidate Answer: {state['candidate_answer']}\n"
    user_prompt += f"Opposite Argument: {state['pro_argument']}\n"
    
    res = models['E'].invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])

    content = get_content(res)
    final_ans = parse_extracted_field(content, "Final Answer")
    
    print(f"   -> Final Decision: {final_ans}")  
    return {"final_answer": final_ans}  
