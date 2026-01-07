import json
import os
import sys
from typing import TypedDict, List
from pathlib import Path
import torch

from langchain_openai import ChatOpenAI
from langchain_huggingface import HuggingFacePipeline
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, END
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

from config.load_env import load_louter, load_api_key

USE_LOCAL = False 


def init_models():
    models = {}

    if not USE_LOCAL:
        print("☁️ [Mode] Using OpenRouter (Cloud)")
        api_key, base_url, model1, model2, model3 = load_louter()

        common_params = {
            "base_url": base_url,
            "api_key": api_key,
            "temperature": 0
        }

        print(f"   - Model A (Engineer): {model1}")
        print(f"   - Model B (Auditor):  {model2}")
        print(f"   - Model C (Editor):   {model3}")

        models['A'] = ChatOpenAI(model=model1, **common_params)
        models['B'] = ChatOpenAI(model=model2, **common_params)
        models['C'] = ChatOpenAI(model=model3, **common_params)

    else:
        print("🖥️ [Mode] Using Local Hugging Face Models (GPU)")

        hf_models = {
            'A': "meta-llama/Meta-Llama-3-8B-Instruct",  
            'B': "Qwen/Qwen2.5-3B-Instruct",                
            'C': "google/gemma-2-2b-it"                 
        }
        
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )

        for role, model_id in hf_models.items():
            print(f"   ...Loading {role} ({model_id}) into VRAM...")
            
            pipe = pipeline(
                "text-generation",
                model=model_id,
                tokenizer=model_id,
                model_kwargs={
                    "quantization_config": bnb_config,
                    "low_cpu_mem_usage": True,
                },
                max_new_tokens=250,
                temperature=0
            )
            models[role] = HuggingFacePipeline(pipeline=pipe)

    return models

llm_dict = init_models()


class DebateState(TypedDict):
    question: str
    original_passage: str
    current_passage: str
    gold_answer: str      
    round_count: int      
    history: List[str]   


def debater_a_node(state: DebateState):
    """ [Role: Engineer - Model A] """
    print(f"\n--- [Round {state['round_count'] + 1}] Debater A (Engineer) is working... ---")
    
    prompt = f"""
    You are Debater A, a Network Engineer expert.
    Analyze the [Current Passage] strictly for technical accuracy regarding the [Question].
    
    Question: {state['question']}
    Current Passage: {state['current_passage']}
    
    Task:
    1. Fix any incorrect IP addresses, AS numbers, or protocol names.
    2. Ensure the technical logic is sound.
    3. If the passage says "[NONE]" but you know the general networking concept, refine it.
    
    Output ONLY the revised passage.
    """
    
    response = llm_dict['A'].invoke([HumanMessage(content=prompt)])
    new_passage = response.content.strip() if hasattr(response, 'content') else str(response).strip()
    
    return {
        "current_passage": new_passage,
        "history": [f"Round {state['round_count']+1} (A): {new_passage[:30]}..."]
    }


def debater_b_node(state: DebateState):
    """ [Role: Auditor - Model B] """
    print(f"--- [Round {state['round_count'] + 1}] Debater B (Auditor) is working... ---")
    
    prompt = f"""
    You are Debater B, a Critical Auditor.
    Review the [Current Passage] to ensure it is grounded in reality.
    
    Question: {state['question']}
    Current Passage: {state['current_passage']}
    
    Task:
    1. Aggressively remove any information that looks like a hallucination.
    2. If the passage answers with specific data that seems uncertain, change it to "정보없음".
    3. Keep the factual parts intact.
    
    Output ONLY the revised passage.
    """

    response = llm_dict['B'].invoke([HumanMessage(content=prompt)])
    new_passage = response.content.strip() if hasattr(response, 'content') else str(response).strip()
    
    return {
        "current_passage": new_passage,
        "history": [f"Round {state['round_count']+1} (B): {new_passage[:30]}..."]
    }
    
    
def debater_c_node(state: DebateState):
    """ [Role: Editor - Model C] """
    print(f"--- [Round {state['round_count'] + 1}] Debater C (Editor) is working... ---")
    
    prompt = f"""
    You are Debater C, a Chief Editor.
    Polish the [Current Passage] for clarity and conciseness.
    
    Question: {state['question']}
    Current Passage: {state['current_passage']}
    
    Task:
    1. Remove redundant phrases.
    2. Ensure the text is concise (max 3-4 sentences).
    3. Fix any grammar or formatting issues.
    
    Output ONLY the revised passage.
    """
    
    response = llm_dict['C'].invoke([HumanMessage(content=prompt)])
    new_passage = response.content.strip() if hasattr(response, 'content') else str(response).strip()
    
    return {
        "current_passage": new_passage,
        "round_count": state["round_count"] + 1, 
        "history": [f"Round {state['round_count']+1} (C): {new_passage[:30]}..."]
    }


def check_continuation(state: DebateState):
    if state["round_count"] < 3:
        return "continue"
    else:
        return "stop"


workflow = StateGraph(DebateState)

workflow.add_node("Debater_A", debater_a_node)
workflow.add_node("Debater_B", debater_b_node)
workflow.add_node("Debater_C", debater_c_node)

workflow.set_entry_point("Debater_A")
workflow.add_edge("Debater_A", "Debater_B")
workflow.add_edge("Debater_B", "Debater_C")

workflow.add_conditional_edges(
    "Debater_C",
    check_continuation,
    {
        "continue": "Debater_A",
        "stop": END
    }
)

app = workflow.compile()


def run_debate_on_dataset(input_file, output_file, limit=None):
    if not os.path.exists(input_file):
        print(f"Error: File not found {input_file}")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if limit:
        data = data[:limit]
        print(f"⚠️ Limit set to {limit} items.")

    results = []

    for i, item in enumerate(data):
        print(f"\n Processing Item {i+1}/{len(data)}: {item.get('question')[:30]}...")
        
        initial_state = {
            "question": item['question'],
            "original_passage": item['passage'],
            "current_passage": item['passage'],
            "gold_answer": item.get('gold_answer', ''),
            "round_count": 0,
            "history": []
        }
        
        try:
            final_state = app.invoke(initial_state)
            
            result_item = {
                "question": item['question'],
                "gold_answer": item.get('gold_answer'),
                "original_passage": item['passage'],
                "debated_passage": final_state['current_passage'],
                "history_log": final_state['history']
            }
            results.append(result_item)
        except Exception as e:
            print(f"❌ Error processing item {i}: {e}")
            continue

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"\n✅ Debate Complete! Saved to {output_file}")

if __name__ == "__main__":
    mode_suffix = "local" if USE_LOCAL else "router"
    
    INPUT_PATH = BASE_DIR / "data" / "passages" / "netconfig_passage.json"
    OUTPUT_PATH = BASE_DIR / "data" / "passages" / f"netconfig_debated_{mode_suffix}.json"
    
    run_debate_on_dataset(INPUT_PATH, OUTPUT_PATH, limit=5)