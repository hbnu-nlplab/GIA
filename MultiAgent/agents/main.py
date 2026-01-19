import sys
import os
import json
from pathlib import Path
from langgraph.graph import StateGraph, END

CURRENT_DIR = Path(__file__).resolve().parent
BASE_DIR = CURRENT_DIR.parent
sys.path.append(str(BASE_DIR))

from agents.state import AgentState
from agents.model_loader import init_models
import agents.debate1 as d1
import agents.debate2 as d2



def build_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("Verifier", d1.verifier_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)
    
    workflow.add_node("Supporter", d2.supporter_node)
    workflow.add_node("Skeptic", d2.skeptic_node)

    workflow.set_entry_point("Collector")
    workflow.add_edge("Collector", "Verifier")
    workflow.add_edge("Verifier", "Synthesizer")

    def check_loop(state):
        return "continue" if state["round_count"] < 3 else "finish_d1"

    workflow.add_conditional_edges(
        "Synthesizer",
        check_loop,
        {
            "continue": "Collector",
            "finish_d1": "Supporter"
        }
    )
    workflow.add_edge("Supporter", "Skeptic")
    workflow.add_edge("Skeptic", END)

    return workflow.compile()



def main():
    print("Initializing Models...")
    init_models()
    
    app = build_graph()
    
    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "telequad_passage.json"
    output_path = BASE_DIR / "data" / "debate_results" / "full_w_context" / "telequad_result.json"
    
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)[:5]

    results = []
    
    import time
    elapsed_times = []

    for i, item in enumerate(data):
        q_text = item.get('question', '')
        print(f"\n🔹 [{i+1}/{len(data)}] Question: {q_text[:40]}...")
        
        initial_state = {
            "question": q_text,
            "original_passage": item.get('passage', ''),
            "current_passage": item.get('passage', ''),
            "gold_answer": item.get('gold_answer', ''),
            "options": item.get('options', ''),
            "round_count": 0,
            "history": [],
            "candidate_answer": "",
            "pro_argument": "",
            "con_argument": "",
            "final_answer": ""
        }
        
        start_time = time.time()
        try:
            out = app.invoke(initial_state)
            end_time = time.time()
            duration = end_time - start_time
            elapsed_times.append(duration)
            print(f"   ⏱️ Time taken: {duration:.2f} seconds")
            
            result_item = {
                "question": q_text,
                "gold_answer": item.get('gold_answer'),
                "debate1_passage": out['current_passage'],
                "debate1_answer": out['candidate_answer'],
                "debate2_answer": out['final_answer']
            }
            results.append(result_item)
            
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

    if elapsed_times:
        avg_time = sum(elapsed_times) / len(elapsed_times)
        print(f"\n📊 Average time per question: {avg_time:.2f} seconds")

    os.makedirs(output_path.parent, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"All Done! Saved to {output_path}")

if __name__ == "__main__":
    main()