
import sys
import os
import json
import time
import traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from langgraph.graph import StateGraph, END

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable

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

def process_item(app, item, index, total):
    q_text = item.get('question', '')
    
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
        
        result_item = {
            "question": q_text,
            "gold_answer": item.get('gold_answer'),
            "debate1_passage": out['current_passage'],
            "debate1_answer": out['candidate_answer'],
            "debate2_answer": out['final_answer'],
            "debate_history": out.get('history', []),
            "duration": duration
        }
        return result_item
    except Exception as e:
        print(f"Error processing item {index}: {e}")
        return None

class Tee:
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        sys.stdout = self
    def __del__(self):
        sys.stdout = self.stdout
        self.file.close()
    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
    def flush(self):
        self.file.flush()
        self.stdout.flush()

def main():
    # Setup Logging
    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    sys.stdout = Tee(log_dir / "debate_execution.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Initializing Models...")
    init_models()
    
    app = build_graph()
    
    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "netbench_passage.json"
    output_path = BASE_DIR / "data" / "debate_results" / "full_w_context" / "netbench_result.json"
    
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    print(f"Loaded {len(data)} items to process.")

    results = []
    
    # Check for existing results to resume
    existing_questions = set()
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    results.extend(loaded)
                    existing_questions = {r.get('question', '') for r in loaded}
            print(f"Resuming from {len(results)} existing items.")
        except Exception as e:
            print(f"Error reading existing output: {e}. Starting fresh.")

    # Filter out already processed items
    items_to_process = [item for item in data if item.get('question', '') not in existing_questions]
    print(f"Skipping {len(existing_questions)} items. Processing remaining {len(items_to_process)} items.")

    MAX_WORKERS = 50 # Increased for speed
    
    start_total_time = time.time()
    os.makedirs(output_path.parent, exist_ok=True)
    
    print(f"Starting parallel execution with {MAX_WORKERS} workers...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_item = {
            executor.submit(process_item, app, item, i, len(data)): i 
            for i, item in enumerate(items_to_process)
        }
        
        for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Processing"):
            res = future.result()
            if res:
                results.append(res)
                
                # Checkpoint every 50 items
                if len(results) % 50 == 0:
                     with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=4, ensure_ascii=False)

    total_duration = time.time() - start_total_time
    print(f"\nAll Done! Total time: {total_duration:.2f} seconds")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"Saved {len(results)} results to {output_path}")

if __name__ == "__main__":
    main()