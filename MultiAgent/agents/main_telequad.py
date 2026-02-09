import re
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
    
    # 금지 패턴 정의 (더 강력한 정규표현식 사용)
    FORBIDDEN_PATTERNS = [
        re.compile(r"the\s+user\s+is\s+asking", re.IGNORECASE),
        re.compile(r"the\s+supporter['']s\s+argument", re.IGNORECASE),
        re.compile(r"critique\s*[:\-]", re.IGNORECASE),
        re.compile(r"the\s+user\s+wants", re.IGNORECASE),
        re.compile(r"the\s+candidate\s+answer\s+is", re.IGNORECASE),
        re.compile(r"the\s+provided\s+context", re.IGNORECASE),
        re.compile(r"let['’s]+\s+analyze", re.IGNORECASE),
        re.compile(r"therefore", re.IGNORECASE),
        re.compile(r"\[?NONE\]?", re.IGNORECASE),
        re.compile(r"Final\s+Answer\s*[:\-]", re.IGNORECASE),
    ]
    
    MAX_RETRIES = 3
    start_time = time.time()
    try:
        current_attempt = 0
        while current_attempt < MAX_RETRIES:
            out = app.invoke(initial_state)
            ans = out.get('final_answer', '')
            
            # Check for forbidden patterns with regex
            should_retry = False
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(ans):
                    should_retry = True
                    break
            
            if not should_retry:
                break
            
            current_attempt += 1
            print(f"[{index}] Triggered regeneration (Attempt {current_attempt}/{MAX_RETRIES}) for forbidden content detected by regex: {ans[:70]}...")
            initial_state["round_count"] = 0 
            initial_state["history"] = []

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
        traceback.print_exc()
        return None

def main():
    # Setup Logging
    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    # MODIFIED: Telequad log
    sys.stdout = Tee(log_dir / "debate_execution_netbench_2.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Initializing Models...")
    init_models()
    
    app = build_graph()
    
    # MODIFIED: Telequad paths
    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "netbench_passage.json"
    output_path = BASE_DIR / "data" / "debate_results" / "full_w_context4" / "netbench_result.json"
    
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    print(f"Loaded {len(data)} items to process.")

    results = []
    
    # 금지 패턴 정의 (더 강력한 정규표현식 사용)
    FORBIDDEN_PATTERNS = [
        re.compile(r"the\s+user\s+is\s+asking", re.IGNORECASE),
        re.compile(r"the\s+supporter['']s\s+argument", re.IGNORECASE),
        re.compile(r"critique\s*[:\-]", re.IGNORECASE),
        re.compile(r"the\s+user\s+wants", re.IGNORECASE),
        re.compile(r"the\s+candidate\s+answer\s+is", re.IGNORECASE),
        re.compile(r"the\s+provided\s+context", re.IGNORECASE),
        re.compile(r"let['’s]+\s+analyze", re.IGNORECASE),
        re.compile(r"therefore", re.IGNORECASE),
        re.compile(r"\[?NONE\]?", re.IGNORECASE),
        re.compile(r"Final\s+Answer\s*[:\-]", re.IGNORECASE),
    ]

    # Check for existing results to resume
    valid_questions = set()
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    valid_results = []
                    for r in loaded:
                        ans = r.get('debate2_answer', '')
                        has_passage = bool(r.get('debate1_passage'))
                        
                        # 내용 검증
                        is_content_valid = bool(ans)
                        if is_content_valid:
                            for pattern in FORBIDDEN_PATTERNS:
                                if pattern.search(ans):
                                    is_content_valid = False
                                    break
                        
                        if has_passage and is_content_valid:
                            valid_results.append(r)
                            valid_questions.add(r.get('question', ''))
                    
                    results.extend(valid_results)
                    print(f"Loaded {len(loaded)} total existing items.")
                    print(f"Retained {len(valid_results)} valid items. Discarded {len(loaded) - len(valid_results)} invalid/incomplete items for re-processing.")
                    
        except Exception as e:
            print(f"Error reading existing output: {e}. Starting fresh.")

    # Filter out already processed (valid) items
    items_to_process = [item for item in data if item.get('question', '') not in valid_questions]
    print(f"Skipping {len(valid_questions)} valid items. Processing remaining {len(items_to_process)} items.")

    MAX_WORKERS = 50
    
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
