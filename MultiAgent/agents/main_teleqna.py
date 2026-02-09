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

def process_item(app, item, index, total, dataset_type, global_context=None):
    q_text = item.get('question', '')
    
    # Context 설정
    context = ""
    if global_context:
        context = global_context
    else:
        # TeleQuAD/NetBench: gold_context 필드 혹은 context 필드 사용
        context = item.get('gold_context', '') or item.get('context', '')
    
    initial_state = {
        "question": q_text,
        "original_passage": item.get('passage', ''),
        "current_passage": item.get('passage', ''),
        "gold_answer": item.get('gold_answer', ''),
        "options": item.get('options', ''),
        "dataset_type": dataset_type,
        "context": context,
        "round_count": 0,
        "history": [],
        "candidate_answer": "",
        "pro_argument": "",
        "con_argument": "",
        "final_answer": ""
    }
    
    MAX_RETRIES = 3
    # 정규표현식을 사용하여 더 유연하게 패턴을 탐지합니다.
    FORBIDDEN_PATTERNS = [
        re.compile(r"the user is asking", re.IGNORECASE),
        re.compile(r"the supporter['']s argument", re.IGNORECASE),
        re.compile(r"critique\s*[:\-]", re.IGNORECASE),
        re.compile(r"the user wants", re.IGNORECASE),
        re.compile(r"the candidate answer is", re.IGNORECASE),
        re.compile(r"the provided context", re.IGNORECASE),
        re.compile(r"\[?NONE\]?", re.IGNORECASE),
        re.compile(r"Final Answer\s*[:\-]", re.IGNORECASE), # 라벨이 답변 내용에 포함된 경우
    ]
    
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
    sys.stdout = Tee(log_dir / "debate_execution_full_w_context.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Initializing Models...")
    init_models()
    
    app = build_graph()
    
    # --- 경로 설정 ---
    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "teleqna_passage.json"
    output_path = BASE_DIR / "data" / "debate_results" / "full_w_context4" / "teleqna_result.json"
    
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    print(f"Loaded {len(data)} items to process.")

    results = []
    
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

    # Dataset Type 및 Global Context 처리
    dataset_type = "descriptive"
    global_context = None

    if "teleqna" in input_path.name.lower():
        dataset_type = "multiple_choice"
    elif "telequad" in input_path.name.lower():
        dataset_type = "short_answer"
    elif "netconfig" in input_path.name.lower():
        dataset_type = "short_answer"
        context_file = BASE_DIR / "data" / "original" / "netconfig_context.txt"
        if context_file.exists():
            with open(context_file, 'r', encoding='utf-8') as f:
                global_context = f.read()
            print("Loaded global context for NetConfig.")
            print(global_context[:10])
    elif "netbench" in input_path.name.lower():
        dataset_type = "descriptive"

    print(f"Dataset type detected: {dataset_type}")

    items_to_process = [item for item in data if item.get('question', '') not in existing_questions]
    print(f"Skipping {len(existing_questions)} items. Processing remaining {len(items_to_process)} items.")

    MAX_WORKERS = 50
    
    start_total_time = time.time()
    os.makedirs(output_path.parent, exist_ok=True)
    
    print(f"Starting parallel execution with {MAX_WORKERS} workers...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_item = {
            executor.submit(process_item, app, item, i, len(data), dataset_type, global_context): i 
            for i, item in enumerate(items_to_process)
        }
        
        for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Processing"):
            res = future.result()
            if res:
                results.append(res)
                
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