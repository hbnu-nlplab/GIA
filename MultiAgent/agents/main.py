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

# --- Helper: 답변 정규화 (따옴표 제거, 소문자 변환) ---
def normalize_answer(text):
    if not text:
        return ""
    # 문자열로 변환 -> 앞뒤 공백 제거 -> 따옴표 제거 -> 소문자 -> 다시 공백 제거
    return str(text).strip().strip('"').strip("'").lower().strip()

# --- NetConfig용 설정 파일 로더 ---
def load_netconfigs(base_path):
    config_dir = base_path / "data" / "original" / "Research_Institute_Internal_DC" / "configs"
    config_map = {}
    
    if not config_dir.exists():
        print(f"⚠️ Warning: Config directory not found: {config_dir}")
        return {}

    print(f"📂 Loading config files from: {config_dir}")
    count = 0
    for file_path in config_dir.iterdir():
        if file_path.is_file():
            try:
                device_name = file_path.stem 
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                formatted_content = f"\n=== CONFIGURATION FOR DEVICE: {device_name} ===\n{content}\n"
                config_map[device_name] = formatted_content
                count += 1
            except Exception as e:
                print(f"❌ Error reading {file_path.name}: {e}")
    
    print(f"✅ Loaded {count} config files.")
    return config_map

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

    workflow.add_conditional_edges("Synthesizer", check_loop, {"continue": "Collector", "finish_d1": "Supporter"})
    workflow.add_edge("Supporter", "Skeptic")
    workflow.add_edge("Skeptic", END)

    return workflow.compile()

def process_item(app, item, index, total, dataset_type, global_context=None):
    q_text = item.get('question', '')
    item_id = item.get('id', '')
    # Context 설정
    context = ""
    if dataset_type == "netconfig" and isinstance(global_context, dict):
        found_configs = []
        for device_name, config_content in global_context.items():
            if device_name.lower() in q_text.lower():
                found_configs.append(config_content)
        
        if found_configs:
            context = "\n".join(found_configs)
        else:
            context = item.get('gold_context', '') or item.get('context', '')
            if not context:
                 context = "[NONE]"

    elif isinstance(global_context, str) and global_context:
        context = global_context
    else:
        context = item.get('gold_context', '') or item.get('context', '')

    initial_state = {
        "id": item_id,
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
    FORBIDDEN_PATTERNS = [
        re.compile(r"the user is asking", re.IGNORECASE),
        re.compile(r"the supporter['']s argument", re.IGNORECASE),
        re.compile(r"critique\s*[:\-]", re.IGNORECASE),
        re.compile(r"the user wants", re.IGNORECASE),
        re.compile(r"the candidate answer is", re.IGNORECASE),
        re.compile(r"the provided context", re.IGNORECASE),
        re.compile(r"\[?NONE\]?", re.IGNORECASE),
        re.compile(r"Final Answer\s*[:\-]", re.IGNORECASE),
    ]
    
    start_time = time.time()
    try:
        current_attempt = 0
        while current_attempt < MAX_RETRIES:
            out = app.invoke(initial_state)
            ans = out.get('final_answer', '')
            
            should_retry = False
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(ans):
                    should_retry = True
                    break
            
            if not should_retry:
                break
            
            current_attempt += 1
            print(f"[{index}] Triggered regeneration (Attempt {current_attempt}/{MAX_RETRIES}) for forbidden content detected: {ans[:70]}...")
            initial_state["round_count"] = 0 
            initial_state["history"] = []

        end_time = time.time()
        duration = end_time - start_time
        
        result_item = {
            "id": id,
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
    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    sys.stdout = Tee(log_dir / "debate_execution_full_w_context.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Initializing Models...")
    init_models()
    
    app = build_graph()
    
    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "netconfig_passage2.json"
    output_path = BASE_DIR / "data" / "debate_results" / "full_w_context4" / "netconfig_result2.json"
    
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"Loaded {len(data)} items to process.")

    # --- [수정됨] 기존 결과 로드 및 필터링 로직 ---
    # 결과를 질문(Question)을 키로 하는 딕셔너리로 관리하여 덮어쓰기 용이하게 함
    all_results_map = {} 
    
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    for r in loaded:
                        all_results_map[r.get('question', '')] = r
            print(f"Loaded {len(all_results_map)} existing results.")
        except Exception as e:
            print(f"Error reading existing output: {e}. Starting fresh.")

    dataset_type = "descriptive"
    global_context = None

    if "teleqna" in input_path.name.lower():
        dataset_type = "multiple_choice"
    elif "telequad" in input_path.name.lower():
        dataset_type = "short_answer"
    elif "netconfig" in input_path.name.lower():
        dataset_type = "netconfig"
        print("NetConfig dataset detected: Loading config files...")
        global_context = load_netconfigs(BASE_DIR)
    elif "netbench" in input_path.name.lower():
        dataset_type = "descriptive"

    print(f"Dataset type detected: {dataset_type}")

    # --- [수정됨] 재실행 대상 선정 로직 ---
    items_to_process = []
    skipped_count = 0
    
    for item in data:
        q = item.get('question', '')
        gold_ans = item.get('gold_answer', '')
        item_id = item.get('id')
        
        # 1. 기존 결과가 없는 경우 -> 실행
        if q not in all_results_map:
            items_to_process.append(item)
            continue
            
        # 2. 기존 결과가 있는 경우 -> 정답과 비교
        existing_res = all_results_map[q]
        pred_ans = existing_res.get('debate2_answer', '')
        
        norm_gold = normalize_answer(gold_ans)
        norm_pred = normalize_answer(pred_ans)
        
        if norm_gold == norm_pred:
            # 정답이 일치하면 스킵 (이미 맞춤)
            skipped_count += 1
        else:
            # 틀렸으면 재실행 리스트에 추가 (덮어쓸 예정)
            # print(f"♻️ Re-queueing incorrect item: {q} (Exp: {gold_ans} vs Got: {pred_ans})")
            items_to_process.append(item)

    print(f"Skipping {skipped_count} correct items.")
    print(f"Queueing {len(items_to_process)} items (New or Incorrect) for processing.")

    MAX_WORKERS = 50
    start_total_time = time.time()
    os.makedirs(output_path.parent, exist_ok=True)
    
    print(f"Starting parallel execution with {MAX_WORKERS} workers...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_item = {
            executor.submit(process_item, app, item, i, len(data), dataset_type, global_context): item['question']
            for i, item in enumerate(items_to_process)
        }
        
        # 완료되는 대로 all_results_map 업데이트 및 저장
        processed_count = 0
        for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Processing"):
            res = future.result()
            if res:
                q_key = res['question']
                # 딕셔너리에 새 결과 업데이트 (덮어쓰기)
                all_results_map[q_key] = res
                processed_count += 1
                
                if processed_count % 10 == 0:
                    # 중간 저장: 맵의 값들을 리스트로 변환하여 저장
                    current_list = list(all_results_map.values())
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(current_list, f, indent=4, ensure_ascii=False)

    total_duration = time.time() - start_total_time
    print(f"\nAll Done! Total time: {total_duration:.2f} seconds")

    # 최종 저장
    final_list = list(all_results_map.values())
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_list, f, indent=4, ensure_ascii=False)
    
    print(f"Saved {len(final_list)} results to {output_path}")

if __name__ == "__main__":
    main()