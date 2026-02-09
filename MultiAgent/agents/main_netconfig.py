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

# --- [Helper] 키 정규화 (비교용) ---
def normalize_key(text):
    if not text: return ""
    return re.sub(r'[\n\\"*]+', '', str(text)).strip()

# --- [Helper] 저장용 텍스트 정제 함수 ---
def clean_text_for_save(text):
    if text is None:
        return ""
    text_str = str(text)
    cleaned = re.sub(r'[\n\\"*]+', '', text_str)
    return cleaned.strip()

# --- [Helper] 타입 자동 감지 ---
def detect_answer_type(item):
    if 'answer_type' in item: return item['answer_type']
    if 'type' in item: return item['type']
    
    gold = str(item.get('gold_answer', '')).strip()
    if gold.startswith('{') and gold.endswith('}'): return 'map'
    if gold.startswith('[') and gold.endswith(']'): return 'set'
    return 'text'

# --- [New Helper] 정답과 예측값 비교 함수 ---
def is_answer_different(gold, pred, ans_type):
    """
    gold_answer와 debate2_answer가 실질적으로 다른지 비교합니다.
    JSON 파싱을 시도하여 구조적 동등성을 확인합니다.
    """
    if gold is None: gold = ""
    if pred is None: pred = ""
    
    str_gold = str(gold).strip()
    str_pred = str(pred).strip()

    # 1. 완전히 문자열이 같으면 False (다르지 않음)
    if str_gold == str_pred:
        return False

    # 2. Map/Set인 경우 JSON 파싱 후 비교 시도
    if ans_type in ['map', 'set']:
        try:
            # 작은따옴표를 큰따옴표로 변환 (Python dict str -> JSON 호환)
            json_gold = str_gold.replace("'", '"')
            json_pred = str_pred.replace("'", '"')
            
            obj_gold = json.loads(json_gold)
            obj_pred = json.loads(json_pred)
            
            if ans_type == 'set':
                # 리스트인 경우 정렬해서 비교 (순서 무관하게)
                if isinstance(obj_gold, list) and isinstance(obj_pred, list):
                    return sorted(map(str, obj_gold)) != sorted(map(str, obj_pred))
            
            return obj_gold != obj_pred
        except:
            # JSON 파싱 실패 시, 텍스트 정제 후 단순 비교
            clean_g = re.sub(r'[\s\n\\"\']+', '', str_gold)
            clean_p = re.sub(r'[\s\n\\"\']+', '', str_pred)
            return clean_g != clean_p

    # 그 외 타입은 단순 문자열 비교
    return str_gold != str_pred

# --- [수정됨] NetConfig용 설정 파일 로더 ---
def load_netconfigs(base_path):
    config_path = base_path / "data" / "original" / "netconfig" / "configs.txt"
    if not config_path.exists():
        print(f"⚠️ Warning: Config file not found: {config_path}")
        return "" 
    print(f"📂 Loading config file from: {config_path}")
    try:
        content = config_path.read_text(encoding='utf-8', errors='ignore')
        print(f"✅ Loaded config file successfully (Length: {len(content)} chars).")
        return content
    except Exception as e:
        print(f"❌ Error reading {config_path.name}: {e}")
        return ""

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
    item_type = detect_answer_type(item)

    context = ""
    if dataset_type == "netconfig" and global_context:
        context = global_context
    else:
        context = item.get('gold_context', '') or item.get('context', '') or "[NONE]"

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
                    should_retry = True; break
            if not should_retry: break
            
            current_attempt += 1
            print(f"[{index}] Retry {current_attempt}...")
            initial_state["round_count"] = 0 
            initial_state["history"] = []

        duration = time.time() - start_time
        
        clean_q = clean_text_for_save(q_text)
        clean_gold = clean_text_for_save(item.get('gold_answer'))
        clean_pred = clean_text_for_save(out['final_answer'])
        
        result_item = {
            "question": clean_q,
            "gold_answer": clean_gold,
            "debate1_passage": out['current_passage'],
            "debate1_answer": out['candidate_answer'],
            "debate2_answer": clean_pred,
            "debate_history": out.get('history', []),
            "duration": duration,
            "answer_type": item_type 
        }
        return result_item
    except Exception as e:
        print(f"Error processing item {index}: {e}")
        traceback.print_exc()
        return None

class Tee:
    def __init__(self, name, mode):
        self.file = open(name, mode); self.stdout = sys.stdout; sys.stdout = self
    def __del__(self): sys.stdout = self.stdout; self.file.close()
    def write(self, data): self.file.write(data); self.stdout.write(data)
    def flush(self): self.file.flush(); self.stdout.flush()

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

    # 1. 입력 데이터 로드
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"Loaded {len(data)} items from input.")

    # 2. 기존 결과 로드
    existing_results_map = {} 
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    for r in loaded:
                        q_key = normalize_key(r.get('question', ''))
                        existing_results_map[q_key] = r
            print(f"Loaded {len(existing_results_map)} existing results.")
        except Exception as e:
            print(f"Error reading existing output: {e}. Starting fresh.")

    # --- 데이터 동기화 ---
    all_results_map = {}
    for item in data:
        q_raw = item.get('question', '')
        q_key = normalize_key(q_raw)
        if q_key in existing_results_map:
            res = existing_results_map[q_key]
            res['question'] = clean_text_for_save(q_raw) 
            all_results_map[q_key] = res

    # --- NetConfig 로드 ---
    dataset_type = "descriptive"
    global_context = None
    if "netconfig" in input_path.name.lower():
        dataset_type = "netconfig"
        print("NetConfig dataset detected: Loading config file (txt)...")
        global_context = load_netconfigs(BASE_DIR)
    
    # --- [수정된 부분] 필터링 로직 ---
    items_to_process = []
    skipped_count = 0
    
    # 재실행 대상 타입 설정
    target_types = ['map', 'set']
    
    print(f"Filtering logic: Process if missing OR (Type is {target_types} AND Answer differs)...")

    for item in data:
        q_raw = item.get('question', '')
        q_key = normalize_key(q_raw)
        item_type = detect_answer_type(item)
        
        # answer_type 정보 동기화
        if q_key in all_results_map:
            if 'answer_type' not in all_results_map[q_key]:
                all_results_map[q_key]['answer_type'] = item_type

        # 실행 여부 결정 플래그
        should_run = False
        reason = ""

        # Case 1: 아예 실행된 적 없는 경우
        if q_key not in all_results_map:
            should_run = True
            reason = "New item"
        else:
            # Case 2: 실행된 적은 있으나, 조건에 따라 재실행해야 하는 경우
            if item_type in target_types:
                prev_res = all_results_map[q_key]
                gold = item.get('gold_answer', '')
                pred = prev_res.get('debate2_answer', '')
                
                # 답이 다르면 재실행 (Wrong Answer)
                if is_answer_different(gold, pred, item_type):
                    should_run = True
                    reason = f"{item_type} Mismatch (Gold vs Pred)"

        if should_run:
            if reason != "New item":
                print(f"🔄 Re-queueing: [{item_type}] {q_raw[:30]}... Reason: {reason}")
            items_to_process.append(item)
        else:
            skipped_count += 1

    print(f"Skipping {skipped_count} items (Correct or Non-target).")
    print(f"Queueing {len(items_to_process)} items for processing.")

    # --- 병렬 실행 ---
    MAX_WORKERS = 50
    start_total_time = time.time()
    os.makedirs(output_path.parent, exist_ok=True)
    
    if items_to_process:
        print(f"Starting parallel execution with {MAX_WORKERS} workers...")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_item = {
                executor.submit(process_item, app, item, i, len(data), dataset_type, global_context): item
                for i, item in enumerate(items_to_process)
            }
            
            processed_count = 0
            for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Processing"):
                res = future.result()
                if res:
                    q_key = normalize_key(res['question'])
                    all_results_map[q_key] = res
                    processed_count += 1
                    
                    if processed_count % 10 == 0:
                        current_list = list(all_results_map.values())
                        with open(output_path, 'w', encoding='utf-8') as f:
                            json.dump(current_list, f, indent=4, ensure_ascii=False)
    
    total_duration = time.time() - start_total_time
    print(f"\nAll Done! Total time: {total_duration:.2f} seconds")

    final_list = list(all_results_map.values())
    if len(final_list) != len(data):
        print(f"⚠️ Warning: Output count ({len(final_list)}) != Input count ({len(data)})")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_list, f, indent=4, ensure_ascii=False)
    
    print(f"Saved total {len(final_list)} results to {output_path}")

if __name__ == "__main__":
    main()