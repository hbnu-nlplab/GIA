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

# --- [주의] state.py에 feedback_to_collector, outer_loop_count 상태가 추가되어야 합니다 ---
from agents_v2.state import NetAgentState
from agents_v2.model_loader import init_models
import agents_v2.debate1 as d1
import agents_v2.debate2 as d2


def normalize_key(text):
    if not text: return ""
    return re.sub(r'[\n\\"*]+', '', str(text)).strip()

def clean_text_for_save(text):
    return str(text).strip()

# --- Helper: 답변 정규화 ---
def normalize_answer(text):
    if not text:
        return ""
    return str(text).strip().strip('"').strip("'").lower().strip()

# --- NetConfig용 설정 파일 로더 ---
def load_netconfigs(base_path):
    config_path = base_path / "data" / "original" / "netconfig" / "configs.txt"
    if not config_path.exists():
        print(f"⚠️ Warning: Config file not found: {config_path}")
        return "" 
    print(f"📂 Loading config file from: {config_path}")
    try:
        context = config_path.read_text(encoding='utf-8', errors='ignore')
        # print(" +++++++++++++ given context: ", context[:100])
        print(f"✅ Loaded config file successfully (Length: {len(context)} chars).")
        return context
    except Exception as e:
        print(f"❌ Error reading {config_path.name}: {e}")
        return ""

# ==========================================
# 🔄 LangGraph 빌드 (계층적 루프 추가)
# ==========================================
def build_graph():
    workflow = StateGraph(NetAgentState)
    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("Verifier", d1.verifier_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)
    workflow.add_node("Supporter", d2.supporter_node)
    workflow.add_node("Skeptic", d2.skeptic_node)

    workflow.set_entry_point("Collector")
    workflow.add_edge("Collector", "Verifier")
    workflow.add_edge("Verifier", "Synthesizer")
    workflow.add_edge("Synthesizer", "Supporter")
    workflow.add_edge("Supporter", "Skeptic")

    def check_debate_status(state):
        status = state.get("status", "ACCEPT").upper()
        if status == "ACCEPT": return "end"
        elif status == "CONTINUE_DEBATE":
            return "end" if state.get("inner_turn_count", 0) >= 3 else "continue_inner"
        elif status == "NEED_MORE_INFO":
            return "end" if state.get("outer_loop_count", 0) >= 3 else "backtrack_outer"
        return "end"

    workflow.add_conditional_edges("Skeptic", check_debate_status, 
        {"end": END, "continue_inner": "Supporter", "backtrack_outer": "Collector"})
    return workflow.compile()

# ==========================================
# 🚀 프로세스 실행 모듈
# ==========================================
from typing import TypedDict, List, Optional

class NetAgentState(TypedDict):
    # 1. 기본 입력 정보
    question: str
    context: str
    dataset_type: str
    options: Optional[str]
    
    # 2. 에이전트 간 공유 데이터
    raw_data: str
    current_passage: str
    candidate_answer: str
    final_answer: str
    debate1_answer: str
    proponent_responses: list
    critic_feedbacks: list
    
    pro_argument: str  # Agent 4의 옹호 논리
    con_argument: str  # Agent 5의 비판 논리

    # 3. 루프 제어 변수 (기본값 대응을 위해 필수 포함)
    hop_count: int
    inner_turn_count: int
    outer_loop_count: int
    
    # 4. 토론 및 피드백 상태
    status: str
    critic_feedback: str
    feedback_to_collector: str
    
    # 5. 이력 및 기타
    history: List[dict]
    # 이전 코드와의 호환성을 위해 유지 (사용하지 않더라도 에러 방지용)
    device_db: dict 
    next_hop_device: Optional[str]


def process_item(app, item, index, total, dataset_type, global_context=None):
    q_text = item.get('question', '')
    item_id = item.get('id', '')
    
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
        "context": context,
        "dataset_type": dataset_type,
        "options": item.get('options', ''), 
        "raw_data": "", "current_passage": "",
        "candidate_answer": "",
        "final_answer": "",
        "pro_argument": "",
        "con_argument": "",
        "hop_count": 0,
        "inner_turn_count": 0,
        "outer_loop_count": 0,
        "status": "INIT",
        "proponent_responses": [],
        "critic_feedbacks": [],
        "history": []
    }
    
    start_time = time.time()
    try:
        out = app.invoke(initial_state)
        ans = out.get('candidate_answer', '')
        
        res = {
            "id": item_id,
            "question": q_text,
            "gold_answer": item.get('gold_answer'),
            "debate1_passage": out.get('current_passage', ''),
            "debate1_answer": out.get('debate1_answer', ''),
            "proponent_defense": out.get('pro_argument', ''), # Agent 4의 의견 저장
            "critic_critique": out.get('con_argument', ''),  # Agent 5의 의견 저장
            "debate2_answer": ans,
            "debate2_rounds": out.get('inner_turn_count', 0),
            "duration": time.time() - start_time
        }
        
        if dataset_type == "netconfig":
            res.update({
                "level": item.get('level', ''),
                "answer_type": item.get('answer_type', ''),
                "answer_status": item.get('answer_status', '')
            })
        return res
    except Exception as e:
        print(f"Error processing item {index}: {e}")
        traceback.print_exc() # 에러 추적을 위해 추가
        return None

class Tee:
    def __init__(self, name, mode):
        self.file = open(name, mode, encoding='utf-8')
        self.stdout = sys.stdout
        sys.stdout = self
    def __del__(self):
        if sys.stdout == self: sys.stdout = self.stdout
        self.file.close()
    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
        self.file.flush()
    def flush(self):
        self.file.flush()
        self.stdout.flush()

def main():
    target_answer_type = None # 특정 answer type 지정 (예: "map"). 지정하지 않으려면 None
    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    sys.stdout = Tee(log_dir / "debate_execution_full_w_context.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Initializing Models...")
   
    init_models()
    app = build_graph()
    
    # input_path = BASE_DIR / "data" / "passages"  / "full_w_context" / "netconfig_en2.json"
    # output_path = BASE_DIR / "data" / "debate_results" / "agents_v2" / "test2" / "netconfig_result.json"
    
    input_path = BASE_DIR / "data" / "passages"  / "full_w_context" / "teleqna_passage.json"
    output_path = BASE_DIR / "data" / "debate_results" / "agents_v2" / "mas" /  "teleqna" / "teleqna_result.json"
    
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    # 1. 입력 데이터 로드
    with open(input_path, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
    # [수정] raw_data 대신 loaded_data를 사용하고, 리스트 형식인지 보장합니다.
    if isinstance(loaded_data, dict):
        data = [loaded_data]
    elif isinstance(loaded_data, list):
        data = loaded_data
    else:
        print(f"❌ Invalid data format: {type(loaded_data)}")
        return

    print(f"Loaded {len(data)} items to process.")

    # 2. 기존 결과 로드 및 필터링 로직
    existing_results_map = {} 
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded_results = json.load(f)
                for r in loaded_results:
                    res_id = str(r.get('id', ''))
                    if res_id:
                        existing_results_map[res_id] = r
            print(f"✅ Loaded {len(existing_results_map)} existing results from disk.")
        except Exception:
            print("⚠️ Error reading existing output. Starting fresh.")
    
    for item in data:
        if not isinstance(item, dict): continue
        item_id = item.get('id', '')
        q_raw = item.get('question', '')
        q_key = normalize_key(q_raw)
        if q_key in existing_results_map:
            existing_results_map[q_key]['id'] = clean_text_for_save(q_raw)

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
        print("======================================global context:", global_context[:20])
    elif "netbench" in input_path.name.lower():
        dataset_type = "descriptive"

    print(f"Dataset type detected: {dataset_type}")

    # --- [수정됨] 재실행 대상 선정 로직 (align.py의 빠진 번호 기준) ---
    existing_int_ids = []
    for res_id in existing_results_map.keys():
        try:
            existing_int_ids.append(int(res_id))
        except ValueError:
            pass

    missing_ids_set = set()
    if existing_int_ids:
        min_id = min(existing_int_ids)
        max_id = max(existing_int_ids)
        expected = set(range(min_id, max_id + 1))
        actual = set(existing_int_ids)
        missing = sorted(list(expected - actual))
        if missing:
            print(f"빠진 ID 개수: {len(missing)}개")
            print(f"빠진 ID 목록: {missing}")
            missing_ids_set = set(missing)
        else:
            print("빠진 ID가 없습니다.")
    else:
        print("정수형 ID를 찾을 수 없습니다.")

    items_to_process = []
    skipped_count = 0
    none_retry_count = 0
    
    for item in data:
        item_id = str(item.get('id', ''))
        
        # 조건 1: 결과 파일에 해당 ID가 없는 경우 (새 데이터 또는 누락 데이터)
        if item_id not in existing_results_map:
            items_to_process.append(item)
            continue
            
        # 조건 2: 결과는 있지만 답변이 [NONE]인 경우 (재시도)
        existing_res = existing_results_map[item_id]
        pred_ans = str(existing_res.get('debate2_answer', '')).strip().upper()
        
        if pred_ans == "[NONE]":
            items_to_process.append(item)
            none_retry_count += 1
        else:
            skipped_count += 1

    print(f"📊 원본 데이터 총합: {len(data)}")
    print(f"⏭️ 스킵 (정상 처리됨): {skipped_count}")
    print(f"🔄 재시도 ([NONE] 답변): {none_retry_count}")
    print(f"🚀 최종 실행 대기: {len(items_to_process)}")
    
    MAX_WORKERS = 50
    start_total_time = time.time()
    os.makedirs(output_path.parent, exist_ok=True)
    
    print(f"Starting parallel execution with {MAX_WORKERS} workers...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_item = {
            executor.submit(process_item, app, item, i, len(data), dataset_type, global_context): item['question']
            for i, item in enumerate(items_to_process)
        }
        
        processed_count = 0
        for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Processing"):
            res = future.result()
            if res:
                res_id = str(res['id'])
                existing_results_map[res_id] = res
                processed_count += 1
                
                # 주기적 저장
                if processed_count % 10 == 0:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(list(existing_results_map.values()), f, indent=4, ensure_ascii=False)
    final_list = list(existing_results_map.values())
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_list, f, indent=4, ensure_ascii=False)
    
    print(f"✅ Done! Saved total {len(final_list)} results to {output_path}")

if __name__ == "__main__":
    main()