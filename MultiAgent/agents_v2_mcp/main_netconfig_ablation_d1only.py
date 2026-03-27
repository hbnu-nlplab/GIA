"""
main_netconfig_ablation_d1only.py
----------------------------------
[Ablation A2] Debate-1 Only 실험용 메인 모듈.

Full system(A3)과의 차이:
- Collector → Verifier → Synthesizer 까지만 실행
- Supporter(Agent 4), Skeptic(Agent 5) 없음
- Synthesizer의 candidate_answer를 최종 답변으로 사용

출력 필드는 full system과 동일 구조 유지 (debate2_answer = debate1_answer).
"""

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

from agents_v2.state import NetAgentState
from agents_v2.model_loader import init_models
import agents_v2.debate1 as d1


def normalize_key(text):
    if not text: return ""
    return re.sub(r'[\n\\"*]+', '', str(text)).strip()


def clean_text_for_save(text):
    return str(text).strip()


def load_netconfigs(base_path):
    config_path = base_path / "data" / "original" / "netconfig" / "configs.txt"
    if not config_path.exists():
        print(f"⚠️ Warning: Config file not found: {config_path}")
        return {}
    print(f"📂 Loading config file from: {config_path}")
    try:
        text = config_path.read_text(encoding='utf-8', errors='ignore')
        result = {}
        current_device = None
        current_lines = []
        for line in text.splitlines():
            m = re.match(r'^\[(.+?)\.cfg\]$', line.strip())
            if m:
                if current_device:
                    result[current_device.lower()] = "\n".join(current_lines)
                current_device = m.group(1)
                current_lines = []
            else:
                current_lines.append(line)
        if current_device:
            result[current_device.lower()] = "\n".join(current_lines)
        print(f"✅ Loaded {len(result)} device configs: {list(result.keys())}")
        return result
    except Exception as e:
        print(f"❌ Error reading {config_path.name}: {e}")
        return {}


# ==========================================
# 🔄 Debate-1 Only 그래프 빌드
# ==========================================
def build_graph():
    """
    Debate-1 only 그래프: Collector → Verifier → Synthesizer → END
    Supporter, Skeptic 없음.
    """
    workflow = StateGraph(NetAgentState)

    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("Verifier", d1.verifier_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)

    workflow.set_entry_point("Collector")
    workflow.add_edge("Collector", "Verifier")
    workflow.add_edge("Verifier", "Synthesizer")
    workflow.add_edge("Synthesizer", END)

    return workflow.compile()


# ==========================================
# 🚀 단일 항목 처리
# ==========================================
def process_item(app, item, index, total, dataset_type, global_context=None):
    q_text = item.get('question', '')
    item_id = item.get('id', '')

    # 컨텍스트 결정 (main_netconfig.py와 동일한 로직)
    context = ""
    if dataset_type == "netconfig" and isinstance(global_context, dict):
        answer_type = item.get('answer_type', '')
        topo_keywords = ('hop', 'path', 'route', 'block', 'flow', 'reach', 'traceroute')
        needs_full_topo = (
            answer_type == 'number' or
            any(kw in q_text.lower() for kw in topo_keywords)
        )
        if needs_full_topo:
            context = "\n".join(global_context.values())
        else:
            found_configs = []
            for device_name, config_content in global_context.items():
                if device_name.lower() in q_text.lower():
                    found_configs.append(config_content)
            context = "\n".join(found_configs) if found_configs else "\n".join(global_context.values())
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
        "raw_data": "",
        "current_passage": "",
        "candidate_answer": "",
        "final_answer": "",
        "debate1_answer": "",
        "pro_argument": "",
        "con_argument": "",
        "hop_count": 0,
        "inner_turn_count": 0,
        "outer_loop_count": 0,
        "status": "INIT",
        "critic_feedback": "",
        "feedback_to_collector": "",
        "proponent_responses": [],
        "critic_feedbacks": [],
        "history": [],
        "device_db": {},
        "next_hop_device": None
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
            "debate1_answer": ans,
            # full system과 비교 편의를 위해 동일 필드 유지
            "proponent_defense": "",
            "critic_critique": "",
            "debate2_answer": ans,   # Debate-1 only이므로 debate1_answer와 동일
            "debate2_rounds": 0,
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
        traceback.print_exc()
        return None


class Tee:
    def __init__(self, name, mode):
        self.file = open(name, mode, encoding='utf-8')
        self.stdout = sys.stdout
        sys.stdout = self

    def __del__(self):
        if sys.stdout == self:
            sys.stdout = self.stdout
        self.file.close()

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
        self.file.flush()

    def flush(self):
        self.file.flush()
        self.stdout.flush()


def main():
    target_answer_type = None
    FORCE_RERUN = False

    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    sys.stdout = Tee(log_dir / "ablation_d1only.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [Ablation A2: Debate-1 Only] Initializing...")

    init_models()
    app = build_graph()

    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "netconfig_en2.json"
    output_path = BASE_DIR / "data" / "debate_results" / "ablation" / "d1only" / "netconfig" / "netconfig_result.json"

    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
    data = [loaded_data] if isinstance(loaded_data, dict) else loaded_data
    print(f"Loaded {len(data)} items.")

    # 기존 결과 로드 (재시작 지원)
    existing_results_map = {}
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                for r in json.load(f):
                    res_id = str(r.get('id', ''))
                    if res_id:
                        existing_results_map[res_id] = r
            print(f"✅ Loaded {len(existing_results_map)} existing results.")
        except Exception:
            print("⚠️ Error reading existing output. Starting fresh.")

    # 데이터셋 타입 감지 및 config 로드
    dataset_type = "netconfig"
    global_context = load_netconfigs(BASE_DIR)
    print(f"Config keys: {list(global_context.keys())}")

    # 처리 대상 선정
    items_to_process = []
    skipped_count = 0
    none_retry_count = 0

    for item in data:
        item_id = str(item.get('id', ''))
        if target_answer_type and item.get('answer_type') != target_answer_type:
            skipped_count += 1
            continue
        if item_id not in existing_results_map:
            items_to_process.append(item)
            continue
        existing_res = existing_results_map[item_id]
        pred_ans = str(existing_res.get('debate2_answer', '')).strip().upper()
        if pred_ans == "[NONE]" or FORCE_RERUN:
            items_to_process.append(item)
            none_retry_count += 1
        else:
            skipped_count += 1

    print(f"📊 총합: {len(data)} | ⏭️ 스킵: {skipped_count} | 🔄 재시도: {none_retry_count} | 🚀 실행: {len(items_to_process)}")

    MAX_WORKERS = 50
    os.makedirs(output_path.parent, exist_ok=True)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_item = {
            executor.submit(process_item, app, item, i, len(data), dataset_type, global_context): item['question']
            for i, item in enumerate(items_to_process)
        }

        processed_count = 0
        for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Processing"):
            res = future.result()
            if res:
                existing_results_map[str(res['id'])] = res
                processed_count += 1
                if processed_count % 10 == 0:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(list(existing_results_map.values()), f, indent=4, ensure_ascii=False)

    final_list = list(existing_results_map.values())
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_list, f, indent=4, ensure_ascii=False)

    print(f"✅ Done! Saved {len(final_list)} results to {output_path}")


if __name__ == "__main__":
    main()
