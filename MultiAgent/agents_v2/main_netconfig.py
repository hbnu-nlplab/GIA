"""
main_netconfig.py
-----------------
NetConfig 데이터셋에 대한 Multi-Agent 토론 실행 메인 모듈.

전체 파이프라인:
1. 입력 JSON 파일 로드 (질문 + 정답 데이터)
2. 네트워크 설정 파일(configs.txt) 로드 → 장비별 딕셔너리로 파싱
3. LangGraph 그래프 빌드 (Collector→Verifier→Synthesizer→Supporter→Skeptic)
4. ThreadPoolExecutor로 병렬 처리
5. 결과를 output JSON에 주기적 저장 (10건마다) + 최종 저장

재실행 최적화:
- 이미 처리된 ID는 스킵 (중단 후 재시작 가능)
- [NONE] 답변은 재시도 대상으로 포함
- 빠진 ID 번호 자동 감지 및 출력
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
    # tqdm 미설치 환경에서는 그냥 이터러블로 사용
    def tqdm(iterable, *args, **kwargs):
        return iterable

# 현재 파일 위치 기준으로 프로젝트 루트 계산
CURRENT_DIR = Path(__file__).resolve().parent
BASE_DIR = CURRENT_DIR.parent
sys.path.append(str(BASE_DIR))

from agents_v2.state import NetAgentState
from agents_v2.model_loader import init_models
import agents_v2.debate1 as d1
import agents_v2.debate2 as d2


def normalize_key(text):
    """질문 텍스트를 딕셔너리 키로 정규화한다 (줄바꿈/따옴표/별표 제거)."""
    if not text: return ""
    return re.sub(r'[\n\\"*]+', '', str(text)).strip()


def clean_text_for_save(text):
    """저장용 텍스트 정제 (앞뒤 공백 제거)."""
    return str(text).strip()


def normalize_answer(text):
    """
    답변 비교를 위한 정규화.
    앞뒤 공백, 따옴표 제거 후 소문자로 변환한다.
    """
    if not text:
        return ""
    return str(text).strip().strip('"').strip("'").lower().strip()


def load_netconfigs(base_path):
    """
    configs.txt 파일을 읽어 장비명별 설정 내용 딕셔너리를 반환한다.

    파일 형식:
        [DeviceName.cfg]
        hostname DeviceName
        interface ...
        ...
        [NextDevice.cfg]
        ...

    Args:
        base_path (Path): 프로젝트 루트 경로
    Returns:
        dict: {장비명(소문자): 설정내용(str)} 형태의 딕셔너리
              파일이 없으면 빈 딕셔너리 반환
    """
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
            # [DeviceName.cfg] 헤더 패턴 감지
            m = re.match(r'^\[(.+?)\.cfg\]$', line.strip())
            if m:
                if current_device:
                    # 이전 장비의 내용 저장 (소문자 키)
                    result[current_device.lower()] = "\n".join(current_lines)
                current_device = m.group(1)
                current_lines = []
            else:
                current_lines.append(line)
        # 마지막 장비 내용 저장
        if current_device:
            result[current_device.lower()] = "\n".join(current_lines)
        print(f"✅ Loaded {len(result)} device configs: {list(result.keys())}")
        return result
    except Exception as e:
        print(f"❌ Error reading {config_path.name}: {e}")
        return {}


# ==========================================
# 🔄 LangGraph 그래프 빌드
# ==========================================
def build_graph():
    """
    5개 에이전트 노드로 구성된 LangGraph 상태 그래프를 빌드한다.

    노드:
        Collector  → Verifier → Synthesizer → Supporter → Skeptic

    Skeptic 판정 후 분기:
        ACCEPT           → END (토론 종료)
        CONTINUE_DEBATE  → Supporter 재호출 (inner_turn_count < 3인 경우)
        NEED_MORE_INFO   → Collector 재호출 (outer_loop_count < 3인 경우)
        한계 초과         → END (강제 종료)

    Returns:
        CompiledGraph: 컴파일된 LangGraph 실행 객체
    """
    workflow = StateGraph(NetAgentState)

    # 노드 등록
    workflow.add_node("Collector", d1.collector_node)
    workflow.add_node("Verifier", d1.verifier_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)
    workflow.add_node("Supporter", d2.supporter_node)
    workflow.add_node("Skeptic", d2.skeptic_node)

    # 선형 엣지: Collector → Verifier → Synthesizer → Supporter → Skeptic
    workflow.set_entry_point("Collector")
    workflow.add_edge("Collector", "Verifier")
    workflow.add_edge("Verifier", "Synthesizer")
    workflow.add_edge("Synthesizer", "Supporter")
    workflow.add_edge("Supporter", "Skeptic")

    def check_debate_status(state):
        """Skeptic 판정 결과에 따른 다음 노드 결정 함수."""
        status = state.get("status", "ACCEPT").upper()
        if status == "ACCEPT":
            return "end"
        elif status == "CONTINUE_DEBATE":
            # 내부 반복 2회 초과 시 강제 종료
            return "end" if state.get("inner_turn_count", 0) >= 3 else "continue_inner"
        elif status == "NEED_MORE_INFO":
            # 외부 반복 2회 초과 시 강제 종료
            return "end" if state.get("outer_loop_count", 0) >= 3 else "backtrack_outer"
        return "end"

    # 조건부 엣지: Skeptic → {END | Supporter | Collector}
    workflow.add_conditional_edges(
        "Skeptic", check_debate_status,
        {"end": END, "continue_inner": "Supporter", "backtrack_outer": "Collector"}
    )
    return workflow.compile()


# ==========================================
# 🚀 단일 항목 처리 함수
# ==========================================
def process_item(app, item, index, total, dataset_type, global_context=None):
    """
    데이터셋 항목 하나를 처리하여 결과를 반환한다.

    컨텍스트 결정 로직 (netconfig 타입):
    - 질문에 장비명이 포함되어 있으면 해당 장비의 설정만 추출하여 컨텍스트로 사용
    - 장비명이 없으면 item의 gold_context 사용
    - 그것도 없으면 "[NONE]"

    Args:
        app: 컴파일된 LangGraph 실행 객체
        item (dict): 데이터셋 항목 (question, id, gold_answer 등 포함)
        index (int): 현재 처리 인덱스 (로그용)
        total (int): 전체 항목 수 (로그용)
        dataset_type (str): 데이터셋 종류
        global_context: netconfig는 dict(장비별 설정), 기타는 str 또는 None

    Returns:
        dict: 처리 결과 (id, question, gold_answer, 답변들, 소요시간 등)
        None: 오류 발생 시
    """
    q_text = item.get('question', '')
    item_id = item.get('id', '')

    # 컨텍스트 결정
    item_level = item.get('level', '')
    context = ""
    if dataset_type == "netconfig" and isinstance(global_context, dict):
        # L4/L5는 항상 전체 토폴로지 context 사용 (시뮬레이션/What-If 질문)
        # 그 외: answer_type이 'number'이거나 경로/홉 키워드가 있으면 전체 config 사용
        answer_type = item.get('answer_type', '')
        topo_keywords = ('hop', 'path', 'route', 'block', 'flow', 'reach', 'traceroute')
        needs_full_topo = (
            item_level in ('L4', 'L5') or
            answer_type == 'number' or
            any(kw in q_text.lower() for kw in topo_keywords)
        )

        if needs_full_topo:
            # 전체 장비 config 제공
            context = "\n".join(global_context.values())
        else:
            # 질문에 언급된 장비명과 일치하는 설정 블록만 추출
            found_configs = []
            for device_name, config_content in global_context.items():
                if device_name.lower() in q_text.lower():
                    found_configs.append(config_content)

            if found_configs:
                context = "\n".join(found_configs)
            else:
                # 장비명 매칭 실패 시 → 전체 토폴로지 컨텍스트 사용
                # (집계/전체 장비 대상 질문: iBGP full-mesh, 가장 많은 인터페이스 등)
                context = "\n".join(global_context.values())
    elif isinstance(global_context, str) and global_context:
        context = global_context
    else:
        context = item.get('gold_context', '') or item.get('context', '')

    # 초기 상태 구성 (모든 필드를 기본값으로 초기화)
    initial_state = {
        "id": item_id,
        "question": q_text,
        "context": context,
        "dataset_type": dataset_type,
        "options": item.get('options', ''),
        "level": item_level,
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
            "debate1_passage": out.get('current_passage', ''),          # Verifier 정제 패시지
            "debate1_answer": out.get('debate1_answer', ''),             # 1차 토론 답변
            "proponent_defense": out.get('pro_argument', ''),            # Supporter 마지막 의견
            "critic_critique": out.get('con_argument', ''),              # Critic 마지막 비판
            "feedback_to_collector": out.get('feedback_to_collector', ''), # Collector 재수집 지시
            "proponent_history": out.get('proponent_responses', []),     # Supporter 전체 이력
            "critic_history": out.get('critic_feedbacks', []),           # Critic 전체 이력
            "final_status": out.get('status', ''),                       # 최종 판정 (ACCEPT 등)
            "debate2_answer": ans,                                       # 최종 답변
            "debate2_rounds": out.get('inner_turn_count', 0),            # 내부 토론 라운드 수
            "duration": time.time() - start_time
        }

        # netconfig 타입의 경우 추가 메타데이터 포함
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
    """
    표준 출력(stdout)을 파일과 콘솔에 동시에 기록하는 클래스.
    실행 로그를 파일에 저장하면서 터미널에도 출력한다.
    """
    def __init__(self, name, mode):
        self.file = open(name, mode, encoding='utf-8')
        self.stdout = sys.stdout
        sys.stdout = self  # stdout을 이 객체로 교체

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
    """
    메인 실행 함수.

    처리 순서:
    1. 로그 파일 설정 (Tee로 파일+콘솔 동시 출력)
    2. 모델 및 그래프 초기화
    3. 입력 데이터 로드
    4. 기존 결과 로드 (재시작 최적화)
    5. 처리 대상 필터링 (미처리 + [NONE] 재시도)
    6. 병렬 처리 (ThreadPoolExecutor)
    7. 결과 저장
    """
    target_answer_type = None # None이면 전체 실행, 문자열이면 해당 타입만 실행
    FORCE_RERUN = False  # True로 설정하면 [NONE]이 아닌 기존 결과도 재실행

    # 로그 디렉토리 생성 및 Tee 설정
    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    sys.stdout = Tee(log_dir / "debate_execution_full_w_context.log", "a")

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Initializing Models...")

    init_models()
    app = build_graph()

    # 입력/출력 경로 설정
    input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "netconfig_en2.json"
    # output_path = BASE_DIR / "data" / "debate_results" / "ablation" / "single" / "netconfig" / "netconfig_result.json"
    output_path = BASE_DIR / "data" / "debate_results" / "agents_v2" / "full_w_context10" / "netconfig" / "netconfig_result.json"

    # 다른 데이터셋으로 전환 시 위 경로를 주석처리하고 아래 사용
    # input_path = BASE_DIR / "data" / "passages" / "full_w_context" / "netbench_passage.json"
    # output_path = BASE_DIR / "data" / "debate_results" / "agents_v2" / "full_w_context3" / "netbench" / "netbench_result.json"

    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return

    # Step 1: 입력 데이터 로드
    with open(input_path, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
    # dict인 경우 리스트로 감싸서 통일
    if isinstance(loaded_data, dict):
        data = [loaded_data]
    elif isinstance(loaded_data, list):
        data = loaded_data
    else:
        print(f"❌ Invalid data format: {type(loaded_data)}")
        return

    print(f"Loaded {len(data)} items to process.")

    # Step 2: 기존 결과 로드 (중단 후 재시작 지원)
    existing_results_map = {}  # {id(str): result_dict}
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

    # Step 3: 데이터셋 타입 자동 감지 (파일명 기반)
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
        print("======================================global context keys:", list(global_context.keys()))
    elif "netbench" in input_path.name.lower():
        dataset_type = "descriptive"

    print(f"Dataset type detected: {dataset_type}")

    # Step 4: 빠진 ID 번호 자동 감지 (연속 범위에서 누락된 ID 찾기)
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

    # Step 5: 처리 대상 선정
    # - 조건 1: 기존 결과에 없는 새 항목
    # - 조건 2: 답변이 [NONE]인 항목 (재시도)
    items_to_process = []
    skipped_count = 0
    none_retry_count = 0

    for item in data:
        item_id = str(item.get('id', ''))

        # target_answer_type이 지정된 경우 해당 타입만 처리
        if target_answer_type and item.get('answer_type') != target_answer_type:
            skipped_count += 1
            continue

        if item_id not in existing_results_map:
            # 미처리 항목
            items_to_process.append(item)
            continue

        # 기존 결과가 있지만 [NONE]이거나 강제 재실행인 경우 재시도
        existing_res = existing_results_map[item_id]
        pred_ans = str(existing_res.get('debate2_answer', '')).strip().upper()
        if pred_ans == "[NONE]" or FORCE_RERUN:
            items_to_process.append(item)
            none_retry_count += 1
        else:
            skipped_count += 1

    print(f"📊 원본 데이터 총합: {len(data)}")
    print(f"⏭️ 스킵 (정상 처리됨): {skipped_count}")
    print(f"🔄 재시도 ([NONE] 답변): {none_retry_count}")
    print(f"🚀 최종 실행 대기: {len(items_to_process)}")

    # Step 6: 병렬 처리
    MAX_WORKERS = 50 # 동시 처리 스레드 수 (과도한 병렬 요청은 rate limit 유발)
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

                # 10건마다 중간 저장 (프로세스 중단 시 손실 최소화)
                if processed_count % 10 == 0:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(list(existing_results_map.values()), f, indent=4, ensure_ascii=False)

    # Step 7: 최종 저장
    final_list = list(existing_results_map.values())
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_list, f, indent=4, ensure_ascii=False)

    print(f"✅ Done! Saved total {len(final_list)} results to {output_path}")


if __name__ == "__main__":
    main()
