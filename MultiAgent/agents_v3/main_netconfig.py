"""
main_netconfig.py
-----------------
NetConfig 데이터셋에 대한 Multi-Agent 토론 실행 메인 모듈. (agents_v3)

전체 파이프라인:
1. ConfigManager로 장비별 .cfg 파일 로드 (=== START/END OF CONFIG === 헤더 포함)
2. LangGraph 그래프 빌드:
   Collector → Verifier → Synthesizer → Supporter → Critic
   - Verifier: 점수 기반 관련성 게이트 (score < 6 → Collector 재호출, 최대 3회)
   - Critic:   ACCEPT → END, REVISE → Synthesizer 재호출 (최대 3회)
3. ThreadPoolExecutor로 병렬 처리 (MAX_WORKERS=10)
4. 결과를 output JSON에 주기적 저장 (10건마다) + 최종 저장

타임아웃: 항목당 300초 (LLM API hang 방지)
재실행 최적화: 이미 처리된 항목 스킵, [NONE]/[TIMEOUT] 재시도
"""

import re
import sys
import os
import json
import time
import logging
import traceback
import threading
from pathlib import Path
from typing import Dict, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from langgraph.graph import StateGraph, END

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable

CURRENT_DIR = Path(__file__).resolve().parent
BASE_DIR = CURRENT_DIR.parent
sys.path.append(str(BASE_DIR))

from agents_v3.state import NetAgentState
from agents_v3.model_loader import init_models
import agents_v3.debate1 as d1
import agents_v3.debate2 as d2


# ==========================================
# 📂 ConfigManager
# ==========================================
def find_config_dir(lab_key: str, netconfig2_dir: Path) -> Optional[Path]:
    """
    랩 키에 해당하는 configs/ 디렉토리 경로를 반환한다.
    존재하지 않으면 None 반환.
    """
    config_dir = netconfig2_dir / lab_key / "configs"
    return config_dir if config_dir.exists() else None


class ConfigManager:
    """
    configs/ 디렉토리 내 개별 .cfg 파일을 읽어 장비별로 캐싱.

    get_all_configs()는 === START/END OF CONFIG === 헤더를 붙여 반환하므로
    Collector LLM이 장비 경계를 명확히 인식할 수 있다.
    get_filtered_configs()는 질문에 언급된 장비명만 word-boundary 매칭하여 반환한다.
    """

    def __init__(self, config_dir: Path, logger: logging.Logger):
        self.config_dir = config_dir
        self.logger = logger
        self._cache: Dict[str, str] = {}
        self._load_all()

    def _load_all(self):
        if not self.config_dir.exists():
            self.logger.warning(f"Config directory not found: {self.config_dir}")
            return
        for cfg_path in sorted(self.config_dir.glob("*.cfg")):
            try:
                hostname = cfg_path.stem
                content = cfg_path.read_text(encoding='utf-8', errors='ignore')
                self._cache[hostname.lower()] = content
            except Exception as e:
                self.logger.error(f"Failed to load {cfg_path}: {e}")
        self.logger.info(f"Loaded {len(self._cache)} configuration files from {self.config_dir}")

    def get_all_configs(self) -> str:
        """전체 장비 config를 === START/END === 헤더와 함께 반환."""
        combined = ""
        for host in sorted(self._cache.keys()):
            combined += f"\n=== START OF CONFIG: {host.upper()} ===\n"
            combined += self._cache[host]
            combined += f"\n=== END OF CONFIG: {host.upper()} ===\n"
        return combined

    def get_filtered_configs(self, q_text: str) -> str:
        """
        질문에 언급된 장비명을 word-boundary 매칭하여 해당 config만 헤더와 함께 반환.
        매칭 실패 시 전체 반환 (집계/전체 장비 대상 질문 대응).
        'pe1'이 'pe10'에 잘못 매칭되는 오류 방지.
        """
        found_parts = []
        for host in sorted(self._cache.keys()):
            pattern = r'\b' + re.escape(host) + r'\b'
            if re.search(pattern, q_text, re.IGNORECASE):
                found_parts.append(f"\n=== START OF CONFIG: {host.upper()} ===\n")
                found_parts.append(self._cache[host])
                found_parts.append(f"\n=== END OF CONFIG: {host.upper()} ===\n")
        if found_parts:
            return "\n".join(found_parts)
        # 매칭 실패 → 전체 반환 (iBGP full-mesh, 가장 많은 인터페이스 등 집계 질문)
        return self.get_all_configs()


# ==========================================
# 🔄 LangGraph 그래프 빌드
# ==========================================
def build_graph(ablation: str = "no_verifier"):
    """
    LangGraph 상태 그래프를 빌드한다.

    ablation:
        "full"        : Collector → Verifier → Synthesizer → Supporter → Skeptic
        "no_verifier" : Collector → Synthesizer → Supporter → Skeptic (Verifier 제거)
        "no_critic"   : Collector → Verifier → Synthesizer → END (Supporter+Skeptic 제거)
    """
    workflow = StateGraph(NetAgentState)

    workflow.add_node("Collector",   d1.collector_node)
    workflow.add_node("Synthesizer", d1.synthesizer_node)

    if ablation == "no_critic":
        workflow.add_node("Verifier", d1.verifier_node)
        workflow.set_entry_point("Collector")
        workflow.add_edge("Collector", "Verifier")

        def check_verifier_nc(state):
            v_status = state.get("verifier_status", "RELEVANT").upper()
            if v_status == "IRRELEVANT" and state.get("outer_loop_count", 0) < 3:
                return "re_collect"
            return "to_synthesizer"

        workflow.add_conditional_edges(
            "Verifier", check_verifier_nc,
            {"to_synthesizer": "Synthesizer", "re_collect": "Collector"}
        )
        workflow.add_edge("Synthesizer", END)

    elif ablation == "no_verifier":
        workflow.add_node("Supporter", d2.supporter_node)
        workflow.add_node("Skeptic",   d2.skeptic_node)
        workflow.set_entry_point("Collector")
        workflow.add_edge("Collector",   "Synthesizer")
        workflow.add_edge("Synthesizer", "Supporter")
        workflow.add_edge("Supporter",   "Skeptic")

        def check_debate_nv(state):
            status = state.get("status", "ACCEPT").upper()
            if status == "ACCEPT":
                return "end"
            elif status == "REVISE":
                return "end" if state.get("inner_turn_count", 0) >= 3 else "revise"
            return "end"

        workflow.add_conditional_edges(
            "Skeptic", check_debate_nv,
            {"end": END, "revise": "Synthesizer"}
        )

    else:  # "full"
        workflow.add_node("Verifier",  d1.verifier_node)
        workflow.add_node("Supporter", d2.supporter_node)
        workflow.add_node("Skeptic",   d2.skeptic_node)
        workflow.set_entry_point("Collector")
        workflow.add_edge("Collector",   "Verifier")
        workflow.add_edge("Synthesizer", "Supporter")
        workflow.add_edge("Supporter",   "Skeptic")

        def check_verifier_status(state):
            v_status = state.get("verifier_status", "RELEVANT").upper()
            if v_status == "IRRELEVANT" and state.get("outer_loop_count", 0) < 3:
                return "re_collect"
            return "to_synthesizer"

        workflow.add_conditional_edges(
            "Verifier", check_verifier_status,
            {"to_synthesizer": "Synthesizer", "re_collect": "Collector"}
        )

        def check_debate_status(state):
            status = state.get("status", "ACCEPT").upper()
            if status == "ACCEPT":
                return "end"
            elif status == "REVISE":
                return "end" if state.get("inner_turn_count", 0) >= 3 else "revise"
            return "end"

        workflow.add_conditional_edges(
            "Skeptic", check_debate_status,
            {"end": END, "revise": "Synthesizer"}
        )

    return workflow.compile()


# ==========================================
# 🚀 단일 항목 처리 함수
# ==========================================
def process_item(app, item: dict, index: int, total: int,
                 dataset_type: str, global_context=None) -> Optional[dict]:
    """
    데이터셋 항목 하나를 처리하여 결과를 반환한다.

    Context 결정 (netconfig + ConfigManager):
    - L4/L5 또는 토폴로지 키워드 포함 → get_all_configs() (전체 장비)
    - 그 외 → get_filtered_configs(question) (장비명 매칭, 실패 시 전체)

    Args:
        app:            컴파일된 LangGraph 실행 객체
        item:           데이터셋 항목
        index:          처리 인덱스 (로그용)
        total:          전체 항목 수 (로그용)
        dataset_type:   데이터셋 종류
        global_context: ConfigManager 또는 str

    Returns:
        dict: 처리 결과, None: 오류 발생 시
    """
    q_text    = item.get('question', '')
    item_id   = item.get('id', '')
    item_level = item.get('level', '')

    # 컨텍스트 결정
    context = ""
    if dataset_type == "netconfig" and isinstance(global_context, ConfigManager):
        # 토폴로지 전체가 필요한 질문 판별
        # ('route' 제외: "routing protocol" 등 단일 장비 질문도 걸림)
        # ('number' 타입 제외: "BGP AS number" 등 단일 장비 질문도 포함됨)
        topo_keywords = ('hop', 'path', 'block', 'flow', 'reach', 'traceroute', 'fail', 'down', 'between')
        needs_full_topo = (
            item_level in ('L4', 'L5') or
            any(kw in q_text.lower() for kw in topo_keywords)
        )
        context = (global_context.get_all_configs() if needs_full_topo
                   else global_context.get_filtered_configs(q_text))
    elif isinstance(global_context, str) and global_context:
        context = global_context
    else:
        context = item.get('gold_context', '') or item.get('context', '')

    # 초기 상태 (모든 필드 기본값 초기화)
    initial_state = {
        "id":                   item_id,
        "question":             q_text,
        "context":              context,
        "dataset_type":         dataset_type,
        "options":              item.get('options', item.get('choices', '')),
        "level":                item_level,
        "raw_data":             "",
        "current_passage":      "",
        "candidate_answer":     "",
        "final_answer":         "",
        "debate1_answer":       "",
        "proponent_responses":  [],
        "critic_feedbacks":     [],
        "pro_argument":         "",
        "con_argument":         "",
        "synthesizer_feedback": "",
        "hop_count":            0,
        "inner_turn_count":     0,
        "outer_loop_count":     0,
        "verifier_status":      "RELEVANT",
        "status":               "INIT",
        "critic_feedback":      "",
        "feedback_to_collector": "",
        "history":              [],
        "device_db":            {},
        "next_hop_device":      None,
        "all_device_names":     list(global_context._cache.keys()) if isinstance(global_context, ConfigManager) else [],
        "candidate_answers":    [],
        "collector_retry_log":  [],
        "synthesizer_retry_log": [],
        "token_usage":          {"model_a": {"input": 0, "output": 0},
                                 "model_b": {"input": 0, "output": 0}},
    }

    gold_raw   = item.get('answer', item.get('gold_answer', ''))
    start_time = time.time()

    _log = logging.getLogger("agents_v3")
    _log.info(
        "[Item][%s] START (%d/%d) | level=%s | answer_type=%s | question=%.120s",
        item_id, index + 1, total, item_level,
        item.get('answer_type', ''), q_text
    )

    try:
        # 300초 타임아웃 — LLM API hang 방지 (threading.Thread 사용, 중첩 executor 회피)
        _result_box = [None]
        _exc_box    = [None]

        def _run():
            try:
                _result_box[0] = app.invoke(initial_state, config={"recursion_limit": 60})
            except Exception as _e:
                _exc_box[0] = _e

        _t = threading.Thread(target=_run, daemon=True)
        _t.start()
        _t.join(timeout=300)

        if _t.is_alive():
            _log.warning("[Item][%s] TIMEOUT after 300s — skipping.", item_id)
            return {
                "question_id":          item_id,
                "question":             q_text,
                "gold":                 gold_raw,
                "candidate_answer":     "[TIMEOUT]",
                "level":                item_level,
                "category":             item.get('category', ''),
                "answer_type":          item.get('answer_type', 'text'),
                "answer_status":        item.get('answer_status', 'OK'),
                "format_parseable":     False,
                "format_completeness":  0.0,
                "current_passage":      "",
                "final_status":         "TIMEOUT",
                "candidate_answers":    [],
                "collector_retries":    [],
                "synthesizer_retries":  [],
                "proponent_history":    [],
                "critic_history":       [],
                "duration":             time.time() - start_time,
            }

        if _exc_box[0] is not None:
            raise _exc_box[0]

        out = _result_box[0]
        if out is None:
            raise RuntimeError("app.invoke returned None")

        candidate_answer = out.get('candidate_answer', '')
        fin_status       = out.get('status', '')
        syn_rounds       = out.get('inner_turn_count', 0)
        _log.info(
            "[Item][%s] DONE | status=%s | synthesizer_rounds=%d | duration=%.1fs | answer=%.200s",
            item_id, fin_status, syn_rounds, time.time() - start_time, candidate_answer
        )
        token_usage = out.get('token_usage', {"input": 0, "output": 0})
        return {
            "question_id":          item_id,
            "question":             q_text,
            "gold":                 gold_raw,
            "candidate_answer":     candidate_answer,
            "raw_pred":             candidate_answer,   # analyze_results.py 호환 필드
            "level":                item_level,
            "category":             item.get('category', ''),
            "answer_type":          item.get('answer_type', 'text'),
            "answer_status":        item.get('answer_status', 'OK'),
            "format_parseable":     True,
            "format_completeness":  1.0,
            "current_passage":      out.get('current_passage', ''),
            "final_status":         fin_status,
            "candidate_answers":    out.get('candidate_answers', []),
            "collector_retries":    out.get('collector_retry_log', []),
            "synthesizer_retries":  out.get('synthesizer_retry_log', []),
            "proponent_history":    out.get('proponent_responses', []),
            "critic_history":       out.get('critic_feedbacks', []),
            "duration":             time.time() - start_time,
            "token_usage":          token_usage,
        }
    except Exception as e:
        _log.error("[Item][%s] ERROR: %s", item_id, e, exc_info=True)
        return None


# ==========================================
# 📊 결과 저장
# ==========================================
def _write_output(rows, output_path, dataset_meta, lab_name,
                  elapsed=None, model_tag="mas_v3"):
    """analyze_results.py 호환 포맷으로 결과를 저장한다."""
    from collections import defaultdict

    type_counts      = defaultdict(int)
    type_parseable   = defaultdict(int)
    type_completeness = defaultdict(list)
    for r in rows:
        atype = str(r.get('answer_type', 'text'))
        type_counts[atype] += 1
        if r.get('format_parseable', True):
            type_parseable[atype] += 1
        type_completeness[atype].append(float(r.get('format_completeness', 1.0)))

    format_stability = {
        atype: {
            "parse_success_rate": round(type_parseable[atype] / cnt, 4) if cnt else 0,
            "avg_completeness":   round(sum(type_completeness[atype]) / len(type_completeness[atype]), 4),
            "count":              cnt,
        }
        for atype, cnt in type_counts.items()
    }

    # 토큰 집계 (모델별)
    def _sum_model(rows, model_key, direction):
        return sum(r.get('token_usage', {}).get(model_key, {}).get(direction, 0) for r in rows)

    valid_rows = [r for r in rows if r.get('token_usage')]
    n = len(valid_rows)

    a_in  = _sum_model(valid_rows, 'model_a', 'input')
    a_out = _sum_model(valid_rows, 'model_a', 'output')
    b_in  = _sum_model(valid_rows, 'model_b', 'input')
    b_out = _sum_model(valid_rows, 'model_b', 'output')
    total_in  = a_in  + b_in
    total_out = a_out + b_out

    token_stats = {
        "model_a": {                              # Verifier + Synthesizer + Supporter
            "total_input":  a_in,
            "total_output": a_out,
            "avg_input":    round(a_in  / n, 1) if n else 0,
            "avg_output":   round(a_out / n, 1) if n else 0,
        },
        "model_b": {                              # Collector + Skeptic
            "total_input":  b_in,
            "total_output": b_out,
            "avg_input":    round(b_in  / n, 1) if n else 0,
            "avg_output":   round(b_out / n, 1) if n else 0,
        },
        "total": {
            "total_input":  total_in,
            "total_output": total_out,
            "total_tokens": total_in + total_out,
            "avg_input":    round(total_in  / n, 1) if n else 0,
            "avg_output":   round(total_out / n, 1) if n else 0,
            "avg_total":    round((total_in + total_out) / n, 1) if n else 0,
        },
        "measured_samples": n,
    }

    payload = {
        "meta": {
            "model":            model_tag,
            "model_tag":        model_tag,
            "backend":          "mas_langgraph_v3",
            "lab":              lab_name,
            "lab_folder":       dataset_meta.get('lab_name', lab_name),
            "date":             time.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_sec":     round(elapsed, 2) if elapsed is not None else None,
            "total_samples":    len(rows),
            "pipeline_version": dataset_meta.get('pipeline_version', ''),
            "question_lang":    dataset_meta.get('question_lang', 'en'),
        },
        "format_stability": format_stability,
        "token_stats":      token_stats,
        "results":          rows,
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)


# ==========================================
# 🏃 랩 단위 실행
# ==========================================
def run_lab(app, lab_dir: Path, output_dir: Path,
            logger: logging.Logger, model_tag: str = "mas_v3",
            target_answer_type: Optional[str] = None,
            target_level: Optional[str] = None,
            force_rerun: bool = False):
    """
    단일 랩 디렉토리에 대해 평가를 실행한다.

    Args:
        app:                컴파일된 LangGraph 실행 객체
        lab_dir:            netconfig2/lab_x/ 디렉토리
        output_dir:         결과 저장 디렉토리
        logger:             로거
        model_tag:          출력 파일명 태그
        target_answer_type: 특정 answer_type만 처리 (None=전체)
        force_rerun:        기존 결과 무시하고 재실행
    """
    lab_name = lab_dir.name

    # JSON 파일 탐색 (*_en.json 우선, 없으면 첫 번째 json)
    json_files = sorted(lab_dir.glob("*_en.json")) or sorted(lab_dir.glob("*.json"))
    if not json_files:
        logger.warning(f"[{lab_name}] JSON 파일 없음, 스킵.")
        return
    input_path = json_files[0]

    # ConfigManager 초기화
    configs_dir   = lab_dir / "configs"
    global_context = ConfigManager(configs_dir, logger)
    logger.info(f"[{lab_name}] Config keys: {list(global_context._cache.keys())}")

    # 출력 경로 결정 (재실행 시 최신 파일에 이어쓰기)
    timestamp    = time.strftime('%Y%m%d_%H%M%S')
    output_path  = output_dir / f"results_raw_{model_tag}_{timestamp}.json"
    if not force_rerun:
        existing = sorted(output_dir.glob(f"results_raw_{model_tag}_*.json"), reverse=True)
        if existing:
            output_path = existing[0]

    logger.info(f"[{lab_name}] {input_path.name} → {output_path.name}")

    # 입력 데이터 로드
    with open(input_path, 'r', encoding='utf-8') as f:
        loaded = json.load(f)
    if isinstance(loaded, dict) and 'questions' in loaded:
        dataset_meta = loaded.get('meta', {})
        data         = loaded['questions']
    elif isinstance(loaded, list):
        dataset_meta = {}
        data         = loaded
    else:
        logger.error(f"[{lab_name}] Invalid data format: {type(loaded)}")
        return
    logger.info(f"[{lab_name}] Loaded {len(data)} items.")

    # 기존 결과 로드 (중단 후 재시작 지원)
    existing_results_map: dict = {}
    os.makedirs(output_dir, exist_ok=True)
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                payload = json.load(f)
            rows = payload.get('results', payload) if isinstance(payload, dict) else payload
            for r in rows:
                res_id = str(r.get('question_id', r.get('id', '')))
                if res_id:
                    existing_results_map[res_id] = r
            logger.info(f"[{lab_name}] 기존 결과 {len(existing_results_map)}건 로드.")
        except Exception:
            logger.warning(f"[{lab_name}] 기존 결과 로드 실패. 처음부터 시작.")

    # 처리 대상 선정 (미처리 + [NONE]/[TIMEOUT] 재시도)
    items_to_process = []
    skipped_count    = 0
    none_retry_count = 0
    for item in data:
        item_id = str(item.get('id', ''))
        if target_answer_type and item.get('answer_type') != target_answer_type:
            skipped_count += 1
            continue
        if target_level and item.get('level') != target_level:
            skipped_count += 1
            continue
        if item_id not in existing_results_map:
            items_to_process.append(item)
            continue
        pred    = str(existing_results_map[item_id].get('raw_pred', '')).strip().upper()
        passage = str(existing_results_map[item_id].get('current_passage', '')).strip()
        if pred in ('[NONE]', '[TIMEOUT]') or not pred or not passage or force_rerun:
            items_to_process.append(item)
            none_retry_count += 1
        else:
            skipped_count += 1

    logger.info(
        f"[{lab_name}] 총합: {len(data)}  스킵: {skipped_count}  "
        f"재시도: {none_retry_count}  실행: {len(items_to_process)}"
    )
    if not items_to_process:
        logger.info(f"[{lab_name}] 처리할 항목 없음.")
        return

    # 병렬 처리
    MAX_WORKERS = 20
    start_total = time.time()
    logger.info(f"[{lab_name}] Starting parallel execution ({MAX_WORKERS} workers)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_item, app, item, i, len(data), "netconfig", global_context
            ): item.get('id', i)
            for i, item in enumerate(items_to_process)
        }
        processed_count = 0
        for future in tqdm(as_completed(futures), total=len(items_to_process), desc=f"[{lab_name}]"):
            res = future.result()
            if res:
                existing_results_map[str(res['question_id'])] = res
                processed_count += 1
                if processed_count % 10 == 0:
                    _write_output(list(existing_results_map.values()),
                                  output_path, dataset_meta, lab_name)

    elapsed    = time.time() - start_total
    final_rows = list(existing_results_map.values())
    _write_output(final_rows, output_path, dataset_meta, lab_name,
                  elapsed=elapsed, model_tag=model_tag)
    logger.info(f"[{lab_name}] ✅ Done! {len(final_rows)}건 저장 → {output_path}  ({elapsed:.1f}s)")


# ==========================================
# 🏁 메인
# ==========================================
def main():
    """
    netconfig2/ 하위 랩을 순서대로 처리한다.
    결과: data/debate_results/v3/labX/results_raw_mas_v3_TIMESTAMP.json

    평가 실행:
        python Experiment/code/NetConfigQA2_2/analyze_results.py \
            data/debate_results/v3/labC/results_raw_mas_v3_*.json
    """
    # MODEL_TAG          = "mistral3_8b_gpt_oss_20b"
    MODEL_TAG          = "gpt_oss_20b_2"
    FORCE_RERUN        = False
    # ablation 설정: "full" | "no_verifier" | "no_critic"
    ABLATION           = "full"
    target_answer_type = None  # None=전체, 문자열=해당 타입만 (예: "text", "set_str")
    target_level       = None  # None=전체, 문자열=해당 레벨만 (예: "L1", "L2", "L3")

    # 로거 설정 (파일 + 콘솔 동시 출력)
    log_dir = BASE_DIR / "data" / "log"
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "agents_v3_netconfig.log", encoding='utf-8'),
            logging.StreamHandler(sys.stdout),
        ]
    )
    logger = logging.getLogger("agents_v3")

    logger.info("Initializing Models...")
    init_models()
    app = build_graph(ablation=ABLATION)

    netconfig2_dir = BASE_DIR / "data" / "original" / "netconfig2"
    # ablation별 출력 경로 분리: results2/MODEL_TAG 또는 ablation/no_verifier/MODEL_TAG
    if ABLATION == "full":
        output_base = BASE_DIR / "data" / "debate_results" / "agents_v3" / "results2" / MODEL_TAG
    else:
        output_base = BASE_DIR / "data" / "debate_results" / "agents_v3" / "ablation" / ABLATION / MODEL_TAG

    labs_to_run = {
        "lab_a": "labA"
        # "lab_b": "labB",
        # "lab_c": "labC", 
        # "lab_d": "labD"
    }

    for lab_key, out_name in labs_to_run.items():
        lab_dir    = netconfig2_dir / lab_key
        output_dir = output_base / out_name

        if not lab_dir.exists():
            logger.warning(f"⚠️ {lab_dir} 없음, 스킵.")
            continue

        run_lab(
            app=app,
            lab_dir=lab_dir,
            output_dir=output_dir,
            logger=logger,
            model_tag=MODEL_TAG,
            target_answer_type=target_answer_type,
            target_level=target_level,
            force_rerun=FORCE_RERUN,
        )

    logger.info("전체 완료.")


if __name__ == "__main__":
    main()
