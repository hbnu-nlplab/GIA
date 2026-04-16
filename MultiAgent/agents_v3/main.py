"""
main.py
-------
범용 Multi-Agent 토론 실행 메인 모듈. (agents_v3)

지원 데이터셋 타입:
  - descriptive     (NetBench 등 서술형)
  - short_answer    (TeleQuAD 등 단답형)
  - multiple_choice (TeleQnA 등 객관식)

파이프라인: Collector → Verifier → Synthesizer → Supporter → Skeptic
  - Verifier: 점수 기반 관련성 게이트 (score < 6 → Collector 재호출, 최대 3회)
  - Skeptic:  ACCEPT → END, REVISE → Synthesizer 재호출 (최대 3회)

결과 포맷:
  라운드별 Collector 재시도 이력(collector_retries), Synthesizer 재시도 이력
  (synthesizer_retries), Supporter/Skeptic 히스토리, 토큰 사용량 포함.
"""

import re
import sys
import os
import json
import time
import logging
import threading
import traceback
from pathlib import Path
from typing import Optional
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

from agents_v3.state import NetAgentState
from agents_v3.model_loader import init_models
import agents_v3.debate1 as d1
import agents_v3.debate2 as d2


# ==========================================
# 🔄 LangGraph 그래프 빌드
# ==========================================
def build_graph(ablation: str = "full"):
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

    Context 결정:
      - global_context가 str이면 전 항목 공유 컨텍스트로 사용
      - 없으면 item['context'] 또는 item['gold_context'] 사용

    Returns:
        dict: 처리 결과 (collector_retries, synthesizer_retries, token_usage 포함)
        None: 오류 발생 시
    """
    q_text    = item.get('question', '')
    item_id   = str(item.get('id', ''))
    item_level = item.get('level', '')

    # 컨텍스트 결정
    if isinstance(global_context, str) and global_context:
        context = global_context
    elif dataset_type in ("short_answer", "descriptive"):
        # gold passage가 있는 타입은 passage 필드 우선 사용 (context는 짧은 요약이라 Verifier 탈락 多)
        context = item.get('passage', '') or item.get('context', '') or item.get('gold_context', '')
    else:
        context = item.get('context', '') or item.get('gold_context', '')

    initial_state = {
        "id":                    item_id,
        "question":              q_text,
        "context":               context,
        "dataset_type":          dataset_type,
        "options":               item.get('options', item.get('choices', '')),
        "level":                 item_level,
        "raw_data":              "",
        "current_passage":       "",
        "candidate_answer":      "",
        "final_answer":          "",
        "debate1_answer":        "",
        "proponent_responses":   [],
        "critic_feedbacks":      [],
        "pro_argument":          "",
        "con_argument":          "",
        "synthesizer_feedback":  "",
        "hop_count":             0,
        "inner_turn_count":      0,
        "outer_loop_count":      0,
        "verifier_status":       "RELEVANT",
        "status":                "INIT",
        "critic_feedback":       "",
        "feedback_to_collector": "",
        "history":               [],
        "device_db":             {},
        "next_hop_device":       None,
        "all_device_names":      [],
        "candidate_answers":     [],
        "collector_retry_log":   [],
        "synthesizer_retry_log": [],
        "token_usage":           {"model_a": {"input": 0, "output": 0},
                                  "model_b": {"input": 0, "output": 0}},
    }

    gold_raw   = item.get('answer', item.get('gold_answer', ''))
    start_time = time.time()

    _log = logging.getLogger("agents_v3")
    _log.info(
        "[Item][%s] START (%d/%d) | level=%s | dataset_type=%s | question=%.120s",
        item_id, index + 1, total, item_level, dataset_type, q_text
    )

    try:
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
                "question_id":         item_id,
                "question":            q_text,
                "gold":                gold_raw,
                "candidate_answer":    "[TIMEOUT]",
                "raw_pred":            "[TIMEOUT]",
                "level":               item_level,
                "category":            item.get('category', ''),
                "answer_type":         item.get('answer_type', 'text'),
                "format_parseable":    False,
                "format_completeness": 0.0,
                "current_passage":     "",
                "final_status":        "TIMEOUT",
                "candidate_answers":   [],
                "collector_retries":   [],
                "synthesizer_retries": [],
                "proponent_history":   [],
                "critic_history":      [],
                "duration":            time.time() - start_time,
                "token_usage":         {"model_a": {"input": 0, "output": 0},
                                        "model_b": {"input": 0, "output": 0}},
            }

        if _exc_box[0] is not None:
            raise _exc_box[0]

        out = _result_box[0]
        if out is None:
            raise RuntimeError("app.invoke returned None")

        candidate_answer = out.get('candidate_answer', '')
        # 최종 답변이 비어있으면 rounds 중 첫 번째 비어있지 않은 답변으로 fallback
        if not candidate_answer.strip():
            for ca in out.get('candidate_answers', []):
                ans = ca.get('answer', '') if isinstance(ca, dict) else str(ca)
                if ans.strip():
                    candidate_answer = ans
                    break
        fin_status       = out.get('status', '')
        syn_rounds       = out.get('inner_turn_count', 0)
        _log.info(
            "[Item][%s] DONE | status=%s | syn_rounds=%d | duration=%.1fs | answer=%.200s",
            item_id, fin_status, syn_rounds, time.time() - start_time, candidate_answer
        )

        return {
            "question_id":         item_id,
            "question":            q_text,
            "gold":                gold_raw,
            "candidate_answer":    candidate_answer,
            "raw_pred":            candidate_answer,
            "level":               item_level,
            "category":            item.get('category', ''),
            "answer_type":         item.get('answer_type', 'text'),
            "format_parseable":    True,
            "format_completeness": 1.0,
            "current_passage":     out.get('current_passage', ''),
            "final_status":        fin_status,
            "candidate_answers":   out.get('candidate_answers', []),
            "collector_retries":   out.get('collector_retry_log', []),
            "synthesizer_retries": out.get('synthesizer_retry_log', []),
            "proponent_history":   out.get('proponent_responses', []),
            "critic_history":      out.get('critic_feedbacks', []),
            "duration":            time.time() - start_time,
            "token_usage":         out.get('token_usage', {"model_a": {"input": 0, "output": 0},
                                                           "model_b": {"input": 0, "output": 0}}),
        }

    except Exception as e:
        _log.error("[Item][%s] ERROR: %s", item_id, e, exc_info=True)
        return None


# ==========================================
# 📊 결과 저장
# ==========================================
def _write_output(rows: list, output_path: Path, dataset_meta: dict,
                  dataset_name: str, elapsed=None, model_tag: str = "mas_v3"):
    """결과를 JSON으로 저장한다. 토큰 집계 포함."""
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
        "model_a": {"total_input": a_in,  "total_output": a_out,
                    "avg_input": round(a_in / n, 1) if n else 0,
                    "avg_output": round(a_out / n, 1) if n else 0},
        "model_b": {"total_input": b_in,  "total_output": b_out,
                    "avg_input": round(b_in / n, 1) if n else 0,
                    "avg_output": round(b_out / n, 1) if n else 0},
        "total":   {"total_input": total_in, "total_output": total_out,
                    "total_tokens": total_in + total_out,
                    "avg_input": round(total_in / n, 1) if n else 0,
                    "avg_output": round(total_out / n, 1) if n else 0,
                    "avg_total": round((total_in + total_out) / n, 1) if n else 0},
        "measured_samples": n,
    }

    payload = {
        "meta": {
            "model":            model_tag,
            "model_tag":        model_tag,
            "backend":          "mas_langgraph_v3",
            "dataset":          dataset_name,
            "date":             time.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_sec":     round(elapsed, 2) if elapsed is not None else None,
            "total_samples":    len(rows),
            "pipeline_version": dataset_meta.get('pipeline_version', ''),
        },
        "format_stability": format_stability,
        "token_stats":      token_stats,
        "results":          rows,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)


# ==========================================
# 🏃 데이터셋 단위 실행
# ==========================================
def run_dataset(app, input_path: Path, output_dir: Path,
                dataset_type: str, logger: logging.Logger,
                model_tag: str = "mas_v3",
                global_context=None,
                force_rerun: bool = False):
    """
    단일 데이터셋 파일에 대해 평가를 실행한다.

    Args:
        app:            컴파일된 LangGraph 실행 객체
        input_path:     입력 JSON 파일 경로
        output_dir:     결과 저장 디렉토리
        dataset_type:   "descriptive" | "short_answer" | "multiple_choice"
        logger:         로거
        model_tag:      출력 파일명 태그
        global_context: 전 항목 공유 컨텍스트 문자열 (없으면 item별 context 사용)
        force_rerun:    기존 결과 무시하고 재실행
    """
    dataset_name = input_path.stem

    # 출력 경로 결정 (재실행 시 최신 파일에 이어쓰기)
    timestamp   = time.strftime('%Y%m%d_%H%M%S')
    output_path = output_dir / f"results_raw_{model_tag}_{timestamp}.json"
    if not force_rerun:
        existing = sorted(output_dir.glob(f"results_raw_{model_tag}_*.json"), reverse=True)
        if existing:
            output_path = existing[0]

    logger.info(f"[{dataset_name}] {input_path.name} → {output_path.name}")

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
        logger.error(f"[{dataset_name}] Invalid data format: {type(loaded)}")
        return
    logger.info(f"[{dataset_name}] Loaded {len(data)} items.")

    # 기존 결과 로드 (중단 후 재시작 지원)
    existing_results_map: dict = {}
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                payload = json.load(f)
            rows = payload.get('results', payload) if isinstance(payload, dict) else payload
            for r in rows:
                res_id = str(r.get('question_id', r.get('id', '')))
                if res_id:
                    existing_results_map[res_id] = r
            logger.info(f"[{dataset_name}] 기존 결과 {len(existing_results_map)}건 로드.")
        except Exception:
            logger.warning(f"[{dataset_name}] 기존 결과 로드 실패. 처음부터 시작.")

    # 처리 대상 선정 (미처리 + [NONE]/[TIMEOUT] 재시도)
    items_to_process = []
    skipped_count    = 0
    none_retry_count = 0
    for item in data:
        item_id = str(item.get('id', ''))
        if item_id not in existing_results_map:
            items_to_process.append(item)
            continue
        pred = str(existing_results_map[item_id].get('raw_pred', '')).strip().upper()
        if pred in ('[NONE]', '[TIMEOUT]') or not pred or force_rerun:
            items_to_process.append(item)
            none_retry_count += 1
        else:
            skipped_count += 1

    # 테스트 실행 시 샘플 수 제한 (0이면 전체 실행)
    MAX_SAMPLES = 0
    if MAX_SAMPLES > 0:
        items_to_process = items_to_process[:MAX_SAMPLES]

    logger.info(
        f"[{dataset_name}] 총합: {len(data)}  스킵: {skipped_count}  "
        f"재시도: {none_retry_count}  실행: {len(items_to_process)}"
    )
    if not items_to_process:
        logger.info(f"[{dataset_name}] 처리할 항목 없음.")
        return

    # 병렬 처리
    MAX_WORKERS = 50
    start_total = time.time()
    logger.info(f"[{dataset_name}] Starting parallel execution ({MAX_WORKERS} workers)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_item, app, item, i, len(data), dataset_type, global_context
            ): item.get('id', i)
            for i, item in enumerate(items_to_process)
        }
        processed_count = 0
        for future in tqdm(as_completed(futures), total=len(items_to_process), desc=f"[{dataset_name}]"):
            res = future.result()
            if res:
                existing_results_map[str(res['question_id'])] = res
                processed_count += 1
                if processed_count % 10 == 0:
                    _write_output(list(existing_results_map.values()),
                                  output_path, dataset_meta, dataset_name, model_tag=model_tag)

    elapsed    = time.time() - start_total
    final_rows = list(existing_results_map.values())
    _write_output(final_rows, output_path, dataset_meta, dataset_name,
                  elapsed=elapsed, model_tag=model_tag)
    logger.info(f"[{dataset_name}] Done! {len(final_rows)}건 저장 → {output_path}  ({elapsed:.1f}s)")


# ==========================================
# 🏁 메인
# ==========================================
def _detect_dataset_type(filename: str) -> str:
    """파일명 기반으로 데이터셋 타입을 감지한다."""
    name = filename.lower()
    if "teleqna" in name:
        return "multiple_choice"
    elif "telequad" in name:
        return "short_answer"
    elif "netbench" in name:
        return "descriptive"
    return "descriptive"


def main():
    MODEL_TAG   = "gpt_oss_20b"
    FORCE_RERUN = False

    # 로거 설정
    log_dir = BASE_DIR / "data" / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "agents_v3_main.log", encoding='utf-8'),
            logging.StreamHandler(sys.stdout),
        ]
    )
    logger = logging.getLogger("agents_v3")

    passages_dir  = BASE_DIR / "data" / "passages" / "full_w_context"
    output_base   = BASE_DIR / "data" / "debate_results" / "agents_v3" / "others" 

    # ── 실행할 데이터셋 목록 ─────────────────────────────────────────
    # key:   passages_dir 아래 JSON 파일명 (확장자 제외)
    # value: output_base 아래 출력 폴더명
    # None=자동 감지 (파일명 기반), 직접 지정도 가능: "short_answer" 등
    datasets_to_run = {
        # "telequad_passage": ("telequad2", None),
        "teleqna_passage":  ("teleqna2",  None),
        # "netbench_passage": ("netbench2", None),  
    }
    # ─────────────────────────────────────────────────────────────────

    logger.info("Initializing Models...")
    init_models()
    app = build_graph()

    for file_key, (out_name, dtype) in datasets_to_run.items():
        input_path = passages_dir / f"{file_key}.json"
        if not input_path.exists():
            logger.warning(f"Input file not found: {input_path} — skipping.")
            continue

        dataset_type = dtype or _detect_dataset_type(input_path.name)
        logger.info(f"Dataset: {input_path.name} | Type: {dataset_type}")

        run_dataset(
            app=app,
            input_path=input_path,
            output_dir=output_base / out_name / MODEL_TAG,
            dataset_type=dataset_type,
            logger=logger,
            model_tag=MODEL_TAG,
            global_context=None,
            force_rerun=FORCE_RERUN,
        )

    logger.info("전체 완료.")


if __name__ == "__main__":
    main()
