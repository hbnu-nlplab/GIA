#!/usr/bin/env python3
"""
NetAlly Evaluation Runner

NetAlly MAS+MCP 시스템을 대상으로 NetConfigQA 데이터셋을 평가합니다.
SSE 스트리밍 응답을 파싱하여 analyze_results.py 호환 형식으로 저장합니다.

Usage:
    python scripts/run_netally_eval.py \
        --dataset /path/to/dataset_en.json \
        --lab Lab-B \
        --limit 10
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL = "http://localhost:8111"
SAVE_INTERVAL = 10
REQUEST_TIMEOUT = 600  # 10 min per question


# ---------------------------------------------------------------------------
# SSE Parsing
# ---------------------------------------------------------------------------

def send_question(
    base_url: str,
    question: str,
    answer_type: str = "text",
    level: str = "",
    timeout: int = REQUEST_TIMEOUT,
) -> Dict[str, Any]:
    """Send a question to NetAlly chat SSE API and parse the streamed response.

    Returns dict with keys: answer, tools_used, latency_ms, error.
    """
    start = time.perf_counter()
    tools_used: List[str] = []
    answer_chunks: List[str] = []
    error: Optional[str] = None
    mas_debug: Dict[str, Any] = {}

    try:
        resp = requests.post(
            f"{base_url}/api/chat",
            json={"message": question, "answer_type": answer_type, "level": level},
            stream=True,
            timeout=timeout,
        )
        resp.raise_for_status()

        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            data_str = line[6:]  # strip "data: "
            if data_str == "[DONE]":
                break
            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")

            if etype == "tool_call":
                tool_name = event.get("name", "")
                if tool_name:
                    tools_used.append(tool_name)

            elif etype == "tool_output":
                # Extract MAS debug info from TeamMultiAdapterRuntime bridge result
                content = event.get("content", "")
                if isinstance(content, str):
                    try:
                        content = json.loads(content)
                    except (json.JSONDecodeError, TypeError):
                        content = {}
                if isinstance(content, dict):
                    meta_data = content.get("meta", {})
                    debug = meta_data.get("mas_debug", {}) if isinstance(meta_data, dict) else {}
                    if debug:
                        mas_debug = {
                            "mas_outer_loops": debug.get("outer_loop_count", 0),
                            "mas_inner_turns": debug.get("inner_turn_count", 0),
                            "mas_tool_calls": debug.get("tool_calls_log", []),
                            "mas_status": debug.get("status", ""),
                        }

            elif etype == "answer":
                chunk = event.get("content", "")
                if chunk:
                    answer_chunks.append(chunk)

            elif etype == "complete":
                break

    except requests.exceptions.Timeout:
        error = "TIMEOUT"
    except requests.exceptions.ConnectionError:
        error = "CONNECTION_ERROR"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    raw_answer = "".join(answer_chunks).strip()

    return {
        "answer": raw_answer,
        "tools_used": tools_used,
        "latency_ms": elapsed_ms,
        "error": error,
        "mas_debug": mas_debug,
    }


# ---------------------------------------------------------------------------
# Prediction Cleaning
# ---------------------------------------------------------------------------

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_CODE_BLOCK_RE = re.compile(r"```(?:\w*\n)?(.*?)```", re.DOTALL)
_FINAL_ANSWER_RE = re.compile(
    r"(?:final\s*answer|answer)\s*[:：]\s*", re.IGNORECASE
)
_BOLD_RE = re.compile(r"\*\*(.*?)\*\*")


def clean_prediction(raw: str) -> str:
    """Strip markdown artifacts, think tags, 'Final Answer:' prefixes, etc."""
    if not raw:
        return ""
    text = _THINK_RE.sub("", raw)

    # If the entire answer is wrapped in a single code block, extract inner content
    code_blocks = _CODE_BLOCK_RE.findall(text)
    if code_blocks and text.strip().startswith("```"):
        text = code_blocks[0].strip()

    # Remove "Final Answer:" or "Answer:" prefix
    text = _FINAL_ANSWER_RE.sub("", text).strip()

    # Remove bold markers
    text = _BOLD_RE.sub(r"\1", text)

    # Remove leading/trailing quotes if they wrap the whole string
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"', "`"):
        text = text[1:-1]

    return text.strip()


# ---------------------------------------------------------------------------
# Dataset Loading
# ---------------------------------------------------------------------------

def load_dataset(path: str) -> Dict[str, Any]:
    """Load dataset JSON and return the full dict."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "questions" not in data:
        raise ValueError(f"Dataset missing 'questions' key: {path}")
    return data


# ---------------------------------------------------------------------------
# Resume Support
# ---------------------------------------------------------------------------

def load_existing_results(output_path: str) -> Dict[str, Dict]:
    """Load already-processed question_ids from an existing output file."""
    if not os.path.exists(output_path):
        return {}
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {r["question_id"]: r for r in data.get("results", [])}
    except (json.JSONDecodeError, KeyError):
        return {}


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------

def save_output(output_path: str, meta: Dict, results: List[Dict]) -> None:
    """Atomically write results to JSON."""
    tmp_path = output_path + ".tmp"
    payload = {"meta": meta, "results": results}
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, output_path)


# ---------------------------------------------------------------------------
# Main Evaluation Loop
# ---------------------------------------------------------------------------

def run_eval(args: argparse.Namespace) -> None:
    dataset = load_dataset(args.dataset)
    questions = dataset["questions"]
    dataset_meta = dataset.get("meta", {})

    if args.limit and args.limit > 0:
        questions = questions[: args.limit]

    # Derive lab_folder from dataset path
    dataset_path = Path(args.dataset)
    lab_folder = dataset_meta.get("lab_folder", dataset_path.parent.parent.name)
    lab_label = args.lab or dataset_meta.get("lab", lab_folder)

    # Output path
    if args.output:
        output_path = args.output
    else:
        results_dir = Path(__file__).resolve().parent.parent / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(
            results_dir / f"netally_eval_{lab_folder}_{ts}.json"
        )

    # Resume
    existing = load_existing_results(output_path)
    if existing:
        print(f"[resume] Found {len(existing)} existing results in {output_path}")

    # Meta
    start_time = time.time()
    meta = {
        "model": "NetAlly-MAS+MCP",
        "model_tag": args.model_tag,
        "backend": "netally",
        "lab": lab_label,
        "lab_folder": lab_folder,
        "date": datetime.now().isoformat(),
        "duration_sec": 0,
        "total_samples": len(questions),
        "dataset": dataset_path.name,
    }

    results: List[Dict] = list(existing.values())
    processed_ids = set(existing.keys())
    new_count = 0

    pbar = tqdm(questions, desc="NetAlly Eval", unit="q")
    for item in pbar:
        qid = item.get("question_id", item.get("id", ""))
        if not qid:
            qid = f"q_{questions.index(item)}"

        if qid in processed_ids:
            pbar.set_postfix({"status": "skip"})
            continue

        question_text = item["question"]
        gold = item.get("answer", item.get("gold", ""))
        level = item.get("level", "")
        category = item.get("category", "")
        answer_type = item.get("answer_type", "text")

        pbar.set_postfix({"qid": qid[:20], "level": level})

        resp = send_question(
            base_url=args.base_url,
            question=question_text,
            answer_type=answer_type,
            level=level,
            timeout=args.timeout,
        )

        raw_pred = resp["answer"]
        pred = clean_prediction(raw_pred)
        tools = resp["tools_used"]
        error = resp["error"]

        gold_answer_status = str(item.get("answer_status", item.get("status", "OK")))
        run_status = "ERROR" if error else "OK"

        result_entry = {
            "question_id": qid,
            "question": question_text,
            "gold": str(gold),
            "raw_pred": raw_pred,
            "pred": pred,
            "level": level,
            "category": category,
            "answer_type": answer_type,
            "answer_status": gold_answer_status,
            "gold_answer_status": gold_answer_status,
            "run_status": run_status,
            "tools_used": tools,
            "tool_count": len(tools),
            "latency_ms": resp["latency_ms"],
            "format_parseable": error is None and len(pred) > 0,
            "format_completeness": 1.0 if (error is None and len(pred) > 0) else 0.0,
        }
        if error:
            result_entry["error"] = error

        # MAS pipeline debug info (present when using TeamMultiAdapterRuntime)
        if resp.get("mas_debug"):
            result_entry.update(resp["mas_debug"])

        results.append(result_entry)
        processed_ids.add(qid)
        new_count += 1

        # Intermediate save
        if new_count % SAVE_INTERVAL == 0:
            meta["duration_sec"] = round(time.time() - start_time, 1)
            save_output(output_path, meta, results)

    # Final save
    meta["duration_sec"] = round(time.time() - start_time, 1)
    save_output(output_path, meta, results)

    # Summary
    ok_count = sum(
        1
        for r in results
        if r.get("run_status", "ERROR" if r.get("error") else "OK") == "OK"
    )
    err_count = len(results) - ok_count
    avg_latency = (
        sum(
            r["latency_ms"]
            for r in results
            if r.get("run_status", "ERROR" if r.get("error") else "OK") == "OK"
        ) / max(ok_count, 1)
    )
    avg_tools = (
        sum(
            r["tool_count"]
            for r in results
            if r.get("run_status", "ERROR" if r.get("error") else "OK") == "OK"
        ) / max(ok_count, 1)
    )

    print(f"\n{'=' * 60}")
    print(f"  NetAlly Evaluation Complete")
    print(f"{'=' * 60}")
    print(f"  Total questions : {len(questions)}")
    print(f"  Processed (new) : {new_count}")
    print(f"  OK / Error      : {ok_count} / {err_count}")
    print(f"  Avg latency     : {avg_latency:,.0f} ms")
    print(f"  Avg tools/q     : {avg_tools:.1f}")
    print(f"  Duration        : {meta['duration_sec']:.1f} sec")
    print(f"  Output          : {output_path}")
    print(f"{'=' * 60}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run NetAlly evaluation on NetConfigQA dataset",
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to dataset JSON file (English)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON path (default: auto-generated in results/)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only first N questions (0 = all)",
    )
    parser.add_argument(
        "--lab",
        default=None,
        help="Lab label (e.g. 'Lab-B'). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--model-tag",
        default="netally-gpt4omini",
        help="Model tag for result metadata (default: netally-gpt4omini)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"NetAlly API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=REQUEST_TIMEOUT,
        help=f"Per-question timeout in seconds (default: {REQUEST_TIMEOUT})",
    )
    return parser.parse_args()


if __name__ == "__main__":
    run_eval(parse_args())
