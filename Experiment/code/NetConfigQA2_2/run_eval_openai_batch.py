"""
NetConfigQA2.0 Evaluator — OpenRouter Parallel Runner

This script preserves the evaluation flow of `run_eval_vllm_offline.py` and
swaps only the inference engine:

    vLLM local batch -> OpenRouter chat.completions parallel calls

Important:
    - OpenRouter does not expose the OpenAI Batch API used by the older file.
    - "Batch" here means local parallel execution with a bounded worker pool.
    - Result schema is kept compatible with the vLLM evaluator so downstream
      analysis scripts can keep consuming `results_raw_vllm_*.json`.

Usage examples:
    python run_eval_openai_batch.py --model gpt-4o-mini --lab A
    python run_eval_openai_batch.py --model gpt-4o-mini --lab A --limit 10 --max-workers 4
    python run_eval_openai_batch.py --model openrouter-gpt-oss-120b-free --lab A --max-workers 2
    python run_eval_openai_batch.py --model gpt-4o-mini --lab A --dry-run
"""

import argparse
import csv
import datetime
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from openai import OpenAI

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from run_eval_vllm_offline import (
    Config as OfflineConfig,
    ConfigManager,
    build_messages,
    dedupe_preserve_order,
    extract_answer_legacy,
    extract_api_response_meta,
    extract_api_text_response,
    find_config_dir,
    find_latest_dataset,
    infer_dataset_language,
    measure_format_stability,
    resolve_max_tokens,
)

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable


class Config:
    BASE_DIR = Path(__file__).parent
    RESULT_DIR = BASE_DIR / "results_2"
    LOG_DIR = BASE_DIR / "logs"
    DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    DEFAULT_MAX_WORKERS = 4
    DEFAULT_TIMEOUT_SEC = 300
    DEFAULT_RETRY_ATTEMPTS = 4
    DEFAULT_RETRY_BACKOFF_SEC = 30
    DEFAULT_REQUEST_DELAY_SEC = 0.25
    OPENROUTER_MAX_CONSECUTIVE_429 = 3


def load_env_candidates() -> None:
    if load_dotenv is None:
        return

    repo_root = Config.BASE_DIR.parents[2]
    candidates = [
        repo_root / ".env",
        repo_root / "MultiAgent" / ".env",
        repo_root / "config" / ".env",
    ]
    for path in candidates:
        if path.exists():
            load_dotenv(dotenv_path=path, override=False)


def get_log_dir(model_name: str, lab_name: str) -> Path:
    clean_name = model_name.replace("/", "_").replace(":", "_")
    log_dir = Config.LOG_DIR / "openrouter" / clean_name / f"Lab{lab_name}"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def setup_logger(model_name: str, lab_name: str) -> Tuple[logging.Logger, str]:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = model_name.replace("/", "_").replace(":", "_")
    log_file = get_log_dir(model_name, lab_name) / f"eval_openrouter_{clean_name}_Lab{lab_name}_{timestamp}.log"

    logger = logging.getLogger(f"NetConfigQA_openrouter_{clean_name}_{lab_name}_{timestamp}")
    logger.setLevel(logging.INFO)
    logger.handlers = []

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(sh)

    return logger, timestamp


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def resolve_labs(labs: List[str]) -> List[str]:
    normalized = dedupe_preserve_order(labs)
    if any(l.lower() == "all" for l in normalized):
        return list(OfflineConfig.LABS.keys())
    invalid = [l for l in normalized if l not in OfflineConfig.LABS]
    if invalid:
        raise ValueError(f"Invalid lab tags: {invalid}. Valid labs: {list(OfflineConfig.LABS.keys())}")
    return normalized


def build_model_aliases() -> Dict[str, Dict[str, Any]]:
    aliases: Dict[str, Dict[str, Any]] = {
        "gpt-4o-mini": {
            "request_model": "openai/gpt-4o-mini",
            "display": "GPT-4o-mini",
            "api_delay_sec": Config.DEFAULT_REQUEST_DELAY_SEC,
            "reasoning": None,
        },
        "openai/gpt-4o-mini": {
            "request_model": "openai/gpt-4o-mini",
            "display": "GPT-4o-mini",
            "api_delay_sec": Config.DEFAULT_REQUEST_DELAY_SEC,
            "reasoning": None,
        },
    }

    for model_key, info in OfflineConfig.MODEL_DICT.items():
        backend = info.get("backend")
        if backend != "openrouter":
            continue
        aliases[model_key] = {
            "request_model": info.get("hf_path", model_key),
            "display": info.get("display", model_key),
            "api_delay_sec": info.get("api_delay_sec", 4.0),
            "reasoning": info.get("openrouter_reasoning"),
        }
        hf_path = info.get("hf_path")
        if hf_path:
            aliases[hf_path] = aliases[model_key]

    return aliases


def resolve_model_keys(models: List[str]) -> List[str]:
    normalized = dedupe_preserve_order(models)
    aliases = build_model_aliases()
    if any(m.lower() == "all" for m in normalized):
        return [key for key in aliases.keys() if "/" not in key]
    return normalized


def resolve_model_spec(model_key: str) -> Dict[str, Any]:
    aliases = build_model_aliases()
    if model_key in aliases:
        spec = dict(aliases[model_key])
        spec["model_tag"] = model_key
        return spec

    if "/" in model_key:
        return {
            "model_tag": model_key,
            "request_model": model_key,
            "display": model_key,
            "api_delay_sec": Config.DEFAULT_REQUEST_DELAY_SEC,
            "reasoning": None,
        }

    raise ValueError(
        f"Unsupported model '{model_key}'. Use 'gpt-4o-mini', one of the OpenRouter aliases in "
        f"run_eval_vllm_offline.py, or a full OpenRouter model id like 'openai/gpt-4o-mini'."
    )


def read_dataset(
    lab_key: str,
    include_levels: Optional[List[str]],
    exclude_levels: Optional[List[str]],
    limit: Optional[int],
) -> Tuple[Path, Path, str, List[Dict[str, Any]]]:
    dataset_path = find_latest_dataset(lab_key)
    if not dataset_path:
        raise FileNotFoundError(f"Dataset not found for Lab-{lab_key}")

    config_dir = find_config_dir(lab_key)
    if not config_dir:
        raise FileNotFoundError(f"Config dir not found for Lab-{lab_key}")

    config_manager = ConfigManager(config_dir, logging.getLogger("null"))
    configs_text = config_manager.get_all_configs()

    with open(dataset_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        data = list(reader)

    include_set = {l.upper() for l in (include_levels or [])}
    exclude_set = {l.upper() for l in (exclude_levels or ["L6"])}

    if include_set:
        data = [row for row in data if row.get("level", "").strip().upper() in include_set]
    if exclude_set:
        data = [row for row in data if row.get("level", "").strip().upper() not in exclude_set]
    if limit:
        data = data[:limit]

    return dataset_path, config_dir, configs_text, data


def build_request_line(
    custom_id: str,
    request_model: str,
    messages: List[Dict[str, str]],
    max_tokens: int,
    reasoning: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "model": request_model,
        "messages": messages,
        "temperature": OfflineConfig.TEMPERATURE,
        "max_tokens": max_tokens,
    }
    if reasoning:
        body["reasoning"] = reasoning
    return {
        "custom_id": custom_id,
        "method": "POST",
        "url": "/v1/chat/completions",
        "body": body,
    }


def get_result_dir(model_display: str, lab_key: str) -> Path:
    clean_display = model_display.replace(" ", "_").replace("/", "_")
    result_dir = Config.RESULT_DIR / clean_display / f"Lab{lab_key}"
    result_dir.mkdir(parents=True, exist_ok=True)
    return result_dir


def get_artifact_dir(result_dir: Path) -> Path:
    artifact_dir = result_dir / "_batch_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def build_client(timeout_sec: Optional[int] = None) -> OpenAI:
    load_env_candidates()
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set.")

    base_url = os.getenv("OPENROUTER_BASE_URL", Config.DEFAULT_OPENROUTER_BASE_URL)
    headers: Dict[str, str] = {}
    referer = (
        os.getenv("OPENROUTER_HTTP_REFERER")
        or os.getenv("OPENROUTER_SITE_URL")
    )
    title = os.getenv("OPENROUTER_TITLE") or os.getenv("OPENROUTER_APP_NAME")
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-OpenRouter-Title"] = title

    return OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=timeout_sec or Config.DEFAULT_TIMEOUT_SEC,
        max_retries=0,
        default_headers=headers or None,
    )


_thread_local = threading.local()


def get_thread_client(timeout_sec: Optional[int] = None) -> OpenAI:
    client = getattr(_thread_local, "client", None)
    if client is None:
        client = build_client(timeout_sec=timeout_sec)
        _thread_local.client = client
    return client


def build_error_meta(request_max_tokens: int, exc: Exception) -> Dict[str, Any]:
    return {
        "finish_reason": "error",
        "stop_reason": None,
        "output_tokens": None,
        "request_max_tokens": request_max_tokens,
        "truncated_flag": False,
        "error_type": type(exc).__name__,
        "error_message": str(exc),
    }


def evaluate_sample(
    sample_index: int,
    row: Dict[str, Any],
    configs_text: str,
    level_token_overrides: Optional[Dict[str, int]],
    model_spec: Dict[str, Any],
    retry_attempts: int,
    retry_backoff_sec: int,
    timeout_sec: int,
    decoding_mode: str,
) -> Tuple[int, str, Dict[str, Any]]:
    level = row.get("level", "L1")
    max_tokens_needed = resolve_max_tokens(
        level,
        row.get("answer_type"),
        level_token_overrides,
        decoding_mode=decoding_mode,
    )
    request_max_tokens = min(max_tokens_needed, 16383)
    messages = build_messages(
        row["question"],
        row["answer_type"],
        configs_text,
        decoding_mode=decoding_mode,
    )
    request_kwargs: Dict[str, Any] = {
        "model": model_spec["request_model"],
        "messages": messages,
        "temperature": OfflineConfig.TEMPERATURE,
        "max_tokens": request_max_tokens,
    }
    if model_spec.get("reasoning"):
        request_kwargs["extra_body"] = {"reasoning": model_spec["reasoning"]}

    delay = float(model_spec.get("api_delay_sec", Config.DEFAULT_REQUEST_DELAY_SEC))
    client = get_thread_client(timeout_sec=timeout_sec)

    for attempt in range(retry_attempts):
        try:
            if delay > 0:
                time.sleep(delay)
            resp = client.chat.completions.create(**request_kwargs)
            return (
                sample_index,
                extract_api_text_response(resp),
                extract_api_response_meta(resp, request_max_tokens=request_max_tokens),
            )
        except Exception as e:
            err_str = str(e)
            is_rate_limit = "429" in err_str or "rate limit" in err_str.lower()
            is_retryable_server = any(code in err_str for code in ("500", "502", "503", "504"))

            if attempt < retry_attempts - 1 and (is_rate_limit or is_retryable_server):
                if is_rate_limit:
                    wait = max(retry_backoff_sec, 120) * (attempt + 1)
                else:
                    wait = retry_backoff_sec * (attempt + 1)
                time.sleep(wait)
                continue

            return sample_index, "", build_error_meta(request_max_tokens, e)

    return sample_index, "", {
        "finish_reason": "error",
        "stop_reason": None,
        "output_tokens": None,
        "request_max_tokens": request_max_tokens,
        "truncated_flag": False,
        "error_type": "RuntimeError",
        "error_message": "Unknown request failure",
    }


def run_evaluation(
    model_key: str,
    lab_key: str,
    limit: Optional[int] = None,
    include_levels: Optional[List[str]] = None,
    exclude_levels: Optional[List[str]] = None,
    level_token_overrides: Optional[Dict[str, int]] = None,
    max_workers: int = Config.DEFAULT_MAX_WORKERS,
    timeout_sec: int = Config.DEFAULT_TIMEOUT_SEC,
    retry_attempts: int = Config.DEFAULT_RETRY_ATTEMPTS,
    retry_backoff_sec: int = Config.DEFAULT_RETRY_BACKOFF_SEC,
    dry_run: bool = False,
    decoding_mode: str = OfflineConfig.DECODING_MODE_DEFAULT,
) -> Optional[Path]:
    logger, timestamp = setup_logger(model_key, lab_key)
    model_spec = resolve_model_spec(model_key)

    dataset_path, config_dir, configs_text, data = read_dataset(
        lab_key,
        include_levels=include_levels,
        exclude_levels=exclude_levels,
        limit=limit,
    )
    dataset_language = infer_dataset_language(dataset_path)

    logger.info(f"Dataset: {dataset_path}")
    logger.info(f"Config dir: {config_dir}")
    logger.info(f"Config text length: {len(configs_text)} chars (~{len(configs_text)//4} tokens)")
    logger.info(f"Filtered samples: {len(data)}")
    logger.info(
        f"Model: {model_spec['display']} | request_model={model_spec['request_model']} | "
        f"workers={max_workers} | timeout={timeout_sec}s"
    )

    result_dir = get_result_dir(model_spec["display"], lab_key)
    artifact_dir = get_artifact_dir(result_dir)
    input_jsonl = artifact_dir / f"batch_input_{dataset_language}_{timestamp}.jsonl"
    manifest_path = artifact_dir / f"batch_manifest_{dataset_language}_{timestamp}.json"

    with open(input_jsonl, "w", encoding="utf-8") as f:
        for idx, row in enumerate(data):
            level = row.get("level", "L1")
            max_tokens = resolve_max_tokens(level, row.get("answer_type"), level_token_overrides)
            max_tokens = resolve_max_tokens(
                level,
                row.get("answer_type"),
                level_token_overrides,
                decoding_mode=decoding_mode,
            )
            messages = build_messages(
                row["question"],
                row["answer_type"],
                configs_text,
                decoding_mode=decoding_mode,
            )
            custom_id = str(row.get("question_id", row.get("id", f"{lab_key}_{idx+1}")))
            line = build_request_line(
                custom_id=custom_id,
                request_model=model_spec["request_model"],
                messages=messages,
                max_tokens=min(max_tokens, 16383),
                reasoning=model_spec.get("reasoning"),
            )
            f.write(json.dumps(line, ensure_ascii=False) + "\n")

    manifest: Dict[str, Any] = {
        "mode": "openrouter_parallel_eval",
        "model": model_spec["display"],
        "model_tag": model_key,
        "request_model": model_spec["request_model"],
        "backend": "openrouter",
        "lab": f"Lab-{lab_key}",
        "lab_key": lab_key,
        "lab_folder": OfflineConfig.LABS.get(lab_key, ""),
        "language": dataset_language,
        "dataset": str(dataset_path.name),
        "dataset_path": str(dataset_path),
        "config_dir": str(config_dir),
        "input_jsonl": str(input_jsonl),
        "submitted_at": str(datetime.datetime.now()),
        "status": "dry_run" if dry_run else "prepared",
        "total_samples": len(data),
        "include_levels": sorted({l.upper() for l in (include_levels or [])}),
        "exclude_levels": sorted({l.upper() for l in (exclude_levels or ["L6"])}),
        "level_token_overrides": level_token_overrides or {},
        "max_workers": max_workers,
        "timeout_sec": timeout_sec,
        "retry_attempts": retry_attempts,
        "retry_backoff_sec": retry_backoff_sec,
        "api_delay_sec": model_spec.get("api_delay_sec", Config.DEFAULT_REQUEST_DELAY_SEC),
        "base_url": os.getenv("OPENROUTER_BASE_URL", Config.DEFAULT_OPENROUTER_BASE_URL),
    }

    save_json(manifest_path, manifest)
    logger.info(f"Prepared input JSONL: {input_jsonl}")
    logger.info(f"Saved manifest: {manifest_path}")

    if dry_run:
        logger.info("Dry run complete. No API requests were sent.")
        return manifest_path

    start_time = time.time()
    outputs_text = [""] * len(data)
    outputs_meta = [
        {
            "finish_reason": None,
            "stop_reason": None,
            "output_tokens": None,
            "request_max_tokens": None,
            "truncated_flag": False,
        }
        for _ in data
    ]

    logger.info(f"Starting OpenRouter inference for {len(data)} samples...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                evaluate_sample,
                idx,
                row,
                configs_text,
                level_token_overrides,
                model_spec,
                retry_attempts,
                retry_backoff_sec,
                timeout_sec,
                decoding_mode,
            ): idx
            for idx, row in enumerate(data)
        }

        consecutive_429_like = 0
        for completed_count, future in enumerate(
            tqdm(as_completed(futures), total=len(futures), desc=f"Lab-{lab_key}"),
            start=1,
        ):
            idx, raw_output, meta = future.result()
            outputs_text[idx] = raw_output
            outputs_meta[idx] = meta

            error_message = str(meta.get("error_message", ""))
            if "429" in error_message or "rate limit" in error_message.lower():
                consecutive_429_like += 1
            else:
                consecutive_429_like = 0

            if consecutive_429_like >= Config.OPENROUTER_MAX_CONSECUTIVE_429:
                raise RuntimeError(
                    f"OpenRouter rate limit persisted for {consecutive_429_like} consecutive samples. "
                    "Current worker/delay settings are too aggressive for this endpoint."
                )

            if completed_count == 1 or completed_count % 50 == 0:
                elapsed = time.time() - start_time
                rate = completed_count / elapsed if elapsed > 0 else 0
                logger.info(f"Progress: {completed_count}/{len(data)} | rate={rate:.2f} req/s")

    duration = time.time() - start_time
    throughput = round(len(outputs_text) / duration, 2) if duration > 0 else 0
    logger.info(f"Inference complete: {len(outputs_text)} samples in {duration:.1f}s ({throughput:.2f} req/s)")

    results = []
    format_stats: Dict[str, Dict[str, Any]] = {}
    for i, raw_output in enumerate(outputs_text):
        row = data[i]
        cleaned = extract_answer_legacy(raw_output, row["answer_type"])
        generation_meta = outputs_meta[i] or {}
        format_metrics = measure_format_stability(cleaned, row["answer_type"])

        results.append({
            "question_id": row.get("question_id", row.get("id", str(i + 1))),
            "question": row["question"],
            "gold": row["answer"],
            "raw_pred": raw_output,
            "pred": cleaned,
            "level": row.get("level", "L1"),
            "category": row.get("category", "General"),
            "answer_type": row["answer_type"],
            "answer_status": row.get("answer_status", "OK"),
            "format_parseable": format_metrics["parseable"],
            "format_completeness": format_metrics["completeness"],
            "finish_reason": generation_meta.get("finish_reason"),
            "stop_reason": generation_meta.get("stop_reason"),
            "output_tokens": generation_meta.get("output_tokens"),
            "request_max_tokens": generation_meta.get("request_max_tokens"),
            "truncated_flag": generation_meta.get("truncated_flag", False),
        })

    for atype in sorted(set(r["answer_type"] for r in results)):
        type_results = [r for r in results if r["answer_type"] == atype]
        parse_rate = sum(1 for r in type_results if r["format_parseable"]) / len(type_results)
        avg_completeness = sum(r["format_completeness"] for r in type_results) / len(type_results)
        format_stats[atype] = {
            "parse_success_rate": round(parse_rate, 4),
            "avg_completeness": round(avg_completeness, 4),
            "count": len(type_results),
        }

    clean_display = model_spec["display"].replace(" ", "_").replace("/", "_")
    output_file = result_dir / f"results_raw_vllm_{dataset_language}_{timestamp}.json"
    output_data = {
        "meta": {
            "model": model_spec["display"],
            "model_tag": model_key,
            "request_model": model_spec["request_model"],
            "backend": "openrouter",
            "lab": f"Lab-{lab_key}",
            "lab_folder": OfflineConfig.LABS.get(lab_key, ""),
            "language": dataset_language,
            "date": str(datetime.datetime.now()),
            "duration_sec": round(duration, 2),
            "throughput": throughput,
            "dataset": str(dataset_path.name),
            "dataset_path": str(dataset_path),
            "config_dir": str(config_dir),
            "result_model_dir": clean_display,
            "result_lab_dir": f"Lab{lab_key}",
            "total_samples": len(results),
            "tokenizer_chat_template": None,
            "enable_prefix_caching": False,
            "structured_outputs_enabled": False,
            "decoding_mode": decoding_mode,
            "level_token_overrides": level_token_overrides or {},
            "max_model_len_override": None,
            "input_jsonl": str(input_jsonl),
            "manifest_path": str(manifest_path),
            "max_workers": max_workers,
            "timeout_sec": timeout_sec,
            "retry_attempts": retry_attempts,
            "retry_backoff_sec": retry_backoff_sec,
        },
        "format_stability": format_stats,
        "results": results,
    }

    save_json(output_file, output_data)

    manifest.update({
        "status": "completed",
        "completed_at": str(datetime.datetime.now()),
        "duration_sec": round(duration, 2),
        "throughput": throughput,
        "raw_output_path": str(output_file),
    })
    save_json(manifest_path, manifest)

    logger.info(f"Saved raw results: {output_file}")
    logger.info(f"Format Stability: {json.dumps(format_stats, indent=2)}")
    return output_file


def main() -> None:
    parser = argparse.ArgumentParser(description="NetConfigQA2.0 OpenRouter Evaluator")
    parser.add_argument("--model", nargs="+", required=True, help="모델 태그 또는 'all'")
    parser.add_argument("--lab", nargs="+", required=True, help="Lab 키 (A B C D) 또는 'all'")
    parser.add_argument("--limit", type=int, default=None, help="디버깅용 제한")
    parser.add_argument("--include-levels", nargs="+", default=None)
    parser.add_argument("--exclude-levels", nargs="+", default=["L6"])
    parser.add_argument(
        "--hard-levels-only",
        action="store_true",
        help="L4/L5 질문만 재실험합니다. --include-levels와 함께 쓰면 L4/L5로 강제됩니다.",
    )
    parser.add_argument("--l4-max-tokens", type=int, default=None, help="L4 전용 생성 토큰 상한 override")
    parser.add_argument("--l5-max-tokens", type=int, default=None, help="L5 전용 생성 토큰 상한 override")
    parser.add_argument("--max-workers", type=int, default=Config.DEFAULT_MAX_WORKERS)
    parser.add_argument("--timeout-sec", type=int, default=Config.DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--retry-attempts", type=int, default=Config.DEFAULT_RETRY_ATTEMPTS)
    parser.add_argument("--retry-backoff-sec", type=int, default=Config.DEFAULT_RETRY_BACKOFF_SEC)
    parser.add_argument("--dry-run", action="store_true", help="입력 JSONL/manifest만 생성하고 API는 호출하지 않습니다.")
    parser.add_argument(
        "--decoding-mode",
        choices=["legacy", "strict"],
        default=OfflineConfig.DECODING_MODE_DEFAULT,
        help="디코딩/추출 정책. 기본값은 legacy입니다.",
    )

    args = parser.parse_args()

    if args.hard_levels_only:
        args.include_levels = ["L4", "L5"]

    level_token_overrides: Dict[str, int] = {}
    if args.l4_max_tokens is not None:
        level_token_overrides["L4"] = args.l4_max_tokens
    if args.l5_max_tokens is not None:
        level_token_overrides["L5"] = args.l5_max_tokens

    model_keys = resolve_model_keys(args.model)
    labs = resolve_labs(args.lab)

    completed = []
    failed = []
    for model_key in model_keys:
        for lab_key in labs:
            try:
                result = run_evaluation(
                    model_key=model_key,
                    lab_key=lab_key,
                    limit=args.limit,
                    include_levels=args.include_levels,
                    exclude_levels=args.exclude_levels,
                    level_token_overrides=level_token_overrides,
                    max_workers=max(1, args.max_workers),
                    timeout_sec=max(1, args.timeout_sec),
                    retry_attempts=max(1, args.retry_attempts),
                    retry_backoff_sec=max(1, args.retry_backoff_sec),
                    dry_run=args.dry_run,
                    decoding_mode=args.decoding_mode,
                )
                completed.append((model_key, lab_key, str(result) if result else "no_output"))
            except Exception as e:
                failed.append((model_key, lab_key, f"{type(e).__name__}: {e}"))

    print("\n============================================================")
    print("OPENROUTER EVALUATION COMPLETE")
    print("============================================================")
    print(f"Completed: {len(completed)}/{len(model_keys) * len(labs)}")
    if completed:
        for model_key, lab_key, artifact in completed:
            print(f"  {model_key} / Lab-{lab_key}: {artifact}")
    if failed:
        print(f"\nFailed ({len(failed)}):")
        for model_key, lab_key, msg in failed:
            print(f"  {model_key} / Lab-{lab_key}: {msg}")


if __name__ == "__main__":
    main()
