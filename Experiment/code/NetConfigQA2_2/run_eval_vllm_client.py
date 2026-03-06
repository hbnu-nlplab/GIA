"""
NetConfigQA2.0 Evaluator — vLLM Client Mode (서버-클라이언트 분리)

외부 GPU 서버에서 vLLM OpenAI-compatible API로 모델을 서빙하고,
로컬 PC에서는 OpenAI SDK로 호출하는 클라이언트만 실행합니다.

torch/vllm/pybatfish 불필요 — openai SDK만 필요.

Usage:
    # vLLM 서버 모드 (Tailscale VPN 경유)
    python run_eval_vllm_client.py --server 100.x.x.x:8000 --lab A B C D
    python run_eval_vllm_client.py --server 100.x.x.x:8000 --lab all --concurrency 4

    # OpenAI API 모드 (GPT-4o-mini)
    python run_eval_vllm_client.py --openai gpt-4o-mini --lab all

    # 공통 옵션
    --limit N              # 디버깅용
    --include-levels L1 L2
    --exclude-levels L6    # 기본값
    --resume               # 체크포인트에서 재개
    --timeout 300          # 요청당 타임아웃(초)
"""

import os
import json
import csv
import argparse
import time
import logging
import datetime
import sys
import re
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Set


# === Configuration ===

class Config:
    BASE_DIR = Path(__file__).parent
    ROOT_DIR = BASE_DIR.parent.parent.parent  # GIA/
    DATA_DIR = ROOT_DIR / "Data"
    LOG_DIR = BASE_DIR / "logs"
    RESULT_DIR = BASE_DIR / "results"

    # Lab 경로 매핑
    LABS = {
        "A": "LabA_Research_Institute_DC_10nodes",
        "B": "LabB_NCN_Basic_SP_20nodes",
        "C": "LabC_NCN_Security_L2VPN_30nodes",
        "D": "LabD_NCN_MultiAS_Complex_40nodes",
    }

    # 서버가 모델을 서빙하므로 display name 매핑만 유지
    DISPLAY_NAMES = {
        "GPT-OSS-20B": "GPT-OSS-20B",
        "Qwen3-Coder": "Qwen3-Coder",
        "GLM-4.7-Flash": "GLM-4.7-Flash",
        "Qwen3.5-9B": "Qwen3.5-9B",
        "gpt-4o-mini": "GPT-4o-mini",
    }

    TEMPERATURE = 0.0

    # 레벨별 출력 토큰 차등
    MAX_OUTPUT_BY_LEVEL = {
        "L1": 4096,
        "L2": 4096,
        "L3": 8192,
        "L4": 16384,
        "L5": 16384,
    }
    MAX_OUTPUT_DEFAULT = 8192


# === Logger ===

def setup_logger(model_name: str, lab_name: str) -> tuple:
    Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = model_name.replace("/", "_").replace(":", "_")
    log_file = Config.LOG_DIR / f"eval_client_{clean_name}_Lab{lab_name}_{timestamp}.log"

    logger = logging.getLogger(f"NetConfigQA_client_{clean_name}_{lab_name}")
    logger.setLevel(logging.INFO)
    logger.handlers = []

    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(sh)

    return logger, timestamp


# === Dataset & Config Finder ===

def find_latest_dataset(lab_key: str) -> Optional[Path]:
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder:
        return None

    dataset_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "Dataset"
    if not dataset_dir.exists():
        return None

    timestamp_dirs = sorted(
        [d for d in dataset_dir.iterdir() if d.is_dir() and d.name.isdigit() or "_" in d.name],
        key=lambda d: d.name, reverse=True
    )

    for ts_dir in timestamp_dirs:
        csv_files = list(ts_dir.glob("*_dataset_batfish_*_ko.csv"))
        if csv_files:
            return csv_files[0]

    csv_files = list(dataset_dir.glob("*_dataset_batfish_*_ko.csv"))
    if csv_files:
        return sorted(csv_files, key=lambda f: f.name, reverse=True)[0]
    return None


def find_config_dir(lab_key: str) -> Optional[Path]:
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder:
        return None
    config_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "configs"
    return config_dir if config_dir.exists() else None


class ConfigManager:
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
        combined = ""
        for host in sorted(self._cache.keys()):
            combined += f"\n=== START OF CONFIG: {host.upper()} ===\n"
            combined += self._cache[host]
            combined += f"\n=== END OF CONFIG: {host.upper()} ===\n"
        return combined


# === Prompt ===

SYSTEM_PROMPT = """You are an expert Network Engineer analyzing network configurations. /no_think

OUTPUT FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. Analyze the configuration carefully, then output ONLY the final answer.

2. Output ONLY the raw answer value in ONE line:
   - text type: Just the text value (e.g., "R1" or "10.0.0.1")
   - numeric/number type: Just the number (e.g., 5 or 10.5)
   - set type: JSON array format (e.g., ["item1", "item2"])
   - map type: JSON object format (e.g., {"key": "value"})
   - boolean type: true or false

3. FORBIDDEN:
   - "The answer is..."
   - "Based on the analysis..."
   - "We need to..."
   - Any explanatory sentences
   - Multiple lines or paragraphs

4. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set: []
   - map: {}
   - boolean: false

REMEMBER: Output ONLY the answer value on ONE line. Nothing else."""


def build_messages(question: str, answer_type: str, configs: str) -> List[Dict[str, str]]:
    user_msg = f"""=== NETWORK CONFIGURATIONS ===
{configs}

=== QUESTION ===
{question}

=== ANSWER TYPE ===
{answer_type}

=== YOUR ANSWER (ONE LINE ONLY) ==="""

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]


# === Answer Extraction & Format Stability ===

def extract_answer(raw: str) -> str:
    """raw output에서 reasoning 토큰을 제거하고 답변만 추출."""
    text = raw.strip()
    if not text:
        return ""
    if 'assistantfinal' in text:
        text = text.split('assistantfinal')[-1].strip()
    elif '</think>' in text:
        text = text.split('</think>')[-1].strip()
    elif '<think>' in text:
        text = text.split('<think>')[0].strip()
    elif text.lstrip().startswith('analysis') or len(text) > 5000:
        return ""
    return text.strip()


def measure_format_stability(raw_output: str, answer_type: str) -> Dict[str, Any]:
    result = {"parseable": False, "completeness": 0.0, "raw_length": len(raw_output)}
    cleaned = raw_output.strip()
    if not cleaned:
        return result

    try:
        if answer_type in ("scalar_int", "number", "numeric"):
            match = re.search(r'-?\d+\.?\d*', cleaned)
            result["parseable"] = match is not None
            result["completeness"] = 1.0 if match else 0.0

        elif answer_type in ("bool", "boolean"):
            lower = cleaned.lower()
            result["parseable"] = any(kw in lower for kw in ["true", "false", "yes", "no"])
            result["completeness"] = 1.0 if result["parseable"] else 0.0

        elif answer_type in ("set_str", "set", "list_str", "edge_set"):
            match = re.search(r'\[.*?\]', cleaned, re.DOTALL)
            if match:
                items = json.loads(match.group(0).replace("'", '"'))
                result["parseable"] = True
                result["completeness"] = 1.0 if len(items) > 0 else 0.0
            elif "," in cleaned:
                result["parseable"] = True
                result["completeness"] = 1.0

        elif answer_type in ("map_str_int", "map_str_str", "map", "dict"):
            match = re.search(r'\{.*?\}', cleaned, re.DOTALL)
            if match:
                obj = json.loads(match.group(0).replace("'", '"'))
                result["parseable"] = True
                result["completeness"] = 1.0 if len(obj) > 0 else 0.0

        elif answer_type in ("path",):
            has_arrow = "->" in cleaned or "→" in cleaned
            result["parseable"] = has_arrow
            result["completeness"] = 1.0 if has_arrow else 0.0

        else:
            lines = [l.strip() for l in cleaned.split('\n') if l.strip()]
            result["parseable"] = len(lines) >= 1 and len(lines[0].split()) <= 10
            result["completeness"] = 1.0 if result["parseable"] else 0.0

    except Exception:
        pass

    return result


# === Async Inference Engine ===

async def infer_single(
    client,  # AsyncOpenAI
    model_id: str,
    messages: List[Dict[str, str]],
    max_tokens: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
    is_openai: bool = False,
) -> str:
    """단일 요청을 비동기로 실행. 3회 재시도 + 지수 백오프."""
    backoff_delays = [5, 15, 45]

    async with semaphore:
        for attempt in range(4):  # 1 + 3 retries
            try:
                kwargs = dict(
                    model=model_id,
                    messages=messages,
                    temperature=Config.TEMPERATURE,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
                if not is_openai:
                    kwargs["extra_body"] = {
                        "stop": ["Question:", "=== QUESTION ==="],
                    }
                else:
                    kwargs["stop"] = ["Question:", "=== QUESTION ==="]

                resp = await client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content or ""

            except Exception as e:
                err_str = str(e)
                if attempt < 3:
                    if "429" in err_str:
                        wait = 60 * (attempt + 1)
                    else:
                        wait = backoff_delays[attempt]
                    await asyncio.sleep(wait)
                else:
                    return f"[ERROR] {err_str}"


async def run_inference_async(
    client,  # AsyncOpenAI
    model_id: str,
    data: List[Dict],
    configs_text: str,
    concurrency: int,
    timeout: float,
    logger: logging.Logger,
    is_openai: bool = False,
    completed_ids: Optional[Set[str]] = None,
    result_dir: Optional[Path] = None,
    timestamp: str = "",
) -> List[Dict[str, Any]]:
    """비동기 병렬 추론 실행. 50건마다 체크포인트 저장."""
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Dict[str, Any]] = []
    total = len(data)
    completed_count = 0
    start_time = time.time()

    # OpenAI API 모드에서는 rate-limit 방지용 딜레이
    openai_delay = 1.2 if is_openai else 0.0

    for i, row in enumerate(data):
        qid = row.get("question_id", row.get("id", str(i + 1)))

        # 이미 완료된 건 스킵
        if completed_ids and qid in completed_ids:
            continue

        level = row.get("level", "L1")
        max_tokens = Config.MAX_OUTPUT_BY_LEVEL.get(level, Config.MAX_OUTPUT_DEFAULT)
        if is_openai:
            max_tokens = min(max_tokens, 16383)

        messages = build_messages(row["question"], row["answer_type"], configs_text)

        if openai_delay > 0:
            await asyncio.sleep(openai_delay)

        raw_output = await infer_single(
            client, model_id, messages, max_tokens, timeout, semaphore, is_openai
        )

        cleaned = extract_answer(raw_output)
        format_metrics = measure_format_stability(cleaned, row["answer_type"])

        results.append({
            "question_id": qid,
            "question": row["question"],
            "gold": row["answer"],
            "raw_pred": raw_output,
            "pred": cleaned,
            "level": level,
            "category": row.get("category", "General"),
            "answer_type": row["answer_type"],
            "answer_status": row.get("answer_status", "OK"),
            "format_parseable": format_metrics["parseable"],
            "format_completeness": format_metrics["completeness"],
        })

        completed_count += 1

        # 진행률 + 체크포인트
        if completed_count % 50 == 0 or completed_count == 1:
            elapsed = time.time() - start_time
            speed = completed_count / elapsed if elapsed > 0 else 0
            remaining = total - completed_count - (len(completed_ids) if completed_ids else 0)
            eta = remaining / speed if speed > 0 else 0
            logger.info(
                f"Progress: {completed_count}/{total} | "
                f"{speed:.1f} req/s | ETA: {eta/60:.1f}min"
            )

            if completed_count % 50 == 0 and result_dir:
                partial_file = result_dir / f"results_partial_{timestamp}.json"
                try:
                    with open(partial_file, 'w', encoding='utf-8') as pf:
                        json.dump({
                            "progress": completed_count,
                            "total": total,
                            "results": results,
                        }, pf, ensure_ascii=False)
                except Exception as e:
                    logger.warning(f"Checkpoint save failed: {e}")

    return results


# === Batch Runner (concurrency > 1) ===

async def run_inference_batch(
    client,
    model_id: str,
    data: List[Dict],
    configs_text: str,
    concurrency: int,
    timeout: float,
    logger: logging.Logger,
    is_openai: bool = False,
    completed_ids: Optional[Set[str]] = None,
    result_dir: Optional[Path] = None,
    timestamp: str = "",
) -> List[Dict[str, Any]]:
    """비동기 배치 추론. Semaphore로 동시성 제어."""
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Optional[Dict[str, Any]]] = [None] * len(data)
    pending_indices = []
    start_time = time.time()

    for i, row in enumerate(data):
        qid = row.get("question_id", row.get("id", str(i + 1)))
        if completed_ids and qid in completed_ids:
            continue
        pending_indices.append(i)

    logger.info(f"Pending: {len(pending_indices)}/{len(data)} (skipped {len(data) - len(pending_indices)} completed)")

    completed_count = 0

    async def process_one(idx: int):
        nonlocal completed_count
        row = data[idx]
        level = row.get("level", "L1")
        max_tokens = Config.MAX_OUTPUT_BY_LEVEL.get(level, Config.MAX_OUTPUT_DEFAULT)
        if is_openai:
            max_tokens = min(max_tokens, 16383)

        messages = build_messages(row["question"], row["answer_type"], configs_text)

        raw_output = await infer_single(
            client, model_id, messages, max_tokens, timeout, semaphore, is_openai
        )

        cleaned = extract_answer(raw_output)
        format_metrics = measure_format_stability(cleaned, row["answer_type"])

        qid = row.get("question_id", row.get("id", str(idx + 1)))
        results[idx] = {
            "question_id": qid,
            "question": row["question"],
            "gold": row["answer"],
            "raw_pred": raw_output,
            "pred": cleaned,
            "level": level,
            "category": row.get("category", "General"),
            "answer_type": row["answer_type"],
            "answer_status": row.get("answer_status", "OK"),
            "format_parseable": format_metrics["parseable"],
            "format_completeness": format_metrics["completeness"],
        }

        completed_count += 1
        if completed_count % 50 == 0:
            elapsed = time.time() - start_time
            speed = completed_count / elapsed if elapsed > 0 else 0
            remaining = len(pending_indices) - completed_count
            eta = remaining / speed if speed > 0 else 0
            logger.info(
                f"Progress: {completed_count}/{len(pending_indices)} | "
                f"{speed:.1f} req/s | ETA: {eta/60:.1f}min"
            )
            # Checkpoint
            if result_dir:
                done = [r for r in results if r is not None]
                partial_file = result_dir / f"results_partial_{timestamp}.json"
                try:
                    with open(partial_file, 'w', encoding='utf-8') as pf:
                        json.dump({
                            "progress": completed_count,
                            "total": len(data),
                            "results": done,
                        }, pf, ensure_ascii=False)
                except Exception as e:
                    logger.warning(f"Checkpoint save failed: {e}")

    # OpenAI API → 순차 (rate-limit), vLLM → 병렬
    if is_openai:
        for idx in pending_indices:
            await asyncio.sleep(1.2)
            await process_one(idx)
    else:
        tasks = [process_one(idx) for idx in pending_indices]
        await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


# === Main Evaluation ===

def load_checkpoint(result_dir: Path, timestamp: str = "") -> tuple:
    """기존 체크포인트 또는 완료된 결과에서 completed_ids를 로드."""
    completed_ids: Set[str] = set()
    prev_results: List[Dict] = []

    # 1. partial 파일 탐색 (최신 timestamp 우선)
    partials = sorted(result_dir.glob("results_partial_*.json"), reverse=True)
    for pf in partials:
        try:
            with open(pf, 'r', encoding='utf-8') as f:
                checkpoint = json.load(f)
            prev_results = checkpoint.get("results", [])
            for r in prev_results:
                completed_ids.add(r["question_id"])
            return completed_ids, prev_results, pf
        except Exception:
            continue

    # 2. 완료된 결과 파일 탐색
    finals = sorted(result_dir.glob("results_raw_*.json"), reverse=True)
    for ff in finals:
        try:
            with open(ff, 'r', encoding='utf-8') as f:
                final = json.load(f)
            prev_results = final.get("results", [])
            for r in prev_results:
                completed_ids.add(r["question_id"])
            return completed_ids, prev_results, ff
        except Exception:
            continue

    return completed_ids, prev_results, None


def run_evaluation(
    model_id: str,
    display_name: str,
    lab_key: str,
    server_url: Optional[str] = None,
    is_openai: bool = False,
    concurrency: int = 8,
    timeout: float = 300.0,
    limit: Optional[int] = None,
    include_levels: Optional[List[str]] = None,
    exclude_levels: Optional[List[str]] = None,
    resume: bool = False,
):
    logger, timestamp = setup_logger(display_name, lab_key)

    # 1. Dataset & Config Load
    dataset_path = find_latest_dataset(lab_key)
    if not dataset_path:
        logger.error(f"Dataset not found for Lab-{lab_key}")
        return None
    logger.info(f"Dataset: {dataset_path}")

    config_dir = find_config_dir(lab_key)
    if not config_dir:
        logger.error(f"Config dir not found for Lab-{lab_key}")
        return None

    config_manager = ConfigManager(config_dir, logger)
    configs_text = config_manager.get_all_configs()
    logger.info(f"Config text length: {len(configs_text)} chars (~{len(configs_text)//4} tokens)")

    # 2. Filter Dataset
    with open(dataset_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        data = list(reader)

    original_count = len(data)
    include_set = {l.upper() for l in (include_levels or [])}
    exclude_set = {l.upper() for l in (exclude_levels or ["L6"])}

    if include_set:
        data = [row for row in data if row.get("level", "").strip().upper() in include_set]
    if exclude_set:
        data = [row for row in data if row.get("level", "").strip().upper() not in exclude_set]
    if limit:
        data = data[:limit]

    logger.info(f"Dataset: {original_count} -> {len(data)} after filter (include={include_set or 'ALL'}, exclude={exclude_set or 'NONE'})")

    # 3. Result directory & checkpoint
    clean_display = display_name.replace(" ", "_").replace("/", "_")
    result_dir = Config.RESULT_DIR / clean_display / f"Lab{lab_key}"
    result_dir.mkdir(parents=True, exist_ok=True)

    completed_ids: Set[str] = set()
    prev_results: List[Dict] = []
    if resume:
        completed_ids, prev_results, checkpoint_file = load_checkpoint(result_dir)
        if completed_ids:
            logger.info(f"Resumed from checkpoint: {len(completed_ids)} completed ({checkpoint_file})")
        else:
            logger.info("No checkpoint found, starting fresh")

    # 4. Create async client
    from openai import AsyncOpenAI

    if is_openai:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not set")
            return None
        client = AsyncOpenAI(api_key=api_key)
        backend_name = "openai"
        logger.info(f"Using OpenAI API: model={model_id}")
    else:
        client = AsyncOpenAI(
            base_url=f"http://{server_url}/v1",
            api_key="EMPTY",
        )
        backend_name = "vllm_client"
        logger.info(f"Using vLLM server: {server_url}, model={model_id}")

    # 5. Run inference
    start_time = time.time()

    if is_openai or concurrency <= 1:
        # 순차 실행 (OpenAI rate-limit 대응)
        results = asyncio.run(run_inference_async(
            client=client,
            model_id=model_id,
            data=data,
            configs_text=configs_text,
            concurrency=concurrency,
            timeout=timeout,
            logger=logger,
            is_openai=is_openai,
            completed_ids=completed_ids,
            result_dir=result_dir,
            timestamp=timestamp,
        ))
    else:
        # 병렬 배치 실행 (vLLM 서버)
        results = asyncio.run(run_inference_batch(
            client=client,
            model_id=model_id,
            data=data,
            configs_text=configs_text,
            concurrency=concurrency,
            timeout=timeout,
            logger=logger,
            is_openai=is_openai,
            completed_ids=completed_ids,
            result_dir=result_dir,
            timestamp=timestamp,
        ))

    # resume일 경우 이전 결과와 합치기
    if prev_results:
        # 새 결과의 qid 세트
        new_ids = {r["question_id"] for r in results}
        # 이전 결과 중 새 결과에 없는 것만 합치기
        merged = [r for r in prev_results if r["question_id"] not in new_ids]
        merged.extend(results)
        results = merged
        logger.info(f"Merged: {len(prev_results)} prev + {len(results) - len(prev_results)} new = {len(results)} total")

    duration = time.time() - start_time
    logger.info(f"Inference complete: {len(results)} samples in {duration:.1f}s")

    # 6. Format Stability 집계
    format_stats = {}
    for atype in set(r["answer_type"] for r in results):
        type_results = [r for r in results if r["answer_type"] == atype]
        parse_rate = sum(1 for r in type_results if r["format_parseable"]) / len(type_results)
        avg_completeness = sum(r["format_completeness"] for r in type_results) / len(type_results)
        format_stats[atype] = {
            "parse_success_rate": round(parse_rate, 4),
            "avg_completeness": round(avg_completeness, 4),
            "count": len(type_results),
        }

    # 7. Save results
    output_file = result_dir / f"results_raw_vllm_{timestamp}.json"

    output_data = {
        "meta": {
            "model": display_name,
            "model_tag": model_id,
            "backend": backend_name,
            "lab": f"Lab-{lab_key}",
            "lab_folder": Config.LABS.get(lab_key, ""),
            "date": str(datetime.datetime.now()),
            "duration_sec": round(duration, 2),
            "throughput": round(len(results) / duration, 2) if duration > 0 else 0,
            "dataset": str(dataset_path.name),
            "total_samples": len(results),
            "server_url": server_url or "api.openai.com",
            "concurrency": concurrency,
            "timeout": timeout,
            "temperature": Config.TEMPERATURE,
            "max_output_by_level": Config.MAX_OUTPUT_BY_LEVEL,
            "resumed": resume and bool(completed_ids),
        },
        "format_stability": format_stats,
        "results": results,
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    # 체크포인트 파일 정리
    for pf in result_dir.glob("results_partial_*.json"):
        try:
            pf.unlink()
        except Exception:
            pass

    logger.info(f"Saved: {output_file}")
    logger.info(f"Format Stability: {json.dumps(format_stats, indent=2)}")

    return output_file


# === Smoke Test ===

def run_smoke_test(args):
    """서버 연결 확인 + 간단한 추론 테스트."""
    from openai import OpenAI

    if args.openai:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("[FAIL] OPENAI_API_KEY not set")
            sys.exit(1)
        client = OpenAI(api_key=api_key)
        model_id = args.openai
        server_label = "OpenAI API"
    else:
        client = OpenAI(base_url=f"http://{args.server}/v1", api_key="EMPTY")
        server_label = f"vLLM @ {args.server}"
        model_id = None

    print(f"\n{'='*50}")
    print(f"  Smoke Test: {server_label}")
    print(f"{'='*50}\n")

    # 1. Connection & model list
    print("[1/3] Connecting to server...")
    try:
        models = client.models.list()
        available = [m.id for m in models.data]
        if not model_id:
            model_id = available[0]
        print(f"  OK - Models: {available}")
    except Exception as e:
        print(f"  FAIL - {e}")
        sys.exit(1)

    # 2. Simple inference
    print(f"\n[2/3] Test inference (model={model_id})...")
    test_messages = [
        {"role": "system", "content": "Answer in one word."},
        {"role": "user", "content": "What is the hostname in this config?\n\nhostname R1\n!"},
    ]
    try:
        t0 = time.time()
        resp = client.chat.completions.create(
            model=model_id,
            messages=test_messages,
            temperature=0.0,
            max_tokens=64,
        )
        latency = time.time() - t0
        answer = resp.choices[0].message.content.strip()
        tokens = resp.usage
        print(f"  OK - Answer: '{answer}' ({latency:.2f}s)")
        print(f"       Tokens: prompt={tokens.prompt_tokens}, completion={tokens.completion_tokens}")
    except Exception as e:
        print(f"  FAIL - {e}")
        sys.exit(1)

    # 3. Concurrency test (vLLM only)
    if not args.openai:
        import asyncio as _asyncio
        from openai import AsyncOpenAI

        async_client = AsyncOpenAI(base_url=f"http://{args.server}/v1", api_key="EMPTY")
        n = 8

        print(f"\n[3/3] Concurrency test ({n} parallel requests)...")

        async def _concurrent_test():
            sem = _asyncio.Semaphore(n)

            async def _req(i):
                async with sem:
                    r = await async_client.chat.completions.create(
                        model=model_id,
                        messages=test_messages,
                        temperature=0.0,
                        max_tokens=64,
                    )
                    return r.choices[0].message.content.strip()

            t0 = time.time()
            results = await _asyncio.gather(*[_req(i) for i in range(n)])
            elapsed = time.time() - t0
            return results, elapsed

        results, elapsed = _asyncio.run(_concurrent_test())
        rps = len(results) / elapsed
        print(f"  OK - {n} requests in {elapsed:.2f}s ({rps:.1f} req/s)")
        print(f"       Answers: {results[:3]}...")
    else:
        print(f"\n[3/3] Concurrency test skipped (OpenAI API)")

    print(f"\n{'='*50}")
    print(f"  ALL TESTS PASSED")
    print(f"{'='*50}\n")


# === CLI ===

def main():
    parser = argparse.ArgumentParser(description="NetConfigQA2.0 vLLM Client Evaluator")

    # 모드 선택 (상호 배타)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", type=str, help="vLLM 서버 주소 (예: 100.x.x.x:8000)")
    mode.add_argument("--openai", type=str, help="OpenAI 모델명 (예: gpt-4o-mini)")

    parser.add_argument("--lab", nargs="+", help="Lab 키 (A B C D) 또는 'all'")
    parser.add_argument("--test", action="store_true", help="서버 연결 + 추론 스모크 테스트")
    parser.add_argument("--concurrency", type=int, default=8, help="동시 요청 수 (기본 8, OpenAI는 1)")
    parser.add_argument("--limit", type=int, default=None, help="디버깅용 제한")
    parser.add_argument("--include-levels", nargs="+", default=None)
    parser.add_argument("--exclude-levels", nargs="+", default=["L6"])
    parser.add_argument("--resume", action="store_true", help="체크포인트에서 재개")
    parser.add_argument("--timeout", type=float, default=300.0, help="요청당 타임아웃 (초)")

    args = parser.parse_args()

    # --test 모드: 서버 연결 + 추론 스모크 테스트
    if args.test:
        run_smoke_test(args)
        return

    if not args.lab:
        parser.error("--lab is required (unless using --test)")

    labs = list(Config.LABS.keys()) if "all" in [l.lower() for l in args.lab] else [l.upper() for l in args.lab]

    # 모델 자동 감지 또는 설정
    if args.openai:
        model_id = args.openai
        display_name = Config.DISPLAY_NAMES.get(model_id, model_id)
        is_openai = True
        server_url = None
        concurrency = 1  # OpenAI는 순차
    else:
        # vLLM 서버에서 모델 자동 감지
        from openai import OpenAI
        sync_client = OpenAI(
            base_url=f"http://{args.server}/v1",
            api_key="EMPTY",
        )
        try:
            models = sync_client.models.list()
            model_id = models.data[0].id
        except Exception as e:
            print(f"Failed to connect to vLLM server at {args.server}: {e}")
            sys.exit(1)

        display_name = Config.DISPLAY_NAMES.get(model_id, model_id)
        is_openai = False
        server_url = args.server
        concurrency = args.concurrency

    print(f"\n{'='*60}")
    print(f"NetConfigQA2.0 Client Evaluator")
    print(f"  Model:       {display_name} ({model_id})")
    print(f"  Backend:     {'OpenAI API' if is_openai else f'vLLM @ {server_url}'}")
    print(f"  Labs:        {labs}")
    print(f"  Concurrency: {concurrency}")
    print(f"  Timeout:     {args.timeout}s")
    print(f"  Resume:      {args.resume}")
    print(f"{'='*60}\n")

    completed = []
    failed = []

    for lab_idx, lab_key in enumerate(labs, 1):
        print(f"\n[{lab_idx}/{len(labs)}] {display_name} x Lab-{lab_key}")
        print("-" * 40)

        try:
            output_file = run_evaluation(
                model_id=model_id,
                display_name=display_name,
                lab_key=lab_key,
                server_url=server_url,
                is_openai=is_openai,
                concurrency=concurrency,
                timeout=args.timeout,
                limit=args.limit,
                include_levels=args.include_levels,
                exclude_levels=args.exclude_levels,
                resume=args.resume,
            )
            if output_file:
                completed.append((lab_key, str(output_file)))
                print(f"[OK] Lab-{lab_key}")
            else:
                failed.append((lab_key, "No output"))
        except Exception as e:
            print(f"[ERROR] Lab-{lab_key}: {e}")
            import traceback
            traceback.print_exc()
            failed.append((lab_key, str(e)))

    print(f"\n{'='*60}")
    print(f"EVALUATION COMPLETE: {display_name}")
    print(f"{'='*60}")
    print(f"Completed: {len(completed)}/{len(labs)}")

    if completed:
        print(f"\nResults:")
        for lab, path in completed:
            print(f"  Lab-{lab}: {path}")

    if failed:
        print(f"\nFailed ({len(failed)}):")
        for lab, err in failed:
            print(f"  Lab-{lab}: {err}")


if __name__ == "__main__":
    main()
