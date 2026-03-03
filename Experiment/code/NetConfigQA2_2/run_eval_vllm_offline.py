"""
NetConfigQA2.0 Evaluator — vLLM Offline Batched Inference (A5000 최적화)

최신 NetConfigQA2.0 (NetConfigQA2_2)의 평가 로직을 유지하면서,
HuggingFace 모델 + vLLM의 Offline Batched Inference를 통해 수백 배 빠른 추론을 수행합니다.

Usage:
    # A5000 서버 등 GPU 리소스가 있는 환경에서 직접 실행
    python run_eval_vllm_offline.py --model gpt-oss:20b --lab A

    # 다중 모델, 다중 Lab 순차 실행
    python run_eval_vllm_offline.py --model all --lab all
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
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

import torch

# Attempt to import vllm
try:
    from vllm import LLM, SamplingParams
except ImportError:
    LLM = None
    SamplingParams = None
    print("Warning: 'vllm' module not found. Install with `pip install vllm`.")


# === Configuration ===

class Config:
    BASE_DIR = Path(__file__).parent
    ROOT_DIR = BASE_DIR.parent.parent.parent  # GIA/
    DATA_DIR = ROOT_DIR / "Data"
    LOG_DIR = BASE_DIR / "logs"
    RESULT_DIR = BASE_DIR / "results"

    # Lab 경로 매핑 (최신 NetConfigQA2_2 기준)
    LABS = {
        "A": "LabA_Research_Institute_DC_10nodes",
        "B": "LabB_NCN_Basic_SP_20nodes",
        "C": "LabC_NCN_Security_L2VPN_30nodes",
        "D": "LabD_NCN_MultiAS_Complex_40nodes",
    }

    # vLLM용 모델 매핑 (명시적 AWQ 양자화 Repo 사용)
    MODEL_DICT = {
        # GPT-OSS-20B: FP16은 ~40GB → A5000 24GB에서 OOM
        # AWQ 버전이 HuggingFace에 있으면 사용, 없으면 GPTQ 또는 bitsandbytes 4-bit 필요
        # TODO: HuggingFace에서 AWQ repo 확인 후 hf_path 업데이트
        "gpt-oss:20b":               {"hf_path": "openai/gpt-oss-20b",                           "display": "GPT-OSS-20B",   "quant": None,  "backend": "vllm_offline"},
        "qwen3-coder:30b-a3b-AWQ":{"hf_path": "stelterlab/Qwen3-Coder-30B-A3B-Instruct-AWQ",  "display": "Qwen3-Coder",   "quant": "awq", "backend": "vllm_offline"},
        "gemma3:27b-it-AWQ":      {"hf_path": "gaunernst/gemma-3-27b-it-int4-awq",            "display": "Gemma-3-27B",   "quant": "awq", "backend": "vllm_offline"},
        "glm-4.7-flash-AWQ":      {"hf_path": "QuantTrio/GLM-4.7-Flash-AWQ",                  "display": "GLM-4.7-Flash", "quant": "awq", "backend": "vllm_offline"},
        "Qwen3.5-27B-AWQ":      {"hf_path": "cyankiwi/Qwen3.5-27B-AWQ-4bit",                "display": "Qwen3.5-27B",   "quant": "awq", "backend": "vllm_offline"},
        "gpt-4o-mini":               {"hf_path": "gpt-4o-mini",                                  "display": "GPT-4o-mini",   "quant": None,  "backend": "openai"},
    }

    ALL_MODELS = list(MODEL_DICT.keys())

    # 공통 평가 파라미터
    TEMPERATURE = 0.0

    # 레벨별 출력 토큰 차등 — 배치를 레벨 그룹으로 분리하여 효율화
    # reasoning 모델(GPT-OSS 등)은 내부 추론에 ~19K 토큰 사용 관찰됨
    MAX_OUTPUT_BY_LEVEL = {
        "L1": 8192,
        "L2": 8192,
        "L3": 16384,
        "L4": 32768,   # reasoning 모델 추론 토큰 포함
        "L5": 65536,   # 최대 추론 — 장애 영향 분석 등 복잡한 질문
    }
    MAX_OUTPUT_DEFAULT = 32768
    
    NUM_CTX = 49152  # 48K — 입력 컨텍스트 길이 (max_model_len)


# === Logger ===

def setup_logger(model_name: str, lab_name: str) -> tuple:
    Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = model_name.replace("/", "_").replace(":", "_")
    log_file = Config.LOG_DIR / f"eval_vllm_{clean_name}_Lab{lab_name}_{timestamp}.log"

    logger = logging.getLogger(f"NetConfigQA_{clean_name}_{lab_name}")
    logger.setLevel(logging.INFO)
    logger.handlers = []

    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(sh)

    return logger, timestamp


# === Dataset & Config Finder (재사용) ===

def find_latest_dataset(lab_key: str) -> Optional[Path]:
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder: return None

    dataset_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "Dataset"
    if not dataset_dir.exists(): return None

    timestamp_dirs = sorted(
        [d for d in dataset_dir.iterdir() if d.is_dir() and d.name.isdigit() or "_" in d.name],
        key=lambda d: d.name, reverse=True
    )

    for ts_dir in timestamp_dirs:
        csv_files = list(ts_dir.glob("*_dataset_batfish_*_ko.csv"))
        if csv_files: return csv_files[0]

    csv_files = list(dataset_dir.glob("*_dataset_batfish_*_ko.csv"))
    if csv_files: return sorted(csv_files, key=lambda f: f.name, reverse=True)[0]
    return None

def find_config_dir(lab_key: str) -> Optional[Path]:
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder: return None
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


# === Prompt & Stability (재사용) ===

SYSTEM_PROMPT = """You are an expert Network Engineer analyzing network configurations.

OUTPUT FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. First, analyze the configuration carefully to find the answer.

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

def measure_format_stability(raw_output: str, answer_type: str) -> Dict[str, Any]:
    result = {"parseable": False, "completeness": 0.0, "raw_length": len(raw_output)}
    cleaned = raw_output.strip()
    if not cleaned: return result

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


# === VLLM Global Engine Manager ===
# 여러 Lab을 돌 때 모델을 계속 로드/언로드 하는 비효율 방지용 싱글톤 래퍼

class VLLMEngineManager:
    _instance = None
    _current_model_key = None
    _openai_client = None
    
    @classmethod
    def get_engine(cls, model_key: str, gpu_util: float, logger: logging.Logger):
        model_info = Config.MODEL_DICT.get(model_key)
        if not model_info:
            raise ValueError(f"Unknown model key: {model_key}")
            
        hf_path = model_info["hf_path"]
        quantization = model_info.get("quant")
        backend = model_info.get("backend", "vllm_offline")

        if backend == "openai":
            if cls._openai_client is None:
                try:
                    from openai import OpenAI
                    api_key = os.getenv("OPENAI_API_KEY")
                    if not api_key:
                        raise RuntimeError("OPENAI_API_KEY 환경변수가 설정되어 있지 않습니다.")
                    cls._openai_client = OpenAI(api_key=api_key)
                    logger.info(f"Initialized OpenAI client for {hf_path}")
                except ImportError:
                    raise RuntimeError("openai 패키지가 설치되어 있지 않습니다. pip install openai")
            cls._current_model_key = model_key
            return cls._openai_client, None

        # 기존 VLLM 모델이 로드되어 있고, 새로 요청한 모델과 다르면 언로드
        if cls._instance is not None and cls._current_model_key != model_key:
            logger.info(f"Unloading previous vLLM engine ({cls._current_model_key})...")
            from vllm.distributed.parallel_state import destroy_model_parallel
            destroy_model_parallel()
            del cls._instance
            cls._instance = None
            torch.cuda.empty_cache()
            import gc; gc.collect()
            time.sleep(2)

        if cls._instance is None:
            if LLM is None:
                raise RuntimeError("vllm is not installed.")
            
            logger.info(f"Loading vLLM engine: {hf_path} (quant={quantization}, max_model_len={Config.NUM_CTX})")
            cls._instance = LLM(
                model=hf_path,
                tensor_parallel_size=torch.cuda.device_count(),
                gpu_memory_utilization=gpu_util,
                max_model_len=Config.NUM_CTX,  # 48K 컨텍스트 길이 명시적 보장
                trust_remote_code=True,
                enforce_eager=False,
                quantization=quantization,
                enable_prefix_caching=True, # 핵심 성능 최적화!!
            )
            cls._current_model_key = model_key
            
        return cls._instance, cls._instance.get_tokenizer()


# === Main Evaluator ===

def run_evaluation(
    model_key: str,
    lab_key: str,
    gpu_util: float,
    limit: Optional[int] = None,
    include_levels: Optional[List[str]] = None,
    exclude_levels: Optional[List[str]] = None,
):
    logger, timestamp = setup_logger(model_key, lab_key)

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

    logger.info(f"Dataset: {original_count} → {len(data)} after filter (include={include_set or 'ALL'}, exclude={exclude_set or 'NONE'})")

    # 3. Request vLLM Engine (Singleton) & Tokenizer
    try:
        llm, tokenizer = VLLMEngineManager.get_engine(model_key, gpu_util, logger)
    except Exception as e:
        logger.critical(f"Failed to load VLLM engine: {e}")
        return None

    # 4. Prepare Prompts (Batch) — 레벨별로 그룹화
    logger.info("Preparing prompts for batch inference...")

    # 인덱스-프롬프트-레벨 매핑
    prompt_groups = {}  # level -> [(original_index, prompt)]
    for idx, row in enumerate(data):
        messages = build_messages(row["question"], row["answer_type"], configs_text)
        try:
            prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        except Exception:
            sys_msg = messages[0]["content"]
            usr_msg = messages[1]["content"]
            prompt = f"{sys_msg}\n\n{usr_msg}"

        level = row.get("level", "L1")
        if level not in prompt_groups:
            prompt_groups[level] = []
        prompt_groups[level].append((idx, prompt))

    # 5. Execute Inference — 레벨별 배치로 분리 (max_tokens 차등)
    model_backend = Config.MODEL_DICT.get(model_key, {}).get("backend", "vllm_offline")

    start_time = time.time()
    outputs_text = [""] * len(data)  # 원래 순서 유지용

    if model_backend == "vllm_offline":
        for level in sorted(prompt_groups.keys()):
            group = prompt_groups[level]
            max_tokens = Config.MAX_OUTPUT_BY_LEVEL.get(level, Config.MAX_OUTPUT_DEFAULT)
            prompts = [p for _, p in group]
            indices = [i for i, _ in group]

            logger.info(f"  {level}: {len(prompts)}건 × max_tokens={max_tokens}")

            sampling_params = SamplingParams(
                temperature=Config.TEMPERATURE,
                max_tokens=max_tokens,
                stop=[
                    "<|eot_id|>",
                    "<|end|>",
                    "Question:",
                    "=== QUESTION ===",
                    "\n\nQuestion:",
                ],
            )
            outputs = llm.generate(prompts, sampling_params)

            for out, orig_idx in zip(outputs, indices):
                outputs_text[orig_idx] = out.outputs[0].text

        logger.info(f"VLLM batch inference complete: {len(data)} samples")
    elif model_backend == "openai":
        logger.info(f"Starting OpenAI sequential inference for {len(data)} samples...")
        openai_model_name = Config.MODEL_DICT.get(model_key, {}).get("hf_path")
        for i, row in enumerate(data, 1):
            if i % 50 == 0 or i == 1:
                elapsed = time.time() - start_time
                eta = (elapsed / i) * (len(data) - i) if i > 0 else 0
                logger.info(f"Progress: {i}/{len(data)} | ETA: {eta/60:.1f}min")
            
            messages = build_messages(row["question"], row["answer_type"], configs_text)
            try:
                # Limit tokens for API, 4o-mini supports 16K max output
                resp = llm.chat.completions.create(
                    model=openai_model_name,
                    messages=messages,
                    temperature=Config.TEMPERATURE,
                    max_tokens=min(max_tokens_needed, 16383), 
                )
                outputs_text.append(resp.choices[0].message.content or "")
            except Exception as e:
                logger.error(f"OpenAI API Error on sample {i}: {e}")
                outputs_text.append("")
    
    duration = time.time() - start_time
    logger.info(f"Inference complete: {len(outputs_text)} samples in {duration:.1f}s ({len(outputs_text)/duration:.1f} req/s)")

    # 6. Process Results
    results = []
    format_stats = {}
    
    for i, raw_output in enumerate(outputs_text):
        row = data[i]
        
        format_metrics = measure_format_stability(raw_output, row["answer_type"])
        
        results.append({
            "question_id": row.get("question_id", row.get("id", str(i+1))),
            "question": row["question"],
            "gold": row["answer"],
            "raw_pred": raw_output,
            "pred": raw_output.strip(), # 채점 스크립트(analyze_results)에서 clean 및 parse 처리
            "level": row.get("level", "L1"),
            "category": row.get("category", "General"),
            "answer_type": row["answer_type"],
            "answer_status": row.get("answer_status", "OK"),
            "format_parseable": format_metrics["parseable"],
            "format_completeness": format_metrics["completeness"],
        })

    # 7. Aggregate & Save
    model_info = Config.MODEL_DICT.get(model_key, {})
    display_name = model_info.get("display", model_key)
    clean_display = display_name.replace(" ", "_").replace("/", "_")

    result_dir = Config.RESULT_DIR / f"{clean_display}" / f"Lab{lab_key}"
    result_dir.mkdir(parents=True, exist_ok=True)
    output_file = result_dir / f"results_raw_vllm_{timestamp}.json"

    for atype in set(r["answer_type"] for r in results):
        type_results = [r for r in results if r["answer_type"] == atype]
        parse_rate = sum(1 for r in type_results if r["format_parseable"]) / len(type_results)
        avg_completeness = sum(r["format_completeness"] for r in type_results) / len(type_results)
        format_stats[atype] = {
            "parse_success_rate": round(parse_rate, 4),
            "avg_completeness": round(avg_completeness, 4),
            "count": len(type_results),
        }

    output_data = {
        "meta": {
            "model": display_name,
            "model_tag": model_key,
            "backend": model_backend,
            "lab": f"Lab-{lab_key}",
            "lab_folder": Config.LABS.get(lab_key, ""),
            "date": str(datetime.datetime.now()),
            "duration_sec": round(duration, 2),
            "throughput": round(len(outputs_text)/duration, 2) if duration > 0 else 0,
            "dataset": str(dataset_path.name),
            "total_samples": len(results),
            "tokenizer_chat_template": True if tokenizer and tokenizer.chat_template else False,
            "enable_prefix_caching": True if model_backend == "vllm_offline" else False,
        },
        "format_stability": format_stats,
        "results": results,
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    logger.info(f"Saved: {output_file}")
    logger.info(f"Format Stability: {json.dumps(format_stats, indent=2)}")

    return output_file


# === CLI ===

def main():
    parser = argparse.ArgumentParser(description="NetConfigQA2.0 VLLM Offline Evaluator")
    parser.add_argument("--model", nargs="+", required=True, help="모델 태그 또는 'all'")
    parser.add_argument("--lab", nargs="+", required=True, help="Lab 키 (A B C D) 또는 'all'")
    parser.add_argument("--gpu_util", type=float, default=0.90, help="VLLM GPU Memory Utilization (기본 0.9)")
    parser.add_argument("--limit", type=int, default=None, help="디버깅용 제한")
    parser.add_argument("--include-levels", nargs="+", default=None)
    parser.add_argument("--exclude-levels", nargs="+", default=["L6"])

    args = parser.parse_args()

    models = Config.ALL_MODELS if "all" in [m.lower() for m in args.model] else args.model
    labs = list(Config.LABS.keys()) if "all" in [l.lower() for l in args.lab] else [l.upper() for l in args.lab]

    total_runs = len(models) * len(labs)
    print(f"\n{'='*60}")
    print(f"NetConfigQA2.0 VLLM Offline Batch Evaluation")
    print(f"Models: {len(models)} | Labs: {len(labs)} | Total runs: {total_runs}")
    print(f"{'='*60}\n")

    completed = []
    failed = []

    for run_idx, (model_key, lab_key) in enumerate([(m, l) for m in models for l in labs], 1):
        display = Config.MODEL_DICT.get(model_key, {}).get("display", model_key)
        print(f"\n[{run_idx}/{total_runs}] {display} × Lab-{lab_key}")
        print("-" * 40)

        try:
            output_file = run_evaluation(
                model_key=model_key,
                lab_key=lab_key,
                gpu_util=args.gpu_util,
                limit=args.limit,
                include_levels=args.include_levels,
                exclude_levels=args.exclude_levels,
            )
            if output_file:
                completed.append((display, lab_key, str(output_file)))
                print(f"[OK] {display} × Lab-{lab_key}")
            else:
                failed.append((display, lab_key, "No output"))
        except Exception as e:
            print(f"[ERROR] {display} × Lab-{lab_key}: {e}")
            failed.append((display, lab_key, str(e)))

    print(f"\n{'='*60}")
    print(f"EVALUATION COMPLETE")
    print(f"{'='*60}")
    print(f"Completed: {len(completed)}/{total_runs}")

    if completed:
        print(f"\nResults:")
        for display, lab, path in completed:
            print(f"  {display} × Lab-{lab}: {path}")

    if failed:
        print(f"\nFailed ({len(failed)}):")
        for display, lab, err in failed:
            print(f"  {display} × Lab-{lab}: {err}")

    # 최종 안전 언로드
    try:
        from vllm.distributed.parallel_state import destroy_model_parallel
        destroy_model_parallel()
        torch.cuda.empty_cache()
    except: pass


if __name__ == "__main__":
    main()
