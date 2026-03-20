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
        "A": "Research_Institute_Internal_DC",
        "B": "LabB_NCN_Basic_SP_20nodes",
        "C": "LabC_NCN_Security_L2VPN_30nodes",
        "D": "LabD_NCN_MultiAS_Complex_40nodes",
    }

    # vLLM용 모델 매핑 (명시적 AWQ 양자화 Repo 사용)
    # max_ctx: 모델 크기에 따라 차등 설정
    #   - 소형 모델(<10GB): Lab-D 설정 ~23,758 tok 처리 가능 → 40960
    #   - 대형 모델(>15GB): KV 캐시 부족 → 16384 (입력+출력 ~13K tok 범위)
    MODEL_DICT = {
        "gpt-oss:20b":               {"hf_path": "openai/gpt-oss-20b",                           "display": "GPT-OSS-20B",   "quant": None,  "backend": "vllm_offline", "max_ctx": 40960},
        "qwen3-coder:30b-a3b-AWQ":{"hf_path": "stelterlab/Qwen3-Coder-30B-A3B-Instruct-AWQ",  "display": "Qwen3-Coder",   "quant": None,  "backend": "vllm_offline", "max_ctx": 40960},
        "Qwen3.5-9B": {"hf_path": "cyankiwi/Qwen3.5-9B-AWQ-4bit", "display": "Qwen3.5-9B",   "quant": None,  "backend": "vllm_offline", "max_ctx": 40960,
                        "extra_kwargs": {"reasoning_parser": "qwen3"}},
        "Qwen3.5-4B": {"hf_path": "cyankiwi/Qwen3.5-4B-AWQ-4bit", "display": "Qwen3.5-4B", "quant": None, "backend": "vllm_offline", "max_ctx": 32768,
                        "env": {"PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True"},
                        "extra_kwargs": {"reasoning_parser": "qwen3", "gpu_memory_utilization": 0.7, "enforce_eager": True}},
        "Foundation-Sec-8B": {"hf_path": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct", "display": "Foundation-Sec-8B", "quant": None, "backend": "vllm_offline", "max_ctx": 42000},
        "gpt-4o-mini":               {"hf_path": "gpt-4o-mini",                                  "display": "GPT-4o-mini",   "quant": None,  "backend": "openai",        "max_ctx": 128000},
    }

    ALL_MODELS = list(MODEL_DICT.keys())

    # 공통 평가 파라미터
    TEMPERATURE = 0.0

    # 레벨별 출력 토큰 차등 — 배치를 레벨 그룹으로 분리하여 효율화
    # vLLM이 max_tokens를 실제 사용 가능한 범위로 자동 클리핑함
    MAX_OUTPUT_BY_LEVEL = {
        "L1": 2048,
        "L2": 2048,
        "L3": 3072,
        "L4": 4096,
        "L5": 4096,
    }
    MAX_OUTPUT_DEFAULT = 8192
    
    NUM_CTX = 16384  # ← 대형 모델(>15GB) 기본값 (모델별 max_ctx가 우선)
                     # 실제 입력: Config(~4192 tok) + System/Q(~400 tok) = ~4600 tok
                     # 출력 최대 8192 tok → 총 필요 시퀀스 ~12800 tok → 16384로 충분
                     # (40960 사용 시 KV 캐시 2,912 토큰만 남아 스케줄 데드락 발생)


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

SYSTEM_PROMPT = """You are an expert Network Engineer analyzing network configurations. /no_think

CRITICAL INSTRUCTIONS - READ CAREFULLY:
You must analyze ALL provided device configurations from top to bottom before answering. This is crucial for multi-device questions and reachability analysis.

OUTPUT FORMAT RULES (MUST FOLLOW EXACTLY):
You must output ONLY the raw answer value on ONE SINGLE LINE. 
Do NOT use markdown code blocks (e.g., ```json or ```). Do NOT add ANY explanatory text or conversational fillers like "The answer is".

Based on the [ANSWER TYPE], use the exact format below:
1. text: Output ONLY the requested string value (e.g., "R1" or "10.0.0.1"). For network paths, use '->' to strictly separate nodes in order (e.g., nodeA -> nodeB -> nodeC).
2. number / numeric / scalar_int: Output ONLY the numeric value (e.g., 5 or 10.5).
3. boolean / bool: Output ONLY 'true' or 'false' (all lowercase).
4. set / set_str / list_str / edge_set: Output a valid JSON Array with double quotes (e.g., ["item1", "item2"]). CRITICAL: You MUST list ALL matching items across all configurations completely without omission. Do not stop early.
5. map / map_str_int / map_str_str / dict: Output a valid JSON Object with double quotes for strings (e.g., {"key": "value"}). CRITICAL: You MUST list ALL matching pair items completely without omission.

NEGATIVE TESTING CAUTION:
If the requested information is 'NOT_CONFIGURED', not found, or missing in the configuration, you MUST strictly output one of the following based on the type:
- text: null
- number / numeric: 0
- set: []
- map: {}
- boolean: false

REMEMBER: Your entire response will be programmatically parsed. The output MUST be just ONE line of the precise answer value."""

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
            
            # 모델별 max_ctx 결정 (MODEL_DICT.max_ctx 우선, 없으면 Config.NUM_CTX)
            model_max_ctx = model_info.get("max_ctx", Config.NUM_CTX)
            logger.info(f"Loading vLLM engine: {hf_path} (quant={quantization}, max_model_len={model_max_ctx})")
            
            # 멀티모달 모델(Gemma-3, Qwen3.5 등)은 vision 인코더를 비활성화하여 KV 캐시 메모리 확보
            # Gemma-3-27B-IT: SigLIP 비전 인코더 프로파일링이 OOM 유발 → 텍스트 전용 모드 강제
            MULTIMODAL_MODEL_KEYS = ["gemma3", "gemma-3", "qwen3.5", "qwen3_5", "llava", "phi-3-v", "pixtral"]
            mm_limits = {}
            if any(kw in model_key.lower() or kw in hf_path.lower() for kw in MULTIMODAL_MODEL_KEYS):
                mm_limits = {"image": 0, "video": 0, "audio": 0}
                logger.info(f"멀티모달 모델 감지 ({model_key}): vision 인코더 비활성화 (텍스트 전용 모드)")
            
            # 모델별 환경 변수 설정 (MoE 등 특수 모델)
            model_env = model_info.get("env", {})
            if model_env:
                for k, v in model_env.items():
                    os.environ[k] = v
                logger.info(f"모델 환경 변수 설정: {model_env}")
            
            # 모델별 enforce_eager 설정 (MoE 모델은 torch.compile이 매우 느림)
            use_eager = model_info.get("eager", False)
            
            llm_kwargs = dict(
                model=hf_path,
                tensor_parallel_size=torch.cuda.device_count(),
                gpu_memory_utilization=gpu_util,
                max_model_len=model_max_ctx,
                trust_remote_code=True,
                enforce_eager=use_eager,
                quantization=quantization,
                enable_prefix_caching=True,  # 핵심 성능 최적화!!
            )
            if mm_limits:
                llm_kwargs["limit_mm_per_prompt"] = mm_limits
            
            # 모델별 추가 kwarg 적용 (reasoning_parser 등)
            extra_kwargs = model_info.get("extra_kwargs", {})
            if extra_kwargs:
                llm_kwargs.update(extra_kwargs)
                logger.info(f"모델 추가 파라미터 적용: {extra_kwargs}")

            cls._instance = LLM(**llm_kwargs)
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
                repetition_penalty=1.05,
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
            
            level = row.get("level", "L1")
            max_tokens_needed = Config.MAX_OUTPUT_BY_LEVEL.get(level, Config.MAX_OUTPUT_DEFAULT)
            messages = build_messages(row["question"], row["answer_type"], configs_text)

            # TPM rate-limit 방지: 요청간 1초 딜레이 (200K TPM / ~4000 TPR ≈ 50 req/min 이내 유지)
            time.sleep(1.2)

            for attempt in range(4):  # 최대 4회 시도 (1회 + 3회 재시도)
                try:
                    resp = llm.chat.completions.create(
                        model=openai_model_name,
                        messages=messages,
                        temperature=Config.TEMPERATURE,
                        max_tokens=min(max_tokens_needed, 16383),
                    )
                    outputs_text[i - 1] = resp.choices[0].message.content or ""
                    break  # 성공 시 재시도 루프 탈출
                except Exception as e:
                    err_str = str(e)
                    if "429" in err_str and attempt < 3:
                        wait = 60 * (attempt + 1)  # 60s, 120s, 180s
                        logger.warning(f"Rate limit on sample {i} (attempt {attempt+1}), waiting {wait}s...")
                        time.sleep(wait)
                    else:
                        logger.error(f"OpenAI API Error on sample {i}: {e}")
                        outputs_text[i - 1] = ""
                        break
    
    duration = time.time() - start_time
    logger.info(f"Inference complete: {len(outputs_text)} samples in {duration:.1f}s ({len(outputs_text)/duration:.1f} req/s)")

    # 6. Process Results — reasoning 토큰 제거
    results = []
    format_stats = {}

    def extract_answer(raw: str) -> str:
        """vLLM raw output에서 reasoning 토큰을 제거하고 답변만 추출."""
        text = raw.strip()
        if not text:
            return ""
        # GPT-OSS-20B: "analysis...assistantfinal ANSWER"
        if 'assistantfinal' in text:
            text = text.split('assistantfinal')[-1].strip()
        # Qwen/GLM: "<think>...</think> ANSWER"
        elif '</think>' in text:
            text = text.split('</think>')[-1].strip()
        elif '<think>' in text:
            text = text.split('<think>')[0].strip()
        # reasoning delimiter 없이 폭주한 경우 → 답변 추출 불가
        elif text.lstrip().startswith('analysis') or len(text) > 5000:
            # 추론 루프에 빠진 것으로 간주 — 빈 문자열 반환
            return ""
        return text.strip()

    for i, raw_output in enumerate(outputs_text):
        row = data[i]
        cleaned = extract_answer(raw_output)

        format_metrics = measure_format_stability(cleaned, row["answer_type"])

        results.append({
            "question_id": row.get("question_id", row.get("id", str(i+1))),
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
