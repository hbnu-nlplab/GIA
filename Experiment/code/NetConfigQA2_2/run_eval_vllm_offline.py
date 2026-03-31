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
    from vllm.sampling_params import StructuredOutputsParams
except ImportError:
    LLM = None
    SamplingParams = None
    StructuredOutputsParams = None
    print("Warning: 'vllm' module not found. Install with `pip install vllm`.")


# === Configuration ===

class Config:
    BASE_DIR = Path(__file__).parent
    ROOT_DIR = BASE_DIR.parent.parent.parent  # GIA/
    DATA_DIR = ROOT_DIR / "Data"
    LOG_DIR = BASE_DIR / "logs"
    RESULT_DIR = BASE_DIR / "results_2"

    # Lab 경로 매핑 (최신 NetConfigQA2_2 기준)
    LABS = {
        "A": "LabA_Research_Institute_DC_10nodes",
        "B": "LabB_NCN_Basic_SP_20nodes",
        "C": "LabC_NCN_Security_L2VPN_30nodes",
        "D": "LabD_NCN_MultiAS_Complex_40nodes",
    }

    # vLLM용 모델 매핑 (명시적 AWQ 양자화 Repo 사용)
    # max_ctx: 모델 크기에 따라 차등 설정
    #   - 소형 모델(<10GB): Lab-D 설정 ~23,758 tok 처리 가능 → 40960
    #   - 대형 모델(>15GB): KV 캐시 부족 → 16384 (입력+출력 ~13K tok 범위)
    MODEL_DICT = {
        "Llama-3.1-8B": {
            "hf_path": "meta-llama/Meta-Llama-3.1-8B-Instruct",
            "display": "Llama-3.1-8B",
            "quant": None,
            "backend": "vllm_offline",
            "max_ctx": 40960,
        },
        "Mistral3-8B": {
            "hf_path": "mistralai/Ministral-3-8B-Instruct-2512",
            "display": "Mistral3-8B",
            "quant": None,
            "backend": "vllm_offline",
            "max_ctx": 40960,
        },
        "Qwen3-8B": {
            "hf_path": "Qwen/Qwen3-8B",
            "display": "Qwen3-8B",
            "quant": None,
            "backend": "vllm_offline",
            "max_ctx": 40960,
            "extra_kwargs": {"reasoning_parser": "qwen3"},
        },
        "gpt-oss:20b": {"hf_path": "openai/gpt-oss-20b", "display": "GPT-OSS-20B", "quant": None, "backend": "vllm_offline", "max_ctx": 40960},
        "qwen3-coder:30b-a3b-AWQ": {"hf_path": "stelterlab/Qwen3-Coder-30B-A3B-Instruct-AWQ", "display": "Qwen3-Coder", "quant": None, "backend": "vllm_offline", "max_ctx": 40960},
        "Nemotron-Cascade-2-30B-A3B-AWQ": {
            "hf_path": "stelterlab/Nemotron-Cascade-2-30B-A3B-AWQ",
            "display": "Nemotron-Cascade-2-30B-A3B",
            "quant": None,
            "backend": "vllm_offline",
            "max_ctx": 40960,
        },
        "Gemma-3-27B-W4A16": {
            "hf_path": "RedHatAI/gemma-3-27b-it-quantized.w4a16",
            "display": "Gemma-3-27B",
            "quant": None,
            "backend": "vllm_offline",
            "max_ctx": 16384,
            "extra_kwargs": {"gpu_memory_utilization": 0.82, "enforce_eager": True},
        },
        "Qwen3.5-9B": {"hf_path": "cyankiwi/Qwen3.5-9B-AWQ-4bit", "display": "Qwen3.5-9B", "quant": None, "backend": "vllm_offline", "max_ctx": 40960,
                       "extra_kwargs": {"reasoning_parser": "qwen3"}},
        # Lab-D prompt can exceed 32K once the full config bundle and chat template are tokenized.
        # Keep this above the measured prompt length so the 4B model remains evaluable on A5000.
        "Qwen3.5-4B": {"hf_path": "cyankiwi/Qwen3.5-4B-AWQ-4bit", "display": "Qwen3.5-4B", "quant": None, "backend": "vllm_offline", "max_ctx": 40960,
                       "env": {"PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True"},
                       "extra_kwargs": {"reasoning_parser": "qwen3", "gpu_memory_utilization": 0.7, "enforce_eager": True}},
        "Foundation-Sec-8B": {"hf_path": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct", "display": "Foundation-Sec-8B", "quant": None, "backend": "vllm_offline", "max_ctx": 40960},
        "gpt-4o-mini": {"hf_path": "gpt-4o-mini", "display": "GPT-4o-mini", "quant": None, "backend": "openai", "max_ctx": 128000},
        "openrouter-gpt-oss-120b-free": {
            "hf_path": "openai/gpt-oss-120b:free",
            "display": "OpenRouter GPT-OSS-120B Free",
            "backend": "openrouter",
            "max_ctx": 131072,
            "api_delay_sec": 4.0,
            "openrouter_reasoning": {"effort": "low", "exclude": True},
        },
        "openrouter-nemotron-super-free": {
            "hf_path": "nvidia/nemotron-3-super-120b-a12b:free",
            "display": "OpenRouter Nemotron-3-Super Free",
            "backend": "openrouter",
            "max_ctx": 262144,
            "api_delay_sec": 4.0,
            "openrouter_reasoning": {"effort": "low", "exclude": True},
        },
        "openrouter-minimax-m2.5-free": {
            "hf_path": "minimax/minimax-m2.5:free",
            "display": "OpenRouter MiniMax-M2.5 Free",
            "backend": "openrouter",
            "max_ctx": 196608,
            "api_delay_sec": 4.0,
            "openrouter_reasoning": {"effort": "low", "exclude": True},
        },
        "openrouter-qwen3-coder-free": {
            "hf_path": "qwen/qwen3-coder:free",
            "display": "OpenRouter Qwen3-Coder Free",
            "backend": "openrouter",
            "max_ctx": 262144,
            "api_delay_sec": 4.0,
        },
        "openrouter-qwen3-next-80b-free": {
            "hf_path": "qwen/qwen3-next-80b-a3b-instruct:free",
            "display": "OpenRouter Qwen3-Next-80B Free",
            "backend": "openrouter",
            "max_ctx": 262144,
            "api_delay_sec": 4.0,
        },
        "openrouter-nemotron-nano-free": {
            "hf_path": "nvidia/nemotron-3-nano-30b-a3b:free",
            "display": "OpenRouter Nemotron-3-Nano Free",
            "backend": "openrouter",
            "max_ctx": 256000,
            "api_delay_sec": 4.0,
        },
    }

    ALL_MODELS = list(MODEL_DICT.keys())

    # 공통 평가 파라미터
    TEMPERATURE = 0.0
    DECODING_MODE_DEFAULT = "legacy"

    # 레벨별 출력 토큰 차등 — 배치를 레벨 그룹으로 분리하여 효율화
    # vLLM이 max_tokens를 실제 사용 가능한 범위로 자동 클리핑함
    MAX_OUTPUT_BY_LEVEL = {
        "L1": 2048,
        "L2": 2048,
        "L3": 3072,
        "L4": 4096,
        "L5": 4096,
    }
    # 답변 타입별 상한.
    # level 기반 max_tokens를 그대로 쓰면 L4/L5 text가 과도하게 길어져 실험 시간이 폭증할 수 있다.
    # 아래 값은 "정답만 한 줄로 짧게"라는 현재 프롬프트 가정에 맞춘 안전 상한이다.
    MAX_OUTPUT_CAP_BY_ANSWER_TYPE = {
        "boolean": 16,
        "number": 32,
        "text": 512,
        "path": 768,
        "set": 2048,
        "map": 2048,
        "map_str_int": 2048,
        "map_str_str": 2048,
    }
    MAX_OUTPUT_DEFAULT = 8192
    OPENROUTER_MAX_CONSECUTIVE_429 = 3
    
    NUM_CTX = 16384  # ← 대형 모델(>15GB) 기본값 (모델별 max_ctx가 우선)
                     # 실제 입력: Config(~4192 tok) + System/Q(~400 tok) = ~4600 tok
                     # 출력 최대 8192 tok → 총 필요 시퀀스 ~12800 tok → 16384로 충분
                     # (40960 사용 시 KV 캐시 2,912 토큰만 남아 스케줄 데드락 발생)


# === Logger ===

def setup_logger(model_name: str, lab_name: str, run_id: Optional[str] = None) -> tuple:
    Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = run_id or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
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


def make_group_id(level: str, answer_type: str) -> str:
    normalized_level = str(level or "L1").strip().upper()
    normalized_type = normalize_answer_type(answer_type)
    return f"{normalized_level}__{normalized_type}"


def load_completed_group_parts(parts_dir: Path) -> Dict[str, Dict[str, Any]]:
    completed_parts: Dict[str, Dict[str, Any]] = {}
    if not parts_dir.exists():
        return completed_parts

    for part_file in sorted(parts_dir.glob("*.json")):
        try:
            with open(part_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception:
            continue
        group_id = payload.get("group_id")
        if group_id:
            completed_parts[group_id] = payload
    return completed_parts


def is_group_part_complete(payload: Optional[Dict[str, Any]]) -> bool:
    if not payload:
        return False
    if "completed" in payload:
        return bool(payload.get("completed"))
    expected_count = payload.get("expected_count")
    item_count = len(payload.get("items", []))
    if expected_count is None:
        return True
    return item_count >= int(expected_count)


def save_group_part(
    parts_dir: Path,
    group_id: str,
    level: str,
    answer_type: str,
    request_max_tokens: int,
    items: List[Dict[str, Any]],
    expected_count: Optional[int] = None,
    completed: bool = True,
) -> Path:
    parts_dir.mkdir(parents=True, exist_ok=True)
    part_file = parts_dir / f"{group_id}.json"
    payload = {
        "group_id": group_id,
        "level": str(level or "L1").strip().upper(),
        "answer_type": normalize_answer_type(answer_type),
        "request_max_tokens": request_max_tokens,
        "expected_count": expected_count if expected_count is not None else len(items),
        "count": len(items),
        "completed": completed,
        "items": items,
    }
    with open(part_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return part_file


def iter_group_chunks(items: List[Any], chunk_size: Optional[int]) -> List[List[Any]]:
    if not chunk_size or chunk_size <= 0 or chunk_size >= len(items):
        return [items]
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


# === Dataset & Config Finder (재사용) ===

def find_latest_dataset(lab_key: str) -> Optional[Path]:
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder: return None

    dataset_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "Dataset"
    if not dataset_dir.exists(): return None

    timestamp_dirs = sorted(
        [
            d for d in dataset_dir.iterdir()
            if d.is_dir() and re.fullmatch(r"\d{8}_\d{6}", d.name)
        ],
        key=lambda d: d.name,
        reverse=True,
    )

    candidate_dirs = list(timestamp_dirs) + [dataset_dir]

    en_csvs = []
    generic_csvs = []
    ko_csvs = []
    for base_dir in candidate_dirs:
        for f in base_dir.glob("*_dataset_batfish_*.csv"):
            name = f.name
            if name.endswith("_en.csv"):
                en_csvs.append(f)
            elif name.endswith("_ko.csv"):
                ko_csvs.append(f)
            else:
                generic_csvs.append(f)

    if en_csvs:
        return sorted(en_csvs, key=lambda f: f.name, reverse=True)[0]
    if generic_csvs:
        return sorted(generic_csvs, key=lambda f: f.name, reverse=True)[0]
    if ko_csvs:
        return sorted(ko_csvs, key=lambda f: f.name, reverse=True)[0]
    return None

def find_config_dir(lab_key: str) -> Optional[Path]:
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder: return None
    config_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "configs"
    return config_dir if config_dir.exists() else None


def infer_dataset_language(dataset_path: Path) -> str:
    name = dataset_path.name.lower()
    if name.endswith("_en.csv"):
        return "en"
    if name.endswith("_ko.csv"):
        return "ko"
    return "unknown"

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

STRICT_SYSTEM_PROMPT = """You are an expert Network Engineer analyzing network configurations. /no_think

CRITICAL INSTRUCTIONS - READ CAREFULLY:
You must analyze ALL provided device configurations from top to bottom before answering. This is crucial for multi-device questions and reachability analysis.

OUTPUT FORMAT RULES (MUST FOLLOW EXACTLY):
You must output ONLY the raw answer value on ONE SINGLE LINE. 
Do NOT use markdown code blocks (e.g., ```json or ```). Do NOT add ANY explanatory text or conversational fillers like "The answer is".
Do NOT output any hidden reasoning, chain-of-thought, analysis, or tags such as <think> ... </think>.
The very first generated token must already be part of the final answer. Do not start with a newline or any preamble.

Based on the [ANSWER TYPE], use the exact format below:
1. text: Output ONLY the requested string value (e.g., "R1" or "10.0.0.1"). For network paths, use '->' to strictly separate nodes in order (e.g., nodeA -> nodeB -> nodeC).
2. number / numeric / scalar_int: Output ONLY the numeric value (e.g., 5 or 10.5).
3. boolean / bool: Output ONLY 'true' or 'false' (all lowercase).
4. set / set_str / list_str / edge_set: Output a valid JSON Array with double quotes (e.g., ["item1", "item2"]). CRITICAL: You MUST list ALL matching items across all configurations completely without omission. Do not stop early.
5. map / map_str_int / map_str_str / dict: Output a valid JSON Object with double quotes for strings (e.g., {"key": "value"}). CRITICAL: You MUST list ALL matching pair items completely without omission.

NEGATIVE TESTING CAUTION:
If the requested information is 'NOT_CONFIGURED', not found, or missing in the configuration, you MUST strictly output exactly:
- NOT_CONFIGURED

REMEMBER: Your entire response will be programmatically parsed. The output MUST be just ONE line of the precise answer value."""

LEGACY_SYSTEM_PROMPT = """You are an expert Network Engineer analyzing network configurations.

OUTPUT FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):

1. First, use <think>...</think> tags to analyze:
   - Search relevant configuration sections
   - Trace network paths and connections
   - Identify the answer

2. After </think>, output ONLY the raw answer value in ONE line:
   - text type: Just the text value (e.g., "R1" or "10.0.0.1")
   - numeric/number type: Just the number (e.g., 5 or 10.5)
   - set type: JSON array format (e.g., ["item1", "item2"])
   - map type: JSON object format (e.g., {"key": "value"})
   - boolean type: true or false

3. FORBIDDEN after </think>:
   - "The answer is..."
   - "Based on the analysis..."
   - "We need to..."
   - "Looking at the configuration..."
   - Any explanatory sentences
   - Multiple lines or paragraphs

4. If NOT_CONFIGURED or information missing:
   - output exactly: NOT_CONFIGURED

REMEMBER: After </think>, output ONLY the answer value on ONE line. Nothing else."""


def build_messages(
    question: str,
    answer_type: str,
    configs: str,
    decoding_mode: str = Config.DECODING_MODE_DEFAULT,
) -> List[Dict[str, str]]:
    normalized_mode = str(decoding_mode or Config.DECODING_MODE_DEFAULT).strip().lower()
    if normalized_mode == "legacy":
        system_prompt = LEGACY_SYSTEM_PROMPT
        user_msg = f"""=== NETWORK CONFIGURATIONS ===
{configs}

=== QUESTION ===
{question}

=== ANSWER TYPE ===
{answer_type}

=== YOUR RESPONSE ===
<think>
[Your analysis here]
</think>
[ANSWER VALUE ONLY - ONE LINE]"""
    else:
        system_prompt = STRICT_SYSTEM_PROMPT
        user_msg = f"""=== NETWORK CONFIGURATIONS ===
{configs}

=== QUESTION ===
{question}

=== ANSWER TYPE ===
{answer_type}

=== YOUR ANSWER (ONE LINE ONLY) ==="""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_msg},
    ]


def normalize_answer_type(answer_type: Optional[str]) -> str:
    normalized = str(answer_type or "text").strip().lower()
    alias_map = {
        "numeric": "number",
        "scalar_int": "number",
        "bool": "boolean",
        "dict": "map",
        "list_str": "set",
        "set_str": "set",
        "edge_set": "set",
    }
    return alias_map.get(normalized, normalized)


def build_structured_outputs(answer_type: str) -> Optional["StructuredOutputsParams"]:
    """Build vLLM structured output constraints for parseable answer types."""
    if StructuredOutputsParams is None:
        return None

    normalized = normalize_answer_type(answer_type)
    common_kwargs = {"disable_fallback": True}

    if normalized == "boolean":
        return StructuredOutputsParams(choice=["true", "false"], **common_kwargs)

    if normalized == "number":
        return StructuredOutputsParams(regex=r"-?\d+(?:\.\d+)?", **common_kwargs)

    if normalized == "set":
        schema = {
            "type": "array",
            "items": {"type": "string"},
        }
        return StructuredOutputsParams(json=schema, **common_kwargs)

    if normalized == "map_str_int":
        schema = {
            "type": "object",
            "additionalProperties": {"type": "integer"},
        }
        return StructuredOutputsParams(json=schema, **common_kwargs)

    if normalized == "map_str_str":
        schema = {
            "type": "object",
            "additionalProperties": {"type": "string"},
        }
        return StructuredOutputsParams(json=schema, **common_kwargs)

    if normalized == "map":
        schema = {
            "type": "object",
        }
        return StructuredOutputsParams(json=schema, **common_kwargs)

    if normalized == "path":
        return StructuredOutputsParams(
            regex=r"[^\n]+(?:\s*(?:->|→)\s*[^\n]+)+",
            **common_kwargs,
        )

    return None

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


def extract_api_text_response(resp: Any) -> str:
    """OpenAI/OpenRouter 응답에서 텍스트를 안전하게 추출."""
    choices = getattr(resp, "choices", None)
    if not choices:
        raise RuntimeError("API response contained no choices.")

    message = getattr(choices[0], "message", None)
    if message is None:
        raise RuntimeError("API response choice contained no message.")

    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    if isinstance(content, list):
        text_parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text" and block.get("text"):
                    text_parts.append(block["text"])
            else:
                block_type = getattr(block, "type", None)
                block_text = getattr(block, "text", None)
                if block_type == "text" and block_text:
                    text_parts.append(block_text)
        return "\n".join(text_parts).strip()
    return str(content)


def extract_api_response_meta(resp: Any, request_max_tokens: Optional[int] = None) -> Dict[str, Any]:
    """OpenAI/OpenRouter 응답에서 종료 사유와 토큰 사용량을 안전하게 추출."""
    choices = getattr(resp, "choices", None) or []
    first_choice = choices[0] if choices else None
    finish_reason = getattr(first_choice, "finish_reason", None) if first_choice else None

    usage = getattr(resp, "usage", None)
    output_tokens = getattr(usage, "completion_tokens", None) if usage else None

    finish_reason_str = str(finish_reason) if finish_reason is not None else None
    truncated_flag = False
    if finish_reason_str:
        truncated_flag = finish_reason_str.lower() in {"length", "max_tokens"}
    if not truncated_flag and output_tokens is not None and request_max_tokens is not None:
        truncated_flag = output_tokens >= request_max_tokens

    return {
        "finish_reason": finish_reason_str,
        "output_tokens": output_tokens,
        "request_max_tokens": request_max_tokens,
        "truncated_flag": truncated_flag,
    }


def extract_vllm_output_meta(
    output_obj: Any,
    completion_obj: Any,
    request_max_tokens: Optional[int] = None,
) -> Dict[str, Any]:
    """vLLM 출력에서 종료 사유와 토큰 사용량을 안전하게 추출."""
    finish_reason = getattr(completion_obj, "finish_reason", None)
    stop_reason = getattr(completion_obj, "stop_reason", None)
    token_ids = getattr(completion_obj, "token_ids", None)

    output_tokens = len(token_ids) if token_ids is not None else None
    if output_tokens is None:
        outputs = getattr(output_obj, "outputs", None) or []
        if outputs:
            text = getattr(outputs[0], "text", "")
            output_tokens = None if not text else None

    finish_reason_str = str(finish_reason) if finish_reason is not None else None
    stop_reason_str = str(stop_reason) if stop_reason is not None else None

    truncated_flag = False
    if finish_reason_str:
        truncated_flag = finish_reason_str.lower() in {"length", "max_tokens"}
    if not truncated_flag and stop_reason_str:
        truncated_flag = stop_reason_str.lower() in {"length", "max_tokens"}
    if not truncated_flag and output_tokens is not None and request_max_tokens is not None:
        truncated_flag = output_tokens >= request_max_tokens

    return {
        "finish_reason": finish_reason_str,
        "stop_reason": stop_reason_str,
        "output_tokens": output_tokens,
        "request_max_tokens": request_max_tokens,
        "truncated_flag": truncated_flag,
    }


def extract_answer_legacy(raw_text: str, answer_type: Optional[str]) -> str:
    """Recover the final answer from reasoning-heavy model output."""
    import json as _json

    normalized_answer_type = normalize_answer_type(answer_type)
    original_text = (raw_text or "").strip()
    if not original_text:
        return ""

    if "</think>" in original_text:
        after_think = original_text.split("</think>")[-1].strip()
    elif "assistantfinal" in original_text:
        parts = original_text.split("assistantfinal")
        after_think = parts[-1].strip()
        if after_think.startswith("think"):
            after_think = after_think[5:].strip()
    elif "<think>" in original_text:
        after_think = original_text.split("<think>")[0].strip()
    else:
        after_think = original_text

    cleaned = after_think
    for _ in range(3):
        cleaned = re.sub(r"<([^>]+)>", r"\1", cleaned).strip()

    prefixes_to_remove = [
        r"^analysis\s*",
        r"^we need to\s*",
        r"^we need\s*",
        r"^based on\s*",
        r"^the answer is\s*",
        r"^answer:\s*",
        r"^result:\s*",
        r"^\**answer\**:\s*",
        r"^json\s*",
        r"^set\s*",
        r"^map\s*",
        r"^text\s*",
        r"^device:\s*",
        r"^router:\s*",
        r"^hostname:\s*",
    ]
    for prefix in prefixes_to_remove:
        cleaned = re.sub(prefix, "", cleaned, flags=re.IGNORECASE)

    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    if not lines and cleaned.strip():
        lines = [cleaned.strip()]
    if not lines:
        return ""

    first_line = lines[0]

    if first_line.lower().startswith("we ") and len(first_line) > 50:
        if normalized_answer_type == "number":
            num_match = re.search(r"\b(-?\d+\.?\d*)\b", first_line)
            if num_match:
                first_line = num_match.group(1)
        elif normalized_answer_type == "text":
            device_match = re.search(r"\bof\s+([A-Za-z0-9_.:/-]+)", first_line)
            if device_match:
                first_line = device_match.group(1)

    if normalized_answer_type == "set":
        match = re.search(r"\[[\s\S]*?\]", cleaned)
        if match:
            try:
                parsed = _json.loads(match.group(0))
                return _json.dumps(parsed, ensure_ascii=False)
            except Exception:
                pass
        return "[]"

    if normalized_answer_type in {"map", "map_str_int", "map_str_str"}:
        match = re.search(r"\{[\s\S]*?\}", cleaned)
        if match:
            try:
                parsed = _json.loads(match.group(0))
                return _json.dumps(parsed, ensure_ascii=False)
            except Exception:
                pass
        return "{}"

    if normalized_answer_type == "number":
        match = re.search(r"-?\d+\.?\d*", cleaned)
        if match:
            return match.group(0)
        return "0"

    if normalized_answer_type == "boolean":
        lower = cleaned.lower()
        if "true" in lower or "yes" in lower:
            return "true"
        if "false" in lower or "no" in lower:
            return "false"
        return "false"

    text = first_line.strip("\"'")
    if len(text.split()) > 5:
        text = text.split()[0]
    if text.lower() == "login local":
        text = "local"
    return text


def resolve_max_tokens(
    level: str,
    answer_type: Optional[str] = None,
    level_token_overrides: Optional[Dict[str, int]] = None,
    decoding_mode: str = Config.DECODING_MODE_DEFAULT,
) -> int:
    """Return effective max_tokens for a given difficulty level and answer type."""
    normalized = str(level or "L1").strip().upper()
    if level_token_overrides and normalized in level_token_overrides:
        base_max_tokens = level_token_overrides[normalized]
    else:
        base_max_tokens = Config.MAX_OUTPUT_BY_LEVEL.get(normalized, Config.MAX_OUTPUT_DEFAULT)

    normalized_mode = str(decoding_mode or Config.DECODING_MODE_DEFAULT).strip().lower()
    if normalized_mode != "legacy":
        normalized_answer_type = normalize_answer_type(answer_type)
        type_cap = Config.MAX_OUTPUT_CAP_BY_ANSWER_TYPE.get(normalized_answer_type)
        if type_cap is not None:
            return min(base_max_tokens, type_cap)
    return base_max_tokens


def build_stop_sequences(
    answer_type: Optional[str],
    decoding_mode: str = Config.DECODING_MODE_DEFAULT,
) -> List[str]:
    """Return conservative stop sequences for one-line answer extraction."""
    normalized_answer_type = normalize_answer_type(answer_type)
    normalized_mode = str(decoding_mode or Config.DECODING_MODE_DEFAULT).strip().lower()

    if normalized_mode == "legacy":
        stop_sequences = [
            "<|eot_id|>",
            "<|end|>",
            "Question:",
            "User:",
            "=== QUESTION ===",
            "\n\nExample",
            "\n\nQuestion:",
            "\nBased on the analysis",
            "\nIn summary",
            "\nThe answer is",
        ]
    else:
        stop_sequences = [
            "<|eot_id|>",
            "<|end|>",
            "Question:",
            "=== QUESTION ===",
            "\n\nQuestion:",
        ]

        if normalized_answer_type in {"text", "number", "boolean", "path"}:
            stop_sequences.extend(["\n", "\r\n"])

        stop_sequences.extend([
            "\nExplanation:",
            "\nReasoning:",
            "\nAnalysis:",
            "\nThe answer is",
        ])

    # Preserve order but deduplicate.
    seen = set()
    deduped = []
    for item in stop_sequences:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    deduped = []
    for item in items:
        if item is None:
            continue
        item = str(item).strip()
        if not item:
            continue
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def should_tokenize_chat_template(model_key: str, hf_path: str, tokenizer: Any) -> bool:
    """Use tokenized chat templates for tokenizers that warn on tokenize=False."""
    tokenizer_cls = type(tokenizer).__name__.lower()
    if "mistral" in tokenizer_cls or "mistral" in str(getattr(tokenizer, "__module__", "")).lower():
        return True
    if "mistral" in str(model_key).lower() or "mistral" in str(hf_path).lower():
        return True
    return False


# === VLLM Global Engine Manager ===
# 여러 Lab을 돌 때 모델을 계속 로드/언로드 하는 비효율 방지용 싱글톤 래퍼

class VLLMEngineManager:
    _instance = None
    _current_model_key = None
    _current_engine_signature = None
    _api_clients = {}
    
    @classmethod
    def get_engine(
        cls,
        model_key: str,
        gpu_util: float,
        logger: logging.Logger,
        max_model_len_override: Optional[str] = None,
    ):
        model_info = Config.MODEL_DICT.get(model_key)
        if not model_info:
            raise ValueError(f"Unknown model key: {model_key}")
            
        hf_path = model_info["hf_path"]
        quantization = model_info.get("quant")
        backend = model_info.get("backend", "vllm_offline")
        model_max_ctx = model_info.get("max_ctx", Config.NUM_CTX)
        if max_model_len_override is not None:
            override = str(max_model_len_override).strip().lower()
            model_max_ctx = -1 if override == "auto" else int(max_model_len_override)
        engine_signature = (model_key, backend, gpu_util, model_max_ctx)

        if backend in ("openai", "openrouter"):
            if backend not in cls._api_clients:
                try:
                    from openai import OpenAI
                except ImportError:
                    raise RuntimeError("openai 패키지가 설치되어 있지 않습니다. pip install openai")

                if backend == "openai":
                    api_key = os.getenv("OPENAI_API_KEY")
                    if not api_key:
                        raise RuntimeError("OPENAI_API_KEY 환경변수가 설정되어 있지 않습니다.")
                    cls._api_clients[backend] = OpenAI(api_key=api_key)
                    logger.info(f"Initialized OpenAI client for {hf_path}")
                else:
                    api_key = os.getenv("OPENROUTER_API_KEY")
                    if not api_key:
                        raise RuntimeError("OPENROUTER_API_KEY 환경변수가 설정되어 있지 않습니다.")

                    extra_headers = {}
                    site_url = os.getenv("OPENROUTER_SITE_URL")
                    app_name = os.getenv("OPENROUTER_APP_NAME")
                    if site_url:
                        extra_headers["HTTP-Referer"] = site_url
                    if app_name:
                        extra_headers["X-OpenRouter-Title"] = app_name

                    client_kwargs = {
                        "api_key": api_key,
                        "base_url": "https://openrouter.ai/api/v1",
                    }
                    if extra_headers:
                        client_kwargs["default_headers"] = extra_headers

                    client_kwargs["max_retries"] = 0
                    cls._api_clients[backend] = OpenAI(**client_kwargs)
                    logger.info(f"Initialized OpenRouter client for {hf_path}")

            cls._current_model_key = model_key
            cls._current_engine_signature = engine_signature
            return cls._api_clients[backend], None

        # 기존 VLLM 모델이 로드되어 있고, 새로 요청한 모델과 다르면 언로드
        if cls._instance is not None and cls._current_engine_signature != engine_signature:
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
            
            max_ctx_label = f"{model_max_ctx} (auto-fit)" if model_max_ctx == -1 else str(model_max_ctx)
            logger.info(f"Loading vLLM engine: {hf_path} (quant={quantization}, max_model_len={max_ctx_label})")
            
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
            cls._current_engine_signature = engine_signature
            
        return cls._instance, cls._instance.get_tokenizer()


# === Main Evaluator ===

def run_evaluation(
    model_key: str,
    lab_key: str,
    gpu_util: float,
    limit: Optional[int] = None,
    include_levels: Optional[List[str]] = None,
    exclude_levels: Optional[List[str]] = None,
    level_token_overrides: Optional[Dict[str, int]] = None,
    group_batch_size: Optional[int] = None,
    group_batch_levels: Optional[List[str]] = None,
    max_model_len_override: Optional[str] = None,
    use_structured_outputs: bool = False,
    decoding_mode: str = Config.DECODING_MODE_DEFAULT,
    run_id: Optional[str] = None,
    resume: bool = False,
):
    logger, timestamp = setup_logger(model_key, lab_key, run_id=run_id)

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
        llm, tokenizer = VLLMEngineManager.get_engine(
            model_key,
            gpu_util,
            logger,
            max_model_len_override=max_model_len_override,
        )
    except Exception as e:
        logger.critical(f"Failed to load VLLM engine: {e}")
        return None

    model_backend = Config.MODEL_DICT.get(model_key, {}).get("backend", "vllm_offline")
    model_info = Config.MODEL_DICT.get(model_key, {})
    hf_path = model_info.get("hf_path", "")
    start_time = time.time()
    outputs_text = [""] * len(data)  # 원래 순서 유지용
    outputs_meta = [
        {
            "finish_reason": None,
            "stop_reason": None,
            "output_tokens": None,
            "request_max_tokens": None,
            "truncated_flag": False,
        }
        for _ in range(len(data))
    ]
    model_info = Config.MODEL_DICT.get(model_key, {})
    display_name = model_info.get("display", model_key)
    clean_display = display_name.replace(" ", "_").replace("/", "_")
    dataset_language = infer_dataset_language(dataset_path)
    group_batch_level_set = {
        str(level or "").strip().upper()
        for level in (group_batch_levels or [])
        if str(level or "").strip()
    }
    result_dir = Config.RESULT_DIR / f"{clean_display}" / f"Lab{lab_key}"
    result_dir.mkdir(parents=True, exist_ok=True)
    output_file = result_dir / f"results_raw_vllm_{dataset_language}_{timestamp}.json"
    parts_dir = result_dir / "_parts" / output_file.stem
    completed_parts = load_completed_group_parts(parts_dir) if resume else {}
    resumed_items = 0

    if resume and completed_parts:
        for payload in completed_parts.values():
            for item in payload.get("items", []):
                try:
                    orig_idx = int(item["index"])
                except Exception:
                    continue
                if 0 <= orig_idx < len(outputs_text):
                    outputs_text[orig_idx] = item.get("raw_pred", "")
                    outputs_meta[orig_idx] = {
                        "finish_reason": item.get("finish_reason"),
                        "stop_reason": item.get("stop_reason"),
                        "output_tokens": item.get("output_tokens"),
                        "request_max_tokens": item.get("request_max_tokens"),
                        "truncated_flag": item.get("truncated_flag", False),
                    }
                    resumed_items += 1
        logger.info(
            f"Resume enabled: loaded {len(completed_parts)} completed group part(s) "
            f"covering {resumed_items} sample(s) from {parts_dir}"
        )

    if model_backend == "vllm_offline":
        # 4. Prepare Prompts (Batch) — 레벨 + 답변 타입별로 그룹화
        logger.info("Preparing prompts for batch inference...")
        prompt_groups = {}  # (level, normalized_answer_type) -> [(original_index, prompt_or_token_ids)]
        use_tokenized_chat_template = should_tokenize_chat_template(model_key, hf_path, tokenizer)
        if use_tokenized_chat_template:
            logger.info("Tokenizer warning 회피를 위해 tokenize=True chat template 경로를 사용합니다.")
        for idx, row in enumerate(data):
            messages = build_messages(
                row["question"],
                row["answer_type"],
                configs_text,
                decoding_mode=decoding_mode,
            )
            try:
                if use_tokenized_chat_template:
                    prompt = tokenizer.apply_chat_template(
                        messages,
                        tokenize=True,
                        add_generation_prompt=True,
                    )
                else:
                    prompt = tokenizer.apply_chat_template(
                        messages,
                        tokenize=False,
                        add_generation_prompt=True,
                    )
            except Exception:
                sys_msg = messages[0]["content"]
                usr_msg = messages[1]["content"]
                prompt = f"{sys_msg}\n\n{usr_msg}"

            level = row.get("level", "L1")
            normalized_answer_type = normalize_answer_type(row.get("answer_type"))
            group_key = (level, normalized_answer_type)
            if group_key not in prompt_groups:
                prompt_groups[group_key] = []
            prompt_groups[group_key].append((idx, prompt))

        # 5. Execute Inference — 레벨/타입별 배치로 분리
        for level, normalized_answer_type in sorted(prompt_groups.keys()):
            original_group = prompt_groups[(level, normalized_answer_type)]
            group = list(original_group)
            group_id = make_group_id(level, normalized_answer_type)
            existing_payload = completed_parts.get(group_id) if resume else None
            existing_items = existing_payload.get("items", []) if existing_payload else []
            if resume and existing_payload:
                if is_group_part_complete(existing_payload):
                    logger.info(
                        f"  {level}/{normalized_answer_type}: {len(group)}건 [resume-skip from {group_id}]"
                    )
                    continue
                completed_indices = {
                    int(item["index"])
                    for item in existing_items
                    if str(item.get("index", "")).isdigit()
                }
                remaining_group = [(idx, prompt) for idx, prompt in group if idx not in completed_indices]
                logger.info(
                    f"  {level}/{normalized_answer_type}: {len(group)}건 "
                    f"[resume-partial {len(existing_items)} done, {len(remaining_group)} remaining]"
                )
                group = remaining_group
                if not group:
                    continue
            max_tokens = resolve_max_tokens(
                level,
                normalized_answer_type,
                level_token_overrides,
                decoding_mode=decoding_mode,
            )
            prompts = [p for _, p in group]
            indices = [i for i, _ in group]
            structured_outputs = (
                build_structured_outputs(normalized_answer_type)
                if use_structured_outputs else None
            )

            structured_label = "structured" if structured_outputs is not None else "freeform"
            chunk_size = None
            if group_batch_size and str(level or "").strip().upper() in group_batch_level_set:
                chunk_size = max(1, int(group_batch_size))
            chunked_group = iter_group_chunks(group, chunk_size)
            chunk_note = ""
            if chunk_size and len(chunked_group) > 1:
                chunk_note = f", chunk_size={chunk_size} ({len(chunked_group)} chunk(s))"
            logger.info(
                f"  {level}/{normalized_answer_type}: {len(prompts)}건 × "
                f"max_tokens={max_tokens} [{structured_label}{chunk_note}]"
            )

            sampling_kwargs = dict(
                temperature=Config.TEMPERATURE,
                repetition_penalty=1.05,
                max_tokens=max_tokens,
                stop=build_stop_sequences(
                    normalized_answer_type,
                    decoding_mode=decoding_mode,
                ),
            )
            if structured_outputs is not None:
                sampling_kwargs["structured_outputs"] = structured_outputs

            sampling_params = SamplingParams(**sampling_kwargs)
            part_items_by_index = {}
            for item in existing_items:
                try:
                    part_items_by_index[int(item["index"])] = item
                except Exception:
                    continue

            total_expected = len(original_group)
            for chunk_idx, chunk in enumerate(chunked_group, start=1):
                chunk_prompts = [p for _, p in chunk]
                chunk_indices = [i for i, _ in chunk]
                outputs = llm.generate(chunk_prompts, sampling_params)

                for out, orig_idx in zip(outputs, chunk_indices):
                    completion = out.outputs[0]
                    outputs_text[orig_idx] = completion.text
                    generation_meta = extract_vllm_output_meta(
                        out,
                        completion,
                        request_max_tokens=max_tokens,
                    )
                    outputs_meta[orig_idx] = generation_meta
                    part_items_by_index[orig_idx] = {
                        "index": orig_idx,
                        "raw_pred": completion.text,
                        "finish_reason": generation_meta.get("finish_reason"),
                        "stop_reason": generation_meta.get("stop_reason"),
                        "output_tokens": generation_meta.get("output_tokens"),
                        "request_max_tokens": generation_meta.get("request_max_tokens"),
                        "truncated_flag": generation_meta.get("truncated_flag", False),
                    }

                part_items = [part_items_by_index[idx] for idx in sorted(part_items_by_index)]
                part_completed = len(part_items) >= total_expected
                part_file = save_group_part(
                    parts_dir=parts_dir,
                    group_id=group_id,
                    level=level,
                    answer_type=normalized_answer_type,
                    request_max_tokens=max_tokens,
                    items=part_items,
                    expected_count=total_expected,
                    completed=part_completed,
                )
                if len(chunked_group) > 1:
                    logger.info(
                        f"    checkpoint saved: {part_file} "
                        f"[chunk {chunk_idx}/{len(chunked_group)}, {len(part_items)}/{total_expected}]"
                    )
                else:
                    logger.info(f"    checkpoint saved: {part_file}")
        logger.info(f"VLLM batch inference complete: {len(data)} samples")
    elif model_backend in ("openai", "openrouter"):
        model_info = Config.MODEL_DICT.get(model_key, {})
        api_model_name = model_info.get("hf_path")
        api_delay_sec = model_info.get(
            "api_delay_sec",
            1.2 if model_backend == "openai" else 4.0,
        )
        logger.info(f"Starting {model_backend} sequential inference for {len(data)} samples...")
        consecutive_429 = 0
        for i, row in enumerate(data, 1):
            if i % 50 == 0 or i == 1:
                elapsed = time.time() - start_time
                eta = (elapsed / i) * (len(data) - i) if i > 0 else 0
                logger.info(f"Progress: {i}/{len(data)} | ETA: {eta/60:.1f}min")
            
            level = row.get("level", "L1")
            max_tokens_needed = resolve_max_tokens(
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

            # OpenRouter free tier는 일일/분당 제한 변동성이 커서 기본 딜레이를 더 보수적으로 둔다.
            time.sleep(api_delay_sec)

            for attempt in range(4):  # 최대 4회 시도 (1회 + 3회 재시도)
                try:
                    request_kwargs = {
                        "model": api_model_name,
                        "messages": messages,
                        "temperature": Config.TEMPERATURE,
                        "max_tokens": min(max_tokens_needed, 16383),
                    }
                    if model_backend == "openrouter":
                        reasoning_cfg = model_info.get("openrouter_reasoning")
                        if reasoning_cfg:
                            request_kwargs["extra_body"] = {"reasoning": reasoning_cfg}

                    resp = llm.chat.completions.create(**request_kwargs)
                    outputs_text[i - 1] = extract_api_text_response(resp)
                    outputs_meta[i - 1] = extract_api_response_meta(
                        resp,
                        request_max_tokens=request_kwargs["max_tokens"],
                    )
                    consecutive_429 = 0
                    break  # 성공 시 재시도 루프 탈출
                except Exception as e:
                    err_str = str(e)
                    if "429" in err_str and attempt < 3:
                        consecutive_429 += 1
                        if model_backend == "openrouter" and consecutive_429 >= Config.OPENROUTER_MAX_CONSECUTIVE_429:
                            raise RuntimeError(
                                f"OpenRouter rate limit persisted for {consecutive_429} consecutive samples. "
                                "Free endpoint로는 현재 전체 평가를 지속하기 어렵습니다."
                            ) from e
                        wait = (120 if model_backend == "openrouter" else 60) * (attempt + 1)
                        logger.warning(f"Rate limit on sample {i} (attempt {attempt+1}), waiting {wait}s...")
                        time.sleep(wait)
                    else:
                        logger.error(f"{model_backend} API Error on sample {i}: {type(e).__name__}: {e}")
                        outputs_text[i - 1] = ""
                        outputs_meta[i - 1] = {
                            "finish_reason": "error",
                            "output_tokens": None,
                            "request_max_tokens": min(max_tokens_needed, 16383),
                            "truncated_flag": False,
                            "error_type": type(e).__name__,
                        }
                        break
    
    duration = time.time() - start_time
    logger.info(f"Inference complete: {len(outputs_text)} samples in {duration:.1f}s ({len(outputs_text)/duration:.1f} req/s)")

    # 6. Process Results — legacy extraction compatible with reasoning-heavy outputs
    results = []
    format_stats = {}

    for i, raw_output in enumerate(outputs_text):
        row = data[i]
        cleaned = extract_answer_legacy(raw_output, row["answer_type"])
        generation_meta = outputs_meta[i] or {}

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
            "finish_reason": generation_meta.get("finish_reason"),
            "stop_reason": generation_meta.get("stop_reason"),
            "output_tokens": generation_meta.get("output_tokens"),
            "request_max_tokens": generation_meta.get("request_max_tokens"),
            "truncated_flag": generation_meta.get("truncated_flag", False),
        })

    # 7. Aggregate & Save
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
            "language": dataset_language,
            "date": str(datetime.datetime.now()),
            "duration_sec": round(duration, 2),
            "throughput": round(len(outputs_text)/duration, 2) if duration > 0 else 0,
            "dataset": str(dataset_path.name),
            "dataset_path": str(dataset_path),
            "config_dir": str(config_dir),
            "result_model_dir": clean_display,
            "result_lab_dir": f"Lab{lab_key}",
            "total_samples": len(results),
            "tokenizer_chat_template": bool(getattr(tokenizer, "chat_template", None)),
            "enable_prefix_caching": True if model_backend == "vllm_offline" else False,
            "structured_outputs_enabled": (
                True
                if model_backend == "vllm_offline" and StructuredOutputsParams is not None and use_structured_outputs
                else False
            ),
            "decoding_mode": decoding_mode,
            "level_token_overrides": level_token_overrides or {},
            "group_batch_size": group_batch_size,
            "group_batch_levels": sorted(group_batch_level_set),
            "max_model_len_override": max_model_len_override,
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
    parser.add_argument(
        "--hard-levels-only",
        action="store_true",
        help="L4/L5 질문만 재실험합니다. --include-levels와 함께 쓰면 L4/L5로 강제됩니다.",
    )
    parser.add_argument("--l4-max-tokens", type=int, default=None, help="L4 전용 생성 토큰 상한 override")
    parser.add_argument("--l5-max-tokens", type=int, default=None, help="L5 전용 생성 토큰 상한 override")
    parser.add_argument(
        "--group-batch-size",
        type=int,
        default=None,
        help="동일 level/type 그룹을 여러 llm.generate 호출로 나눌 chunk 크기. 기본값은 비활성화.",
    )
    parser.add_argument(
        "--group-batch-levels",
        nargs="+",
        default=["L4", "L5"],
        help="group chunking을 적용할 level 목록. 기본값: L4 L5",
    )
    parser.add_argument(
        "--max-model-len",
        default=None,
        help="vLLM max_model_len override. 정수 또는 'auto' 사용 가능.",
    )
    parser.add_argument(
        "--structured-outputs",
        action="store_true",
        help="vLLM structured outputs 제약을 켭니다. 기본값은 비활성화입니다.",
    )
    parser.add_argument(
        "--decoding-mode",
        choices=["legacy", "strict"],
        default=Config.DECODING_MODE_DEFAULT,
        help="디코딩/추출 정책. legacy는 예전 통신학회 스타일 reasoning+후처리, strict는 한 줄 응답 강제.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="결과 파일/로그/체크포인트를 고정할 실행 ID. 재개할 때 같은 값을 사용합니다.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="같은 --run-id의 group checkpoint를 읽어 완료된 level/answer_type 그룹을 건너뜁니다.",
    )

    args = parser.parse_args()

    if args.resume and not args.run_id:
        raise ValueError("--resume 사용 시에는 동일 실행을 식별할 --run-id를 함께 지정해야 합니다.")

    if args.hard_levels_only:
        args.include_levels = ["L4", "L5"]

    group_batch_levels = dedupe_preserve_order([str(level).upper() for level in (args.group_batch_levels or [])])

    level_token_overrides = {}
    if args.l4_max_tokens is not None:
        level_token_overrides["L4"] = args.l4_max_tokens
    if args.l5_max_tokens is not None:
        level_token_overrides["L5"] = args.l5_max_tokens

    if "all" in [m.lower() for m in args.model]:
        models = list(Config.ALL_MODELS)
    else:
        models = dedupe_preserve_order(args.model)
        invalid_models = [m for m in models if m not in Config.MODEL_DICT]
        if invalid_models:
            raise ValueError(f"Unknown model tag(s): {invalid_models}")

    if "all" in [l.lower() for l in args.lab]:
        labs = list(Config.LABS.keys())
    else:
        labs = dedupe_preserve_order([l.upper() for l in args.lab])
        invalid_labs = [l for l in labs if l not in Config.LABS]
        if invalid_labs:
            raise ValueError(f"Unknown lab key(s): {invalid_labs}")

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
                level_token_overrides=level_token_overrides or None,
                group_batch_size=args.group_batch_size,
                group_batch_levels=group_batch_levels,
                max_model_len_override=args.max_model_len,
                use_structured_outputs=args.structured_outputs,
                decoding_mode=args.decoding_mode,
                run_id=args.run_id,
                resume=args.resume,
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
