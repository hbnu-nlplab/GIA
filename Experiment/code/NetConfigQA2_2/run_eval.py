"""
NetConfigQA2.0 Evaluator — Ollama + OpenAI API

Ollama(로컬 모델) 또는 OpenAI API를 통해 LLM 추론을 수행하고 원본 응답을 저장합니다.
채점은 analyze_results.py에서 수행합니다.

Usage:
    # 단일 모델, 단일 Lab
    python run_eval.py --model gpt-oss:20b --lab A

    # 전체 모델, 전체 Lab (6×4 = 24회)
    python run_eval.py --model all --lab all

    # 특정 모델들, 특정 Lab들
    python run_eval.py --model gpt-oss:20b qwen3.5:27b --lab A B

    # OpenAI API 모델
    python run_eval.py --model gpt-4o-mini --lab A --backend openai
"""

import os
import json
import csv
import argparse
import time
import logging
import datetime
import sys
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

    # Ollama 모델 매핑 (논문용 이름 → Ollama 태그)
    MODEL_DICT = {
        "gpt-oss:20b":                      {"tag": "gpt-oss:20b",                      "display": "GPT-OSS-20B",       "backend": "ollama"},
        "qwen3-coder:30b-a3b-q4_K_M":       {"tag": "qwen3-coder:30b-a3b-q4_K_M",       "display": "Qwen3-Coder",       "backend": "ollama"},
        "gemma3:27b-it-q4_K_M":             {"tag": "gemma3:27b-it-q4_K_M",             "display": "Gemma-3-27B",       "backend": "ollama"},
        "glm-4.7-flash:q4_K_M":             {"tag": "glm-4.7-flash:q4_K_M",             "display": "GLM-4.7-Flash",     "backend": "ollama"},
        "qwen3.5:27b":                       {"tag": "qwen3.5:27b",                       "display": "Qwen3.5-27B",       "backend": "ollama"},
        "gpt-4o-mini":                       {"tag": "gpt-4o-mini",                       "display": "GPT-4o-mini",       "backend": "openai"},
    }

    # 전체 모델 키 (--model all 용)
    ALL_MODELS = list(MODEL_DICT.keys())

    # Ollama 서버
    OLLAMA_BASE_URL = "http://localhost:11434/v1"

    # 공통 평가 파라미터
    TEMPERATURE = 0.0

    # 레벨별 num_predict 차등 적용 — L1-L3는 짧은 답변, L4-L5는 reasoning 토큰 필요
    MAX_OUTPUT_BY_LEVEL = {
        "L1": 4096,
        "L2": 4096,
        "L3": 8192,
        "L4": 32768,
        "L5": 70000,
    }
    MAX_OUTPUT_DEFAULT = 32768

    # num_ctx: Lab-D (31K input + 4K output = 35K) 기준으로 설정
    # VRAM 초과 시 Ollama가 자동으로 RAM 오프로딩 (속도 저하 있지만 동작)
    NUM_CTX = 49152  # 48K — 전 모델 공통 (공정 비교)
    # GPT-4o-mini (API)는 128K 지원, num_ctx 불필요


# === Logger ===

def setup_logger(model_name: str, lab_name: str) -> tuple:
    Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = model_name.replace("/", "_").replace(":", "_")
    log_file = Config.LOG_DIR / f"eval_{clean_name}_Lab{lab_name}_{timestamp}.log"

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


# === Config File Manager ===

class ConfigManager:
    """네트워크 장비 설정 파일(.cfg) 로드 및 캐싱"""

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
        """모든 config 파일을 하나의 문자열로 결합"""
        combined = ""
        for host in sorted(self._cache.keys()):
            combined += f"\n=== START OF CONFIG: {host.upper()} ===\n"
            combined += self._cache[host]
            combined += f"\n=== END OF CONFIG: {host.upper()} ===\n"
        return combined


# === Dataset Finder ===

def find_latest_dataset(lab_key: str) -> Optional[Path]:
    """Lab의 최신 데이터셋 CSV 파일을 찾습니다."""
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder:
        return None

    dataset_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "Dataset"
    if not dataset_dir.exists():
        return None

    # 최신 타임스탬프 폴더 찾기
    timestamp_dirs = sorted(
        [d for d in dataset_dir.iterdir() if d.is_dir() and d.name.isdigit() or "_" in d.name],
        key=lambda d: d.name,
        reverse=True
    )

    for ts_dir in timestamp_dirs:
        csv_files = list(ts_dir.glob("*_dataset_batfish_*_ko.csv"))
        if csv_files:
            return csv_files[0]

    # 직접 Dataset/ 아래에 있는 경우
    csv_files = list(dataset_dir.glob("*_dataset_batfish_*_ko.csv"))
    if csv_files:
        return sorted(csv_files, key=lambda f: f.name, reverse=True)[0]

    return None


def find_config_dir(lab_key: str) -> Optional[Path]:
    """Lab의 configs 폴더 경로를 반환합니다."""
    lab_folder = Config.LABS.get(lab_key)
    if not lab_folder:
        return None
    config_dir = Config.DATA_DIR / "Pnetlab" / lab_folder / "configs"
    return config_dir if config_dir.exists() else None


# === Prompt Builder ===

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


# === Inference Engine ===

class InferenceEngine:
    """Ollama / OpenAI API 공통 추론 엔진"""

    def __init__(self, model_key: str, backend: str, logger: logging.Logger):
        self.model_key = model_key
        self.backend = backend
        self.logger = logger

        model_info = Config.MODEL_DICT.get(model_key, {})
        self.model_tag = model_info.get("tag", model_key)
        self.display_name = model_info.get("display", model_key)

        if backend == "ollama":
            import requests as _req
            # Ollama native API — num_ctx 설정 가능
            self._ollama_url = "http://localhost:11434/api/chat"
            self._requests = _req
            # 연결 테스트
            try:
                _req.get("http://localhost:11434/api/tags", timeout=5)
            except Exception as e:
                raise RuntimeError(f"Ollama 서버 연결 실패: {e}")
        elif backend == "openai":
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise RuntimeError("OPENAI_API_KEY 환경변수가 설정되어 있지 않습니다.")
            self.client = OpenAI(api_key=api_key)
        else:
            raise ValueError(f"Unknown backend: {backend}")

        self.num_ctx = Config.NUM_CTX
        self.logger.info(f"Engine initialized: {self.display_name} ({self.model_tag}) via {backend}, num_ctx={self.num_ctx}")

    def generate(self, messages: List[Dict[str, str]], level: str = "") -> str:
        """단일 요청 추론. level에 따라 num_predict를 조절."""
        max_tokens = Config.MAX_OUTPUT_BY_LEVEL.get(level, Config.MAX_OUTPUT_DEFAULT)
        try:
            if self.backend == "ollama":
                resp = self._requests.post(self._ollama_url, json={
                    "model": self.model_tag,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": Config.TEMPERATURE,
                        "num_ctx": self.num_ctx,
                        "num_predict": max_tokens,
                    }
                }, timeout=1800)
                data = resp.json()
                return data.get("message", {}).get("content", "")
            else:
                response = self.client.chat.completions.create(
                    model=self.model_tag,
                    messages=messages,
                    temperature=Config.TEMPERATURE,
                    max_tokens=min(max_tokens, 16384),  # OpenAI API 한도
                )
                return response.choices[0].message.content or ""
        except Exception as e:
            self.logger.error(f"Generation error: {e}")
            return ""


# === Format Stability Metrics ===

def measure_format_stability(raw_output: str, answer_type: str) -> Dict[str, Any]:
    """Format Stability 측정 — Parse 성공 여부 및 Completeness"""
    import re

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
            # JSON array 파싱 시도
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

        else:  # text, scalar_str
            # 텍스트는 단일 값이면 OK
            lines = [l.strip() for l in cleaned.split('\n') if l.strip()]
            result["parseable"] = len(lines) >= 1 and len(lines[0].split()) <= 10
            result["completeness"] = 1.0 if result["parseable"] else 0.0

    except Exception:
        pass

    return result


# === Main Evaluator ===

def run_evaluation(
    model_key: str,
    lab_key: str,
    backend: str,
    limit: Optional[int] = None,
    include_levels: Optional[List[str]] = None,
    exclude_levels: Optional[List[str]] = None,
):
    """단일 모델 × 단일 Lab 평가 실행"""

    logger, timestamp = setup_logger(model_key, lab_key)

    # 데이터셋 찾기
    dataset_path = find_latest_dataset(lab_key)
    if not dataset_path:
        logger.error(f"Dataset not found for Lab-{lab_key}")
        return None
    logger.info(f"Dataset: {dataset_path}")

    # Config 로드
    config_dir = find_config_dir(lab_key)
    if not config_dir:
        logger.error(f"Config dir not found for Lab-{lab_key}")
        return None

    config_manager = ConfigManager(config_dir, logger)
    configs_text = config_manager.get_all_configs()
    logger.info(f"Config text length: {len(configs_text)} chars (~{len(configs_text)//4} tokens)")

    # 데이터셋 로드 + 필터링
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

    # 추론 엔진 초기화
    engine = InferenceEngine(model_key, backend, logger)

    # 추론 실행
    results = []
    start_time = time.time()

    # 결과 폴더 및 파일 경로 설정
    model_info = Config.MODEL_DICT.get(model_key, {})
    display_name = model_info.get("display", model_key)
    clean_display = display_name.replace(" ", "_").replace("/", "_")
    result_dir = Config.RESULT_DIR / f"{clean_display}" / f"Lab{lab_key}"
    result_dir.mkdir(parents=True, exist_ok=True)

    output_file = result_dir / f"results_raw_{timestamp}.json"
    partial_file = result_dir / f"results_partial_{timestamp}.json"

    for i, row in enumerate(data, 1):
        if i % 50 == 0 or i == 1:
            elapsed = time.time() - start_time
            eta = (elapsed / i) * (len(data) - i) if i > 0 else 0
            logger.info(f"Progress: {i}/{len(data)} ({i/len(data)*100:.1f}%) | ETA: {eta/60:.1f}min")
            
            # 중간 저장 (Checkpointing)
            if i % 50 == 0:
                try:
                    with open(partial_file, 'w', encoding='utf-8') as pf:
                        json.dump({"progress": i, "total": len(data), "results": results}, pf, ensure_ascii=False)
                except Exception as e:
                    logger.warning(f"Checkpoint save failed: {e}")

        level = row.get("level", "L1")
        messages = build_messages(row["question"], row["answer_type"], configs_text)
        raw_output = engine.generate(messages, level=level)

        # Format Stability 측정
        format_metrics = measure_format_stability(raw_output, row["answer_type"])

        results.append({
            "question_id": row.get("question_id", row.get("id", str(i))),
            "question": row["question"],
            "gold": row["answer"],
            "raw_pred": raw_output,
            "pred": raw_output.strip(),
            "level": row.get("level", "L1"),
            "category": row.get("category", "General"),
            "answer_type": row["answer_type"],
            "answer_status": row.get("answer_status", "OK"),
            "format_parseable": format_metrics["parseable"],
            "format_completeness": format_metrics["completeness"],
        })

    duration = time.time() - start_time
    logger.info(f"Inference complete: {len(results)} samples in {duration:.1f}s ({len(results)/duration:.1f} req/s)")

    # Format Stability 집계 (방어적 작성)
    format_stats = {}
    try:
        ans_types = set(r.get("answer_type") for r in results if "answer_type" in r)
        for atype in ans_types:
            type_results = [r for r in results if r.get("answer_type") == atype]
            if not type_results: continue
            parse_rate = sum(1 for r in type_results if r.get("format_parseable")) / len(type_results)
            avg_completeness = sum(r.get("format_completeness", 0) for r in type_results) / len(type_results)
            format_stats[atype] = {
                "parse_success_rate": round(parse_rate, 4),
                "avg_completeness": round(avg_completeness, 4),
                "count": len(type_results),
            }
    except Exception as e:
        logger.error(f"Format stats aggregation failed: {e}")

    # 최종 결과 데이터 구성 (최대한 방어적으로)
    try:
        output_data = {
            "meta": {
                "model": display_name,
                "model_tag": model_key,
                "backend": backend,
                "lab": f"Lab-{lab_key}",
                "lab_folder": Config.LABS.get(lab_key, ""),
                "date": str(datetime.datetime.now()),
                "duration_sec": round(duration, 2),
                "dataset": str(dataset_path.name),
                "total_samples": len(results),
                "temperature": getattr(Config, "TEMPERATURE", 0.0),
                "num_ctx": getattr(Config, "NUM_CTX", 0),
                "max_output_by_level": getattr(Config, "MAX_OUTPUT_BY_LEVEL", {}),
                "include_levels": sorted(include_set) if include_set else [],
                "exclude_levels": sorted(exclude_set) if exclude_set else [],
            },
            "format_stability": format_stats,
            "results": results,
        }
    except Exception as e:
        logger.error(f"Metadata construction failed: {e}. Saving raw results only.")
        output_data = {"meta": {"error": str(e)}, "results": results}

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    # 성공 시 부분 저장 파일 삭제
    if partial_file.exists():
        try: partial_file.unlink()
        except: pass

    logger.info(f"Saved: {output_file}")
    logger.info(f"Format Stability: {json.dumps(format_stats, indent=2)}")

    return output_file


# === CLI ===

def main():
    # Pre-flight Check: Ensure all required Config attributes exist
    required_attrs = ["MODEL_DICT", "LABS", "NUM_CTX", "TEMPERATURE", "MAX_OUTPUT_BY_LEVEL", "RESULT_DIR", "DATA_DIR"]
    missing = [attr for attr in required_attrs if not hasattr(Config, attr)]
    if missing:
        print(f"Error: Missing Config attributes: {missing}")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="NetConfigQA2.0 Evaluator (Ollama + Ollama API)")

    parser.add_argument(
        "--model", nargs="+", required=True,
        help="모델 태그 (예: gpt-oss:20b qwen3.5:27b) 또는 'all'",
    )
    parser.add_argument(
        "--lab", nargs="+", required=True,
        help="Lab 키 (예: A B C D) 또는 'all'",
    )
    parser.add_argument(
        "--backend", choices=["ollama", "openai"], default=None,
        help="추론 백엔드 (미지정 시 MODEL_DICT에서 자동 결정)",
    )
    parser.add_argument("--limit", type=int, default=None, help="평가 샘플 수 제한 (디버깅용)")
    parser.add_argument("--include-levels", nargs="+", default=None)
    parser.add_argument("--exclude-levels", nargs="+", default=["L6"])

    args = parser.parse_args()

    # 모델/Lab 확장
    models = Config.ALL_MODELS if "all" in [m.lower() for m in args.model] else args.model
    labs = list(Config.LABS.keys()) if "all" in [l.lower() for l in args.lab] else [l.upper() for l in args.lab]

    total_runs = len(models) * len(labs)
    print(f"\n{'='*60}")
    print(f"NetConfigQA2.0 Evaluation")
    print(f"Models: {len(models)} | Labs: {len(labs)} | Total runs: {total_runs}")
    print(f"{'='*60}\n")

    completed = []
    failed = []

    for run_idx, (model_key, lab_key) in enumerate(
        [(m, l) for m in models for l in labs], 1
    ):
        model_info = Config.MODEL_DICT.get(model_key, {})
        display = model_info.get("display", model_key)
        backend = args.backend or model_info.get("backend", "ollama")

        print(f"\n[{run_idx}/{total_runs}] {display} × Lab-{lab_key} (backend={backend})")
        print("-" * 40)

        try:
            output_file = run_evaluation(
                model_key=model_key,
                lab_key=lab_key,
                backend=backend,
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

    # 최종 요약
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

    print(f"\nNext: python analyze_results.py results/*/results_raw_*.json")


if __name__ == "__main__":
    main()
