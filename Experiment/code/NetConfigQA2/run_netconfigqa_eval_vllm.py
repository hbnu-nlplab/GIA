"""
NetConfigQA VLLM Evaluator - Raw Inference Only

이 스크립트는 LLM 추론만 수행하고 원본 응답을 저장합니다.
전처리, 점수 계산, 시각화는 reanalyze_results.py에서 수행합니다.
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
from typing import List, Dict

import torch

# Attempt to import vllm
try:
    from vllm import LLM, SamplingParams
except ImportError:
    print("Error: 'vllm' module not found. Please install it using `pip install vllm`.")
    pass

# === Configuration ===
class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    # 프로젝트 루트(GIA) 폴더를 찾기 위해 3단계 위로 이동
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(BASE_DIR)))
    DATA_DIR = os.path.join(ROOT_DIR, "Data") 
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    RESULT_DIR = os.path.join(BASE_DIR, "results")
    
    # Defaults
    DEFAULT_DATASET_PATH = os.path.join(DATA_DIR, "Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251230_125613.csv").replace("/", os.sep)
    DEFAULT_CONFIG_DIR = os.path.join(DATA_DIR, "Pnetlab/Research_Institute_Internal_DC/configs").replace("/", os.sep)
    
    # Model Dictionary (AWQ optimized)
    MODEL_DICT = {
        "Mistral3-8B": "mistralai/Ministral-3-8B-Instruct-2512",
        "Qwen3-8B": "Qwen/Qwen3-8B",
        "GPT-OSS-20B": "openai/gpt-oss-20b",
        "LLlama-3.1-8B": "meta-llama/Llama-3.1-8B-Instruct",
    }

# === Logger ===
def setup_logger(model_name: str):
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_model_name = model_name.replace("/", "_").replace("\\", "_")
    log_file = os.path.join(Config.LOG_DIR, f"eval_{clean_model_name}_{timestamp}.log")
    
    logger = logging.getLogger("NetConfigQA_VLLM")
    logger.setLevel(logging.INFO)
    logger.handlers = [] # clear handlers
    
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)
    
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(sh)
    
    return logger, timestamp

logger = logging.getLogger("NetConfigQA_VLLM") # Global placeholder

# --- Core Logic Reuse ---

def extract_answer_from_raw(raw_text: str, answer_type: str) -> str:
    """
    GPT-OSS-20B와 같이 불필요한 텍스트를 출력하는 모델의 응답에서 답만 추출
    
    전략:
    1. </think> 태그 이후의 첫 번째 유의미한 라인 추출
    2. "The answer is", "Based on", "Analysis" 등의 설명 텍스트 제거
    3. JSON 형식 답변 파싱 시도
    """
    import re
    import json
    
    original_text = raw_text  # Keep for fallback
    
    # 1. </think> 태그 및 구분자 이후 텍스트 추출
    if '</think>' in raw_text:
        after_think = raw_text.split('</think>')[-1].strip()
    elif 'assistantfinal' in raw_text:
        # Handle multiple assistantfinal - take LAST one
        parts = raw_text.split('assistantfinal')
        after_think = parts[-1].strip()
        
        # Handle 'assistantfinal think' pattern
        if after_think.startswith('think'):
            after_think = after_think[5:].strip()
            
            # If long explanation without structured answer, extract from original
            if len(after_think) > 80 and not any(after_think.strip().startswith(c) for c in ['{', '[', '"']):
                # Look for last JSON object
                json_matches = list(re.finditer(r'\{[^{}]+:[^{}]+\}', original_text))
                if json_matches:
                    after_think = json_matches[-1].group(0)
                # Look for last JSON array
                elif re.search(r'\[[^\[\]]+\]', original_text):
                    array_matches = list(re.finditer(r'\[[^\[\]]+\]', original_text))
                    after_think = array_matches[-1].group(0)
                # Extract number from explanation
                elif len(after_think) > 100:
                    sentences = after_think.split('.')
                    if sentences:
                        last_sent = sentences[-1].strip()
                        num_match = re.search(r'\b(\d+)\b', last_sent)
                        if num_match:
                            after_think = num_match.group(1)
    elif '<think>' in raw_text:
        after_think = raw_text.split('<think>')[0].strip()
    else:
        after_think = raw_text.strip()
    
    # 2. 불필요한 프리픽스 제거
    prefixes_to_remove = [
        r'^analysis\s*',
        r'^we need to\s*',
        r'^based on\s*',
        r'^the answer is\s*',
        r'^answer:\s*',
        r'^result:\s*',
        r'^\**answer\**:\s*',
        r'^json\s*',
        r'^set\s*',
        r'^map\s*',
        r'^text\s*',
    ]
    
    cleaned = after_think
    for prefix in prefixes_to_remove:
        cleaned = re.sub(prefix, '', cleaned, flags=re.IGNORECASE)
    
    # 3. 첫 번째 라인만 추출 (여러 줄 설명이 있을 경우)
    lines = [l.strip() for l in cleaned.split('\n') if l.strip()]
    if not lines:
        return "null"
    
    first_line = lines[0]
    
    # 4. 타입별 특수 처리
    if answer_type == "set":
        # JSON 배열 파싱 시도
        match = re.search(r'\[.*?\]', first_line)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed)
            except:
                pass
        return "[]"
    
    elif answer_type == "map":
        # JSON 객체 파싱 시도
        match = re.search(r'\{.*?\}', first_line)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed)
            except:
                pass
        return "{}"
    
    elif answer_type in ["number", "numeric"]:
        # 숫자만 추출
        match = re.search(r'-?\d+\.?\d*', first_line)
        if match:
            return match.group(0)
        return "0"
    
    elif answer_type == "boolean":
        # true/false 추출
        lower = first_line.lower()
        if 'true' in lower or 'yes' in lower:
            return "true"
        elif 'false' in lower or 'no' in lower:
            return "false"
        return "false"
    
    else:  # text
        # 따옴표나 불필요한 문장 제거
        text = first_line.strip('"\'')
        # 문장 형태면 첫 단어/구문만 추출
        if len(text.split()) > 5:
            # 너무 긴 설명이면 첫 단어만
            text = text.split()[0]
        # Cisco-specific: 'login local' -> 'local'
        if text.lower() == 'login local':
            text = 'local'
        return text

class ConfigManager:
    """Manages loading and caching of network device configuration files."""
    def __init__(self, config_dirs: List[str]):
        self.config_dirs = [Path(d) for d in config_dirs]
        self._cache: Dict[str, str] = {} # hostname -> content
        self._load_all_configs()

    def _load_all_configs(self):
        for config_dir in self.config_dirs:
            if not config_dir.exists():
                logger.warning(f"Config directory not found: {config_dir}")
                continue
            for cfg_path in config_dir.rglob("*.cfg"):
                try:
                    hostname = cfg_path.stem
                    with open(cfg_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    self._cache[hostname.lower()] = content
                except Exception as e:
                    logger.error(f"Failed to load {cfg_path}: {e}")
        logger.info(f"Loaded {len(self._cache)} configuration files.")

    def get_configs(self, hostnames: List[str]) -> str:
        combined_config = ""
        # Sort hostnames to ensure deterministic prompts (better caching)
        targets = sorted(list(set(h.lower() for h in hostnames if h)))
        
        for host in targets:
            if host in self._cache:
                combined_config += f"\n=== START OF CONFIG: {host.upper()} ===\n"
                combined_config += self._cache[host]
                combined_config += f"\n=== END OF CONFIG: {host.upper()} ===\n"
        return combined_config

# === Evaluator ===

class VLLMEvaluator:
    def __init__(self, model_key: str, config_dir: str, gpu_util: float = 0.9):
        # Initial Logging
        global logger
        logger, self.timestamp = setup_logger(model_key)
        
        self.model_name = model_key
        self.model_path = Config.MODEL_DICT.get(model_key, model_key)
        self.gpu_util = gpu_util
        
        logger.info(f"Initializing VLLM Evaluator...")
        logger.info(f"Model: {self.model_name} ({self.model_path})")
        logger.info(f"Config Dir: {config_dir}")
        
        # Verify resources
        try:
            self.llm = LLM(
                model=self.model_path,
                tensor_parallel_size=torch.cuda.device_count(), # Utilize all visible GPUs
                gpu_memory_utilization=self.gpu_util,
                max_model_len=16384,
                trust_remote_code=True,
                enforce_eager=False,
                quantization="awq" if "AWQ" in self.model_path else None
            )
        except Exception as e:
            logger.critical(f"VLLM Initialization Failed: {e}")
            raise e
            
        self.tokenizer = self.llm.get_tokenizer()
        self.config_manager = ConfigManager([config_dir])
        self.sampling_params = SamplingParams(
            temperature=0.0,
            max_tokens=32768,  # Keep high for long reasoning chains
            stop=[
                "<|eot_id|>", 
                "Question:", 
                "User:", 
                "=== QUESTION ===",
                "\n\nExample",  # Stop if model starts generating examples
                "\n\nQuestion:",  # Stop if model starts new question
                "\nBased on the analysis",  # Common verbose pattern
                "\nIn summary",  # Common verbose pattern
                "\nThe answer is",  # Common verbose pattern
            ]
        )
        
        # Result Dir Setup
        self.res_dir = os.path.join(Config.RESULT_DIR, self.model_name.replace("/", "_"))
        os.makedirs(self.res_dir, exist_ok=True)

    def prepare_prompt(self, question: str, answer_type: str, configs: str) -> str:
        # Prompt Template - Direct and Clear
        system_msg = """You are an expert Network Engineer analyzing network configurations.

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
   ❌ "The answer is..."
   ❌ "Based on the analysis..."
   ❌ "We need to..."
   ❌ "Looking at the configuration..."
   ❌ Any explanatory sentences
   ❌ Multiple lines or paragraphs
   
4. If NOT_CONFIGURED or information missing:
   - text: null
   - numeric: 0
   - set: []
   - map: {}
   - boolean: false

REMEMBER: After </think>, output ONLY the answer value on ONE line. Nothing else."""

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
        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg}
        ]
        
        try:
            return self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        except:
            return f"{system_msg}\n\n{user_msg}"

    def run(self, csv_path: str, limit: int = None):
        logger.info(f"Loading dataset from {csv_path}")
        if not os.path.exists(csv_path):
            logger.error("Dataset not found.")
            return

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            data = list(reader)
        
        if limit: data = data[:limit]
        
        logger.info("Generating prompts...")
        # Pre-load Configs once
        hostnames = list(self.config_manager._cache.keys())
        configs_content = self.config_manager.get_configs(hostnames)
        
        prompts = []
        for row in data:
            p = self.prepare_prompt(row['question'], row['answer_type'], configs_content)
            prompts.append(p)
            
        logger.info(f"Starting batch generation for {len(prompts)} samples...")
        start_time = time.time()
        
        outputs = self.llm.generate(prompts, self.sampling_params)
        
        duration = time.time() - start_time
        logger.info(f"Inference Time: {duration:.2f}s | Throughput: {len(prompts)/duration:.1f} req/s")
        
        # Collect Results (RAW + Cleaned prediction)
        results = []
        for i, output in enumerate(outputs):
            row = data[i]
            raw_pred = output.outputs[0].text
            
            # Extract clean answer from raw output
            cleaned_pred = extract_answer_from_raw(raw_pred, row['answer_type'])
            
            res_entry = {
                "question_id": row.get('question_id', str(i)),
                "question": row['question'],
                "gold": row['answer'],
                "raw_pred": raw_pred,  # Raw prediction (for debugging)
                "pred": cleaned_pred,  # Cleaned prediction (for scoring)
                "level": row.get('level', 'L1'),
                "category": row.get('category', 'General'),
                "answer_type": row['answer_type'],
                "answer_status": row.get('answer_status', 'OK')
            }
            results.append(res_entry)
        
        # Save RAW JSON (no stats - use reanalyze_results.py for scoring)
        output_file = os.path.join(self.res_dir, f"results_raw_{self.timestamp}.json")
        final_output = {
            "meta": {
                "model": self.model_name,
                "date": str(datetime.datetime.now()),
                "duration": duration,
                "dataset": os.path.basename(csv_path),
                "total_samples": len(results)
            },
            "results": results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Inference Complete. Raw results saved to {output_file}")
        logger.info(f"Run 'python reanalyze_results.py \"{output_file}\"' to score and visualize.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=Config.DEFAULT_DATASET_PATH)
    parser.add_argument("--config_dir", default=Config.DEFAULT_CONFIG_DIR)
    parser.add_argument("--model", nargs='+', required=True, help="하나 이상의 모델 지정 (예: --model Qwen3-8B Mistral3-8B)")
    parser.add_argument("--gpu_util", type=float, default=0.9)
    parser.add_argument("--sample", type=int, default=None)
    args = parser.parse_args()
    
    # 여러 모델 순차 실행
    total_models = len(args.model)
    for idx, model_key in enumerate(args.model, 1):
        print(f"\n{'='*60}")
        print(f"[{idx}/{total_models}] Starting evaluation for: {model_key}")
        print(f"{'='*60}\n")
        
        try:
            evaluator = VLLMEvaluator(model_key, args.config_dir, args.gpu_util)
            evaluator.run(args.dataset, args.sample)
            
            # 메모리 정리 (중요!)
            del evaluator
            torch.cuda.empty_cache()
            print(f"[{idx}/{total_models}] Completed: {model_key} - GPU memory cleared.\n")
            
        except Exception as e:
            print(f"[{idx}/{total_models}] ERROR with model {model_key}: {e}")
            torch.cuda.empty_cache()  # 에러 발생해도 메모리 정리
            continue  # 하나 실패해도 다음 모델 계속 진행
    
    print(f"\n{'='*60}")
    print(f"All {total_models} model(s) evaluation completed.")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
