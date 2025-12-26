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
    DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "Data") 
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    RESULT_DIR = os.path.join(BASE_DIR, "results")
    
    # Defaults
    DEFAULT_DATASET_PATH = os.path.join(DATA_DIR, "Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251224_012740.csv").replace("/", os.sep)
    DEFAULT_CONFIG_DIR = os.path.join(DATA_DIR, "Pnetlab/Research_Institute_Internal_DC/configs").replace("/", os.sep)
    
    # Model Dictionary (AWQ optimized)
    MODEL_DICT = {
        "Mistral3-8B": "mistralai/Ministral-3-8B-Instruct-2512",
        "Qwen3-8B": "Qwen/Qwen3-8B",
        "GPT-OSS-20B": "openai/gpt-oss-20b",
        "LLlama-4-Scout-17B": "meta-llama/Llama-4-Scout-17B-16E-Instruct",
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
                max_model_len=8192,
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
            max_tokens=32768,  # INCREASED: was 16384, now 32768 to prevent truncation during <think>
            stop=["<|eot_id|>", "Question:", "User:", "=== QUESTION ==="]
            # NOTE: Do NOT add "</think>" as stop token - it cuts off the answer
        )
        
        # Result Dir Setup
        self.res_dir = os.path.join(Config.RESULT_DIR, self.model_name.replace("/", "_"))
        os.makedirs(self.res_dir, exist_ok=True)

    def prepare_prompt(self, question: str, answer_type: str, configs: str) -> str:
        # Prompt Template logic
        system_msg = """You are an expert Network Engineer. Your task is to analyze network configurations and provide precise answers.

WORKFLOW (CRITICAL):
1. Use <think>...</think> tags to reason about the network structure, device connections, and configurations.
2. Inside <think> tags: Analyze the configuration, trace the connections, identify key information.
3. After closing </think>, IMMEDIATELY provide ONLY the final answer in the exact format requested.
4. Do NOT include any explanation, preamble, or additional text after the answer.

Output Format:
- boolean: true or false
- numeric: Number only (e.g., 5)
- set/list: JSON array ["item1", "item2"]
- map/dict: JSON object {"key": "value"}
- text: Exact value string only

If information is missing or NOT_CONFIGURED:
- boolean: false
- numeric: 0
- set: []
- map: {}
- text: null

CRITICAL: Provide the answer on the FIRST line after </think> with NO other text."""

        user_msg = f"""=== DEVICE CONFIGURATIONS ===
{configs}

=== QUESTION ===
{question}

=== EXPECTED ANSWER TYPE ===
{answer_type}

=== YOUR RESPONSE ===
<think>
[Analyze the network configuration, trace connections, identify the answer]
</think>

[ANSWER ON FIRST LINE - No other text]
"""
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
        
        # Collect Results (RAW only - no preprocessing or scoring)
        results = []
        for i, output in enumerate(outputs):
            row = data[i]
            raw_pred = output.outputs[0].text
            
            res_entry = {
                "question_id": row.get('question_id', str(i)),
                "question": row['question'],
                "gold": row['answer'],
                "raw_pred": raw_pred,  # Raw prediction only
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
    parser.add_argument("--model", required=True)
    parser.add_argument("--gpu_util", type=float, default=0.9)
    parser.add_argument("--sample", type=int, default=None)
    args = parser.parse_args()
    
    evaluator = VLLMEvaluator(args.model, args.config_dir, args.gpu_util)
    evaluator.run(args.dataset, args.sample)

if __name__ == "__main__":
    main()
