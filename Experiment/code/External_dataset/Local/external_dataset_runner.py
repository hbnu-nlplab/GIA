#!/usr/bin/env python3
"""
External Dataset Runner
=======================
공통 실행기: 모델 로딩, 배치 처리, 결과 저장, 로깅

Usage:
    python external_dataset_runner.py --dataset teleqna --model Mistral3-8B
    python external_dataset_runner.py --dataset all --model all
    python external_dataset_runner.py --debug
"""

import os
import sys
import json
import yaml
import logging
import datetime
import argparse
import gc
import time
import warnings
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import torch

# Suppress warnings
warnings.filterwarnings("ignore", message=".*apply_chat_template.*")
warnings.filterwarnings("ignore", message=".*tokenize=False.*")
warnings.filterwarnings("ignore", category=UserWarning, module="transformers")

# === 경로 설정 ===
BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "code"))
from External_dataset.Local import get_dataset, DATASET_REGISTRY
CONFIG_DIR = PROJECT_ROOT / "configs"


# === 설정 로드 ===
def load_config(name: str) -> dict:
    """YAML 설정 파일 로드"""
    config_path = CONFIG_DIR / f"{name}.yaml"
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@dataclass
class RunConfig:
    """실행 설정"""
    model_name: str
    model_path: str
    dataset_name: str
    dataset_path: str
    result_dir: Path
    context_length: int
    gpu_memory_utilization: float = 0.85
    tensor_parallel_size: int = 1
    debug: bool = False
    

# === 로거 설정 ===
def setup_logger(log_dir: Path, prefix: str = "runner") -> logging.Logger:
    """로거 초기화"""
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{prefix}_{timestamp}.log"
    
    logger = logging.getLogger("ExternalDatasetRunner")
    logger.setLevel(logging.INFO)
    logger.handlers = []
    
    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)
    
    # Console handler
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(sh)
    
    return logger


# === HuggingFace 인증 ===
def authenticate_hf():
    """HuggingFace 로그인"""
    try:
        from huggingface_hub import login
        hf_token = os.getenv("HF_TOKEN")
        if hf_token:
            login(token=hf_token)
            return True
    except Exception as e:
        print(f"⚠️ HF authentication failed: {e}")
    return False


# === vLLM 실행기 ===
class VLLMRunner:
    """vLLM 기반 추론 실행기"""
    
    def __init__(self, config: RunConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.llm = None
        self.tokenizer = None
        
    def load_model(self):
        """모델 로드"""
        from vllm import LLM
        
        self.logger.info(f"⏳ Loading model: {self.config.model_name}")
        self.logger.info(f"   Path: {self.config.model_path}")
        
        self.llm = LLM(
            model=self.config.model_path,
            dtype="auto",
            trust_remote_code=True,
            gpu_memory_utilization=self.config.gpu_memory_utilization,
            max_model_len=min(self.config.context_length, 16384),  # vLLM 제한
            tensor_parallel_size=self.config.tensor_parallel_size,
        )
        self.tokenizer = self.llm.get_tokenizer()
        self.logger.info(f"   ✓ Model loaded successfully")
        
    def run_inference(self, dataset) -> List[Dict[str, Any]]:
        """추론 실행"""
        from vllm import SamplingParams
        
        items = dataset.items
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"📦 Dataset: {dataset.name.upper()}")
        self.logger.info(f"   Total items: {len(items)}")
        self.logger.info(f"   Primary Metric: {dataset.primary_metric}")
        self.logger.info(f"{'='*80}\n")
        
        # 샘플링 파라미터 (데이터셋별 설정 사용)
        sampling_config = dataset.get_sampling_params()
        
        # Guided Generation (Structured Output) 설정
        guided_params = dataset.get_guided_params()
        if guided_params:
            # vLLM guided decoding 사용
            from vllm import GuidedDecodingParams
            sampling = SamplingParams(
                **sampling_config,
                guided_decoding=GuidedDecodingParams(**guided_params)
            )
            self.logger.info(f"   🔧 Structured Output: ENABLED (JSON schema)")
        else:
            sampling = SamplingParams(**sampling_config)
        
        self.logger.info(f"   Sampling: temp={sampling_config['temperature']}, "
                        f"max_tokens={sampling_config['max_tokens']}, "
                        f"stop={sampling_config['stop']}")
        
        # 프롬프트 빌드
        self.logger.info(f"⏳ Building prompts...")
        prompts = []
        valid_items = []
        truncated_count = 0
        
        max_prompt_tokens = self.config.context_length - sampling_config['max_tokens'] - 100
        
        for item in items:
            messages = dataset.build_messages(item)
            prompt_str = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            
            # 토큰 수 체크 (스킵 대신 트렁케이션)
            prompt_tokens = self.tokenizer.encode(prompt_str)
            if len(prompt_tokens) > max_prompt_tokens:
                # 컨텍스트 트렁케이션
                truncated_context = dataset.truncate_context(
                    item.context, 
                    max_chars=int(len(item.context) * (max_prompt_tokens / len(prompt_tokens)))
                )
                item.context = truncated_context
                messages = dataset.build_messages(item)
                prompt_str = self.tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
                truncated_count += 1
            
            prompts.append(prompt_str)
            valid_items.append(item)
        
        self.logger.info(f"   ✓ Built {len(prompts)} prompts (truncated: {truncated_count})")
        
        # 추론 실행
        self.logger.info(f"🔄 Running inference...")
        outputs = self.llm.generate(prompts, sampling)
        self.logger.info(f"   ✓ Inference completed")
        
        # 결과 수집
        results = []
        for i, (item, output) in enumerate(zip(valid_items, outputs)):
            raw_answer = output.outputs[0].text.strip()
            parsed_answer = dataset.parse_response(raw_answer)
            
            results.append({
                "id": item.id,
                "question": item.question,
                "context": item.context,
                "gold": item.gold,
                "model_answer_raw": raw_answer,
                "model_answer_parsed": parsed_answer,
                "metadata": item.metadata,
            })
        
        return results
    
    def cleanup(self):
        """GPU 메모리 정리"""
        self.logger.info(f"🧹 Cleaning up GPU memory...")
        if self.llm:
            try:
                from vllm.distributed.parallel_state import destroy_model_parallel
                destroy_model_parallel()
            except:
                pass
            del self.llm
            self.llm = None
        if self.tokenizer:
            del self.tokenizer
            self.tokenizer = None
        
        for _ in range(3):
            gc.collect()
        
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
        
        time.sleep(2)
        self.logger.info(f"   ✓ Cleanup completed")


# === 결과 저장 ===
def save_results(results: List[Dict], dataset, config: RunConfig, logger: logging.Logger):
    """
    결과 저장
    구조: Result/external_dataset/{dataset}/{model}/run.json
    """
    # 디렉토리 생성
    save_dir = config.result_dir / dataset.name / config.model_name
    save_dir.mkdir(parents=True, exist_ok=True)
    
    # 타임스탬프
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 메트릭 계산 (데이터셋별 전체 메트릭)
    predictions = [r["model_answer_parsed"] for r in results]
    references = [r["gold"] for r in results]
    metrics = dataset.compute_all_metrics(predictions, references)
    
    # 평가된 문항 ID 리스트 (동일 문항 비교용)
    evaluated_ids = [r["id"] for r in results]
    
    # 결과 파일 저장
    output = {
        "meta": {
            "model": config.model_name,
            "model_path": config.model_path,
            "dataset": dataset.name,
            "timestamp": timestamp,
            "total_items": len(results),
            "primary_metric": dataset.primary_metric,
        },
        "metrics": metrics,
        "evaluated_ids": evaluated_ids,
        "data": results,
    }
    
    # 최신 결과 (덮어쓰기)
    latest_path = save_dir / "latest.json"
    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    # 타임스탬프 백업
    backup_path = save_dir / f"run_{timestamp}.json"
    with open(backup_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    logger.info(f"💾 Results saved:")
    logger.info(f"   Latest: {latest_path}")
    logger.info(f"   Backup: {backup_path}")
    
    # 메트릭 출력
    logger.info(f"\n📊 Metrics ({dataset.primary_metric} is primary):")
    for k, v in metrics.items():
        if isinstance(v, float):
            logger.info(f"   {k:12}: {v:6.2f}%")
        else:
            logger.info(f"   {k:12}: {v}")
    
    return metrics


# === 메인 실행 ===
def main():
    parser = argparse.ArgumentParser(description="External Dataset Evaluation Runner")
    parser.add_argument("--dataset", type=str, default="all",
                       help="Dataset name (teleqna/telequad/netbench/all)")
    parser.add_argument("--model", type=str, default="all",
                       help="Model name (from models.yaml) or 'all'")
    parser.add_argument("--debug", action="store_true",
                       help="Debug mode (mock responses, no GPU)")
    parser.add_argument("--limit", type=int, default=None,
                       help="Limit number of items per dataset (for testing)")
    args = parser.parse_args()
    
    # 설정 로드
    exp_config = load_config("exp")
    models_config = load_config("models")
    
    # 경로 설정
    result_dir = PROJECT_ROOT / exp_config["paths"]["result_dir"]
    log_dir = PROJECT_ROOT / exp_config["paths"]["log_dir"]
    
    # 로거 초기화
    logger = setup_logger(log_dir)
    logger.info("="*80)
    logger.info("🚀 External Dataset Evaluation Runner")
    logger.info("="*80)
    
    # HuggingFace 인증
    authenticate_hf()
    
    # 데이터셋 선택
    if args.dataset == "all":
        dataset_names = [k for k, v in exp_config["datasets"].items() if v.get("enabled", True)]
    else:
        dataset_names = [args.dataset]
    
    # 모델 선택
    if args.model == "all":
        models_to_run = models_config.get("vllm_models", {})
    else:
        if args.model in models_config.get("vllm_models", {}):
            models_to_run = {args.model: models_config["vllm_models"][args.model]}
        else:
            logger.error(f"Model '{args.model}' not found in models.yaml")
            return
    
    logger.info(f"\n📋 Datasets: {', '.join(dataset_names)}")
    logger.info(f"📋 Models: {', '.join(models_to_run.keys())}")
    
    # 모델별 실행
    for model_name, model_info in models_to_run.items():
        logger.info(f"\n{'='*80}")
        logger.info(f"🤖 Model: {model_name}")
        logger.info(f"{'='*80}")
        
        runner = None
        
        try:
            # 데이터셋별 실행
            for ds_name in dataset_names:
                ds_config = exp_config["datasets"].get(ds_name, {})
                if not ds_config.get("enabled", True):
                    logger.info(f"⏭️ Skipping disabled dataset: {ds_name}")
                    continue
                
                # 이미 완료된 경우 스킵
                result_file = result_dir / ds_name / model_name / "latest.json"
                if result_file.exists() and not args.debug:
                    logger.info(f"⏭️ Already completed: {ds_name}/{model_name}")
                    continue
                
                # 데이터셋 로드
                dataset = get_dataset(ds_name)
                dataset_path = PROJECT_ROOT / ds_config["path"]
                
                if not dataset_path.exists():
                    logger.warning(f"⚠️ Dataset file not found: {dataset_path}")
                    continue
                
                dataset.load(str(dataset_path))
                
                if args.limit:
                    dataset._items = dataset._items[:args.limit]
                
                logger.info(f"\n📂 Loaded {len(dataset)} items from {ds_name}")
                
                # 모델 로드 (첫 데이터셋에서만)
                if runner is None and not args.debug:
                    config = RunConfig(
                        model_name=model_name,
                        model_path=model_info["path"],
                        dataset_name=ds_name,
                        dataset_path=str(dataset_path),
                        result_dir=result_dir,
                        context_length=model_info.get("context_length", 16384),
                        gpu_memory_utilization=model_info.get("gpu_memory_utilization", 0.85),
                        tensor_parallel_size=model_info.get("tensor_parallel_size", 1),
                        debug=args.debug,
                    )
                    runner = VLLMRunner(config, logger)
                    runner.load_model()
                
                # 추론 실행
                if args.debug:
                    # Mock 결과
                    results = [{
                        "id": item.id,
                        "question": item.question,
                        "context": item.context[:100],
                        "gold": item.gold,
                        "model_answer_raw": "option 1: test" if ds_name == "teleqna" else "test answer",
                        "model_answer_parsed": "option 1" if ds_name == "teleqna" else "test answer",
                        "metadata": item.metadata,
                    } for item in dataset.items]
                else:
                    runner.config.dataset_name = ds_name
                    results = runner.run_inference(dataset)
                
                # 결과 저장
                save_config = RunConfig(
                    model_name=model_name,
                    model_path=model_info["path"],
                    dataset_name=ds_name,
                    dataset_path=str(dataset_path),
                    result_dir=result_dir,
                    context_length=model_info.get("context_length", 16384),
                )
                save_results(results, dataset, save_config, logger)
        
        except Exception as e:
            logger.error(f"❌ Error processing {model_name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        finally:
            # 클린업
            if runner:
                runner.cleanup()
                runner = None
    
    logger.info(f"\n{'='*80}")
    logger.info("🎉 All evaluations completed!")
    logger.info(f"{'='*80}")


if __name__ == "__main__":
    main()
