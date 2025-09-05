"""
LLM 모델 관리자
다양한 LLM 모델들을 통합 관리하고 성능을 평가하는 시스템
"""

import os
import json
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod
import logging

# LLM 클라이언트들
from openai import OpenAI
import anthropic
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

@dataclass
class LLMConfig:
    """LLM 설정 클래스"""
    name: str
    model_id: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_tokens: int = 2000
    temperature: float = 0.1
    timeout: int = 30
    local: bool = False
    device: str = "cuda"

class BaseLLM(ABC):
    """LLM 기본 인터페이스"""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.name = config.name
        
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """텍스트 생성"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """모델 사용 가능 여부 확인"""
        pass

class OpenAILLM(BaseLLM):
    """OpenAI 모델 래퍼"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.client = OpenAI(
            api_key=config.api_key or os.getenv("OPENAI_API_KEY"),
            base_url=config.base_url
        )
    
    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.config.model_id,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                temperature=kwargs.get("temperature", self.config.temperature),
                timeout=self.config.timeout
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"OpenAI API error: {e}")
            return ""
    
    def is_available(self) -> bool:
        try:
            self.client.models.list()
            return True
        except:
            return False

class AnthropicLLM(BaseLLM):
    """Anthropic Claude 모델 래퍼"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.client = anthropic.Anthropic(
            api_key=config.api_key or os.getenv("ANTHROPIC_API_KEY")
        )
    
    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.client.messages.create(
                model=self.config.model_id,
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                temperature=kwargs.get("temperature", self.config.temperature),
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logging.error(f"Anthropic API error: {e}")
            return ""
    
    def is_available(self) -> bool:
        try:
            # Claude 가용성 체크 (간단한 요청)
            self.client.messages.create(
                model=self.config.model_id,
                max_tokens=10,
                messages=[{"role": "user", "content": "Hi"}]
            )
            return True
        except:
            return False

class HuggingFaceLLM(BaseLLM):
    """HuggingFace 로컬 모델 래퍼"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.tokenizer = None
        self.model = None
        self._load_model()
    
    def _load_model(self):
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_id)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.config.model_id,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
        except Exception as e:
            logging.error(f"Failed to load model {self.config.model_id}: {e}")
    
    def generate(self, prompt: str, **kwargs) -> str:
        if not self.model or not self.tokenizer:
            return ""
        
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True)
            
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_new_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                    temperature=kwargs.get("temperature", self.config.temperature),
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # 입력 제외하고 생성된 부분만 디코딩
            generated_ids = outputs[0][inputs.input_ids.shape[1]:]
            return self.tokenizer.decode(generated_ids, skip_special_tokens=True)
        
        except Exception as e:
            logging.error(f"Generation error: {e}")
            return ""
    
    def is_available(self) -> bool:
        return self.model is not None and self.tokenizer is not None

class LLMManager:
    """LLM 모델 통합 관리자"""
    
    def __init__(self, config_file: str = "llm_configs.json"):
        self.models: Dict[str, BaseLLM] = {}
        self.config_file = config_file
        self.load_configs()
    
    def load_configs(self):
        """설정 파일에서 모델 설정 로드"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                configs = json.load(f)
                
            for config_data in configs:
                config = LLMConfig(**config_data)
                self.add_model(config)
        else:
            # 기본 설정 생성
            self.create_default_configs()
    
    def create_default_configs(self):
        """기본 모델 설정들 생성"""
        default_configs = [
            {
                "name": "gpt-4o-mini",
                "model_id": "gpt-4o-mini",
                "api_key": None,
                "max_tokens": 2000,
                "temperature": 0.1
            },
            {
                "name": "claude-3-haiku",
                "model_id": "claude-3-haiku-20240307",
                "api_key": None,
                "max_tokens": 2000,
                "temperature": 0.1
            },
            {
                "name": "llama-3-8b",
                "model_id": "meta-llama/Meta-Llama-3-8B-Instruct",
                "local": True,
                "max_tokens": 2000,
                "temperature": 0.1
            },
            {
                "name": "qwen-2.5-7b",
                "model_id": "Qwen/Qwen2.5-7B-Instruct",
                "local": True,
                "max_tokens": 2000,
                "temperature": 0.1
            }
        ]
        
        with open(self.config_file, 'w') as f:
            json.dump(default_configs, f, indent=2)
        
        # 기본 설정으로 모델 로드
        for config_data in default_configs:
            config = LLMConfig(**config_data)
            self.add_model(config)
    
    def add_model(self, config: LLMConfig):
        """새 모델 추가"""
        try:
            if config.local:
                model = HuggingFaceLLM(config)
            elif "gpt" in config.model_id.lower():
                model = OpenAILLM(config)
            elif "claude" in config.model_id.lower():
                model = AnthropicLLM(config)
            else:
                # 기본적으로 HuggingFace로 시도
                model = HuggingFaceLLM(config)
            
            self.models[config.name] = model
            logging.info(f"Added model: {config.name}")
            
        except Exception as e:
            logging.error(f"Failed to add model {config.name}: {e}")
    
    def get_model(self, name: str) -> Optional[BaseLLM]:
        """모델 가져오기"""
        return self.models.get(name)
    
    def list_models(self) -> List[str]:
        """사용 가능한 모델 목록"""
        return list(self.models.keys())
    
    def list_available_models(self) -> List[str]:
        """현재 사용 가능한 모델들만 필터링"""
        available = []
        for name, model in self.models.items():
            if model.is_available():
                available.append(name)
        return available
    
    def generate_batch(self, prompts: List[str], model_names: List[str] = None) -> Dict[str, List[str]]:
        """여러 모델로 배치 생성"""
        if model_names is None:
            model_names = self.list_available_models()
        
        results = {}
        for model_name in model_names:
            model = self.get_model(model_name)
            if model and model.is_available():
                model_results = []
                for prompt in prompts:
                    try:
                        start_time = time.time()
                        response = model.generate(prompt)
                        end_time = time.time()
                        
                        model_results.append({
                            "response": response,
                            "time": end_time - start_time,
                            "success": True
                        })
                    except Exception as e:
                        model_results.append({
                            "response": "",
                            "time": 0,
                            "success": False,
                            "error": str(e)
                        })
                
                results[model_name] = model_results
        
        return results
    
    def benchmark_models(self, test_prompts: List[str]) -> Dict[str, Dict[str, float]]:
        """모델들 성능 벤치마크"""
        results = {}
        
        for model_name in self.list_available_models():
            model = self.get_model(model_name)
            if not model:
                continue
            
            total_time = 0
            success_count = 0
            
            for prompt in test_prompts:
                try:
                    start_time = time.time()
                    response = model.generate(prompt)
                    end_time = time.time()
                    
                    if response.strip():  # 비어있지 않은 응답
                        success_count += 1
                        total_time += (end_time - start_time)
                
                except Exception as e:
                    logging.warning(f"Benchmark error for {model_name}: {e}")
            
            results[model_name] = {
                "success_rate": success_count / len(test_prompts),
                "avg_time": total_time / max(success_count, 1),
                "total_time": total_time
            }
        
        return results

# 사용 예시
if __name__ == "__main__":
    # 로깅 설정
    logging.basicConfig(level=logging.INFO)
    
    # LLM 매니저 초기화
    manager = LLMManager()
    
    # 사용 가능한 모델 확인
    print("Available models:", manager.list_available_models())
    
    # 테스트 프롬프트
    test_prompt = "What is BGP and how does it work in network routing?"
    
    # 단일 모델 테스트
    gpt_model = manager.get_model("gpt-4o-mini")
    if gpt_model and gpt_model.is_available():
        response = gpt_model.generate(test_prompt)
        print(f"GPT Response: {response[:100]}...")
    
    # 벤치마크 실행
    benchmark_results = manager.benchmark_models([test_prompt])
    print("Benchmark results:", benchmark_results)
