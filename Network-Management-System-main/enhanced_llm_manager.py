"""
통합 LLM 관리 시스템
다양한 LLM 프로바이더를 통합적으로 관리하고 벤치마크 실험을 지원합니다.
"""

import os
import json
import time
import asyncio
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod

import openai
import anthropic
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch


@dataclass
class LLMResponse:
    """LLM 응답 표준 형식"""
    content: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency: float
    cost: float = 0.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseLLMProvider(ABC):
    """LLM 프로바이더 기본 클래스"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_name = config.get('model_name')
        self.max_tokens = config.get('max_tokens', 4096)
        self.temperature = config.get('temperature', 0.0)
        
    @abstractmethod
    async def generate(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        """텍스트 생성"""
        pass
    
    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """토큰 수 계산"""
        pass


class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT 모델 프로바이더"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # 테스트 모드 체크
        self.test_mode = config.get('test_mode', False) or os.getenv('LLM_TEST_MODE', '').lower() == 'true'
        
        if not self.test_mode:
            api_key = config.get('api_key') or os.getenv('OPENAI_API_KEY')
            if not api_key:
                print(f"경고: OpenAI API 키가 설정되지 않았습니다. 테스트 모드로 전환합니다.")
                self.test_mode = True
            else:
                self.client = openai.AsyncOpenAI(api_key=api_key)
        
        # 모델별 가격 정보 (입력/출력 토큰당 달러)
        self.pricing = {
            'gpt-4': {'input': 0.00003, 'output': 0.00006},
            'gpt-4-turbo': {'input': 0.00001, 'output': 0.00003},
            'gpt-3.5-turbo': {'input': 0.0000005, 'output': 0.0000015},
        }
    
    async def generate(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        start_time = time.time()
        
        # 테스트 모드인 경우 모킹된 응답 반환
        if self.test_mode:
            await asyncio.sleep(0.1)  # 실제 API 호출 시뮬레이션
            latency = time.time() - start_time
            
            # 모킹된 응답 생성
            mock_content = f"[테스트 모드] {self.model_name}의 모킹된 응답입니다. 질문: {prompt[:100]}..."
            
            return LLMResponse(
                content=mock_content,
                input_tokens=len(prompt.split()) + (len(system_prompt.split()) if system_prompt else 0),
                output_tokens=len(mock_content.split()),
                latency=latency,
                cost=0.001,  # 테스트용 고정 비용
                metadata={'test_mode': True, 'model': self.model_name}
            )
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            latency = time.time() - start_time
            usage = response.usage
            content = response.choices[0].message.content
            
            # 비용 계산
            model_key = self.model_name.replace('gpt-4-0125-preview', 'gpt-4-turbo')
            pricing = self.pricing.get(model_key, {'input': 0, 'output': 0})
            cost = (usage.prompt_tokens * pricing['input'] + 
                   usage.completion_tokens * pricing['output'])
            
            return LLMResponse(
                content=content,
                model=self.model_name,
                provider='openai',
                input_tokens=usage.prompt_tokens,
                output_tokens=usage.completion_tokens,
                latency=latency,
                cost=cost,
                metadata={'finish_reason': response.choices[0].finish_reason}
            )
            
        except Exception as e:
            raise Exception(f"OpenAI API 오류: {str(e)}")
    
    def count_tokens(self, text: str) -> int:
        """OpenAI tiktoken을 사용한 토큰 수 계산"""
        try:
            import tiktoken
            encoding = tiktoken.encoding_for_model(self.model_name)
            return len(encoding.encode(text))
        except:
            # 대략적인 추정 (1 토큰 ≈ 4 글자)
            return len(text) // 4


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude 모델 프로바이더"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # 테스트 모드 체크
        self.test_mode = config.get('test_mode', False) or os.getenv('LLM_TEST_MODE', '').lower() == 'true'
        
        if not self.test_mode:
            api_key = config.get('api_key') or os.getenv('ANTHROPIC_API_KEY')
            if not api_key:
                print(f"경고: Anthropic API 키가 설정되지 않았습니다. 테스트 모드로 전환합니다.")
                self.test_mode = True
            else:
                self.client = anthropic.AsyncAnthropic(api_key=api_key)
        
        self.pricing = {
            'claude-3-opus-20240229': {'input': 0.000015, 'output': 0.000075},
            'claude-3-sonnet-20240229': {'input': 0.000003, 'output': 0.000015},
            'claude-3-haiku-20240307': {'input': 0.00000025, 'output': 0.00000125},
        }
    
    async def generate(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        start_time = time.time()
        
        # 테스트 모드인 경우 모킹된 응답 반환
        if self.test_mode:
            await asyncio.sleep(0.1)  # 실제 API 호출 시뮬레이션
            latency = time.time() - start_time
            
            # 모킹된 응답 생성
            mock_content = f"[테스트 모드] {self.model_name}의 모킹된 응답입니다. 질문: {prompt[:100]}..."
            
            return LLMResponse(
                content=mock_content,
                input_tokens=len(prompt.split()) + (len(system_prompt.split()) if system_prompt else 0),
                output_tokens=len(mock_content.split()),
                latency=latency,
                cost=0.001,  # 테스트용 고정 비용
                metadata={'test_mode': True, 'model': self.model_name}
            )
        
        try:
            response = await self.client.messages.create(
                model=self.model_name,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt or "",
                messages=[{"role": "user", "content": prompt}]
            )
            
            latency = time.time() - start_time
            content = response.content[0].text
            
            # 비용 계산
            pricing = self.pricing.get(self.model_name, {'input': 0, 'output': 0})
            cost = (response.usage.input_tokens * pricing['input'] + 
                   response.usage.output_tokens * pricing['output'])
            
            return LLMResponse(
                content=content,
                model=self.model_name,
                provider='anthropic',
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                latency=latency,
                cost=cost,
                metadata={'stop_reason': response.stop_reason}
            )
            
        except Exception as e:
            raise Exception(f"Anthropic API 오류: {str(e)}")
    
    def count_tokens(self, text: str) -> int:
        # Claude의 토큰 계산 (대략적 추정)
        return len(text) // 4


class HuggingFaceProvider(BaseLLMProvider):
    """Hugging Face Transformers 모델 프로바이더"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.device = config.get('device', 'cuda' if torch.cuda.is_available() else 'cpu')
        
        # 모델과 토크나이저 로드
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            torch_dtype=torch.float16 if self.device == 'cuda' else torch.float32,
            device_map="auto" if self.device == 'cuda' else None
        )
        
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
    
    async def generate(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        start_time = time.time()
        
        # 프롬프트 형식화
        if system_prompt:
            full_prompt = f"System: {system_prompt}\n\nUser: {prompt}\n\nAssistant:"
        else:
            full_prompt = f"User: {prompt}\n\nAssistant:"
        
        try:
            # 토큰화
            inputs = self.tokenizer(full_prompt, return_tensors="pt")
            if self.device == 'cuda':
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            input_length = inputs['input_ids'].shape[1]
            
            # 생성
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs['input_ids'],
                    max_new_tokens=self.max_tokens,
                    temperature=self.temperature,
                    do_sample=self.temperature > 0,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id
                )
            
            # 응답 추출
            generated_tokens = outputs[0][input_length:]
            content = self.tokenizer.decode(generated_tokens, skip_special_tokens=True)
            
            latency = time.time() - start_time
            output_tokens = len(generated_tokens)
            
            return LLMResponse(
                content=content.strip(),
                model=self.model_name,
                provider='huggingface',
                input_tokens=input_length,
                output_tokens=output_tokens,
                latency=latency,
                cost=0.0,  # 로컬 모델은 API 비용 없음
                metadata={'device': self.device}
            )
            
        except Exception as e:
            raise Exception(f"HuggingFace 모델 오류: {str(e)}")
    
    def count_tokens(self, text: str) -> int:
        return len(self.tokenizer.encode(text))


class OllamaProvider(BaseLLMProvider):
    """Ollama 로컬 모델 프로바이더"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get('base_url', 'http://localhost:11434')
        
    async def generate(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        import aiohttp
        start_time = time.time()
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                ) as response:
                    result = await response.json()
                    
            latency = time.time() - start_time
            content = result.get('response', '')
            
            return LLMResponse(
                content=content,
                model=self.model_name,
                provider='ollama',
                input_tokens=self.count_tokens(prompt),
                output_tokens=self.count_tokens(content),
                latency=latency,
                cost=0.0
            )
            
        except Exception as e:
            raise Exception(f"Ollama API 오류: {str(e)}")
    
    def count_tokens(self, text: str) -> int:
        return len(text) // 4  # 대략적 추정


class LLMManager:
    """통합 LLM 관리자"""
    
    def __init__(self, config_path: str = "llm_configs.json"):
        self.providers = {}
        self.load_configs(config_path)
    
    def load_configs(self, config_path: str):
        """설정 파일에서 LLM 구성 로드"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                configs = json.load(f)
            
            for model_id, config in configs.items():
                provider_type = config.get('provider')
                
                if provider_type == 'openai':
                    self.providers[model_id] = OpenAIProvider(config)
                elif provider_type == 'anthropic':
                    self.providers[model_id] = AnthropicProvider(config)
                elif provider_type == 'huggingface':
                    self.providers[model_id] = HuggingFaceProvider(config)
                elif provider_type == 'ollama':
                    self.providers[model_id] = OllamaProvider(config)
                else:
                    print(f"지원하지 않는 프로바이더: {provider_type}")
                    
        except FileNotFoundError:
            print(f"설정 파일을 찾을 수 없습니다: {config_path}")
            self.create_sample_config(config_path)
        except json.JSONDecodeError:
            print(f"설정 파일 형식 오류: {config_path}")
    
    def create_sample_config(self, config_path: str):
        """샘플 설정 파일 생성"""
        sample_config = {
            "gpt-4": {
                "provider": "openai",
                "model_name": "gpt-4",
                "max_tokens": 4096,
                "temperature": 0.0,
                "api_key": "your_openai_key_here"
            },
            "claude-3-sonnet": {
                "provider": "anthropic",
                "model_name": "claude-3-sonnet-20240229",
                "max_tokens": 4096,
                "temperature": 0.0,
                "api_key": "your_anthropic_key_here"
            },
            "llama-2-7b": {
                "provider": "huggingface",
                "model_name": "meta-llama/Llama-2-7b-chat-hf",
                "max_tokens": 2048,
                "temperature": 0.0,
                "device": "cuda"
            },
            "qwen-7b": {
                "provider": "ollama",
                "model_name": "qwen:7b",
                "base_url": "http://localhost:11434",
                "max_tokens": 2048,
                "temperature": 0.0
            }
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2, ensure_ascii=False)
        
        print(f"샘플 설정 파일 생성됨: {config_path}")
    
    async def generate(
        self, 
        model_id: str, 
        prompt: str, 
        system_prompt: str = None
    ) -> LLMResponse:
        """지정된 모델로 텍스트 생성"""
        if model_id not in self.providers:
            raise ValueError(f"등록되지 않은 모델: {model_id}")
        
        provider = self.providers[model_id]
        return await provider.generate(prompt, system_prompt)
    
    def get_available_models(self) -> List[str]:
        """사용 가능한 모델 목록 반환"""
        return list(self.providers.keys())
    
    def get_model_info(self, model_id: str) -> Dict[str, Any]:
        """모델 정보 반환"""
        if model_id not in self.providers:
            return {}
        
        provider = self.providers[model_id]
        return {
            'model_name': provider.model_name,
            'provider': provider.__class__.__name__,
            'max_tokens': provider.max_tokens,
            'temperature': provider.temperature
        }


# 사용 예시
async def main():
    """LLM Manager 사용 예시"""
    # LLM 관리자 초기화
    llm_manager = LLMManager()
    
    # 사용 가능한 모델 확인
    models = llm_manager.get_available_models()
    print(f"사용 가능한 모델: {models}")
    
    # 네트워크 관련 질문
    question = "BGP 피어링 설정에서 AS 번호의 역할은 무엇인가요?"
    system_prompt = """당신은 네트워크 엔지니어링 전문가입니다. 
    정확하고 기술적으로 상세한 답변을 제공해주세요."""
    
    # 여러 모델로 동시 실행
    tasks = []
    for model_id in models[:2]:  # 처음 2개 모델만 테스트
        task = llm_manager.generate(model_id, question, system_prompt)
        tasks.append((model_id, task))
    
    # 결과 수집
    for model_id, task in tasks:
        try:
            response = await task
            print(f"\n=== {model_id} 응답 ===")
            print(f"내용: {response.content[:200]}...")
            print(f"토큰: {response.input_tokens}/{response.output_tokens}")
            print(f"지연시간: {response.latency:.2f}초")
            print(f"비용: ${response.cost:.6f}")
        except Exception as e:
            print(f"{model_id} 오류: {e}")


if __name__ == "__main__":
    asyncio.run(main())
