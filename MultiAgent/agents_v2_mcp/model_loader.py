"""
model_loader.py
---------------
LLM 모델 로딩 및 관리 모듈.

두 가지 모드를 지원한다:
- USE_LOCAL=False (기본): OpenRouter API를 통해 클라우드 LLM 사용
- USE_LOCAL=True:         로컬 GPU에 HuggingFace 모델을 4-bit 양자화로 로드

에이전트는 'A', 'B' 두 개의 모델 키를 사용한다:
- 'A': 합성·검증 담당 (Synthesizer, Verifier, Supporter)
- 'B': 수집·비판 담당 (Collector, Skeptic)
"""

import gc
import sys
import os
from pathlib import Path
from langchain_openai import ChatOpenAI

# 프로젝트 루트를 sys.path에 추가하여 config 패키지를 임포트 가능하게 함
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
from config.load_env import load_louter

# === 설정: USE_LOCAL=True로 바꾸면 로컬 GPU 모드로 전환 ===
USE_LOCAL = False

if USE_LOCAL:
    # 로컬 모드에서만 필요한 패키지 (GPU 환경에서만 설치되어 있음)
    import torch
    from langchain_huggingface import HuggingFacePipeline
    from transformers import pipeline, BitsAndBytesConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer
    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"  # GPU 메모리 단편화 방지

# 동시에 메모리에 올려둘 수 있는 최대 모델 수 (LRU 제거 기준)
MAX_LOADED_MODELS = 1


class DynamicModelLoader:
    """
    로컬 HuggingFace 모델을 LRU 방식으로 동적 로드/언로드하는 클래스.
    VRAM이 제한된 환경에서 여러 모델을 순차적으로 사용할 때 유용하다.
    """
    def __init__(self, model_map):
        """
        Args:
            model_map (dict): {'A': 'model_id_A', 'B': 'model_id_B'} 형태의 역할-모델 매핑
        """
        self.model_map = model_map
        self.loaded_models = {}   # {model_id: HuggingFacePipeline} 캐시
        self.access_history = []  # LRU 추적용 접근 순서 기록

        # 4-bit 양자화 설정 (VRAM 절약)
        self.bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",             # NF4 양자화 타입
            bnb_4bit_compute_dtype=torch.float16,   # 연산은 float16으로
            bnb_4bit_use_double_quant=True,         # 이중 양자화로 추가 압축
            llm_int8_enable_fp32_cpu_offload=True   # CPU 오프로드 허용
        )

    def load_model(self, role):
        """
        주어진 역할(role)에 해당하는 모델을 로드하고 반환한다.
        이미 로드된 모델은 캐시에서 즉시 반환한다.

        Args:
            role (str): 'A' 또는 'B'
        Returns:
            HuggingFacePipeline: 로드된 모델 파이프라인
        """
        model_id = self.model_map[role]

        # 캐시 히트: 이미 로드된 모델 반환
        if model_id in self.loaded_models:
            return self.loaded_models[model_id]

        print(f"🚀 [Role {role}] Loading Model: {model_id} across ALL GPUs...")

        # GPU 0,1,2에 자동 분산 (GPU 3은 OOM 방지를 위해 제외)
        device_map = "auto"
        max_memory = {
            0: "22GiB",
            1: "22GiB",
            2: "22GiB",
            3: "0GiB",   # GPU 3 사용 안 함
            "cpu": "100GiB"
        }

        # 모델 로드: 4-bit 양자화 + 멀티 GPU 분산
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map=device_map,
            quantization_config=self.bnb_config,
            dtype=torch.float16,
            trust_remote_code=True,
            low_cpu_mem_usage=True   # CPU 메모리 사용 최소화
        )

        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)

        # text-generation 파이프라인 생성
        pipe = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            max_new_tokens=1024,
            temperature=0.01,       # 거의 greedy 디코딩 (재현성 확보)
            return_full_text=False   # 입력 프롬프트 제외하고 생성 부분만 반환
        )

        hf_pipe = HuggingFacePipeline(pipeline=pipe)
        self.loaded_models[model_id] = hf_pipe
        return hf_pipe


class LazyModelProxy:
    """
    모델을 실제 사용 시점까지 로드를 미루는 프록시 클래스.
    invoke() 호출 시점에 DynamicModelLoader.load_model()을 호출하고,
    완료 후 GPU 캐시를 비워 다음 모델을 위한 공간을 확보한다.
    """
    def __init__(self, loader, role):
        self.loader = loader
        self.role = role

    def invoke(self, *args, **kwargs):
        """모델을 로드하고 추론 실행. 완료 후 GPU 메모리 정리."""
        model = self.loader.load_model(self.role)
        try:
            return model.invoke(*args, **kwargs)
        finally:
            gc.collect()
            if USE_LOCAL:
                import torch
                torch.cuda.empty_cache()  # 추론 후 GPU 캐시 해제


# 모듈 수준 전역 모델 딕셔너리 (한 번만 초기화)
_LLM_DICT = {}


def init_models():
    """
    LLM 모델을 초기화하고 전역 딕셔너리에 저장한다.
    두 번 이상 호출해도 한 번만 초기화된다 (싱글톤 패턴).

    Returns:
        dict: {'A': llm_a, 'B': llm_b} 형태의 모델 딕셔너리
    """
    global _LLM_DICT
    if _LLM_DICT:
        return _LLM_DICT  # 이미 초기화된 경우 즉시 반환

    models = {}

    if not USE_LOCAL:
        # 클라우드 모드: OpenRouter API 사용
        print(" [Mode] Using OpenRouter (Cloud)")
        try:
            api_key, base_url, model1, model2 = load_louter()
        except ImportError:
            print("Check config/load_env.py implementation")
            return {}

        common_params = {
            "base_url": base_url,
            "api_key": api_key,
            "temperature": 0,
            "max_tokens": 4096      # thinking 모델(Qwen 등)의 <think> 블록 포함 충분한 공간
        }
        models['A'] = ChatOpenAI(model=model1, **common_params)
        models['B'] = ChatOpenAI(model=model2, **common_params)

    else:
        # 로컬 GPU 모드: HuggingFace 모델 동적 로드
        print("🖥️ [Mode] Using Local Dynamic Loading (GPU)")
        hf_models = {
            'A': "Qwen/Qwen3.5-9B",
            'B': "zai-org/GLM-4.7-Flash"
        }
        loader = DynamicModelLoader(hf_models)
        # LazyModelProxy로 감싸서 실제 사용 시점에 로드
        models = {
            'A': LazyModelProxy(loader, 'A'),
            'B': LazyModelProxy(loader, 'B')
        }

    _LLM_DICT = models
    return models


def get_models():
    """초기화된 모델 딕셔너리를 반환한다. 초기화되지 않은 경우 init_models()를 호출한다."""
    return init_models()
