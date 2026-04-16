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

        # 모델이 이미 양자화된 경우(Mxfp4 등) quantization_config 충돌 방지:
        # from_pretrained를 먼저 config만 로드해서 확인
        from transformers import AutoConfig
        try:
            model_cfg = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
            already_quantized = hasattr(model_cfg, "quantization_config") and model_cfg.quantization_config is not None
        except Exception:
            already_quantized = False

        load_kwargs = dict(
            device_map=device_map,
            max_memory=max_memory,
            trust_remote_code=True,
            low_cpu_mem_usage=True,
        )
        if already_quantized:
            # 사전 양자화 모델: bnb config 없이 로드 (dtype도 모델 기본값 따름)
            print(f"  ℹ️  [{model_id}] Pre-quantized model detected — skipping BitsAndBytesConfig")
        else:
            load_kwargs["quantization_config"] = self.bnb_config
            load_kwargs["torch_dtype"] = torch.float16

        # 모델 로드: 멀티 GPU 분산
        model = AutoModelForCausalLM.from_pretrained(model_id, **load_kwargs)

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

# 토크나이저 캐시 (CPU 전용, 토큰 계산용)
_TOKENIZER_CACHE: dict = {}
_HF_MODEL_MAP = {
    'A': "mistralai/Ministral-3-8B-Instruct-2512",
    'B': "openai/gpt-oss-20b",
}

def provider_config(model_name):
    if model_name == "openai/gpt-oss-20b":
        return {
            "provider": {
                "only": ["deepinfra"]
            }
        }
    return None

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
            "temperature": 0
        }
        models['A'] = ChatOpenAI(model=model1, **common_params, max_tokens=2048)
        _provider_cfg = provider_config(model2)
        models['B'] = ChatOpenAI(model=model2, **common_params, max_tokens=2048, extra_body=_provider_cfg if _provider_cfg else None)

    else:
        # 로컬 GPU 모드: HuggingFace 모델 동적 로드
        print("🖥️ [Mode] Using Local Dynamic Loading (GPU)")
        hf_models = {
            'A': "mistralai/Ministral-3-8B-Instruct-2512",
            'B': "openai/gpt-oss-20b"
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


def invoke_with_tokens(llm, prompt: str, role: str = 'A'):
    """
    LLM을 호출하고 (response, input_tokens, output_tokens)를 반환한다.

    - USE_LOCAL=False (API): ChatOpenAI usage_metadata에서 토큰 수 읽기
    - USE_LOCAL=True  (GPU): 토크나이저로 프롬프트·응답 토큰 직접 계산
    """
    response = llm.invoke(prompt)
    text = response.content if hasattr(response, 'content') else str(response)

    if not USE_LOCAL:
        # API 모드: usage_metadata에서 직접 읽기
        meta = getattr(response, 'usage_metadata', None) or {}
        input_tokens  = meta.get('input_tokens',  0)
        output_tokens = meta.get('output_tokens', 0)
    else:
        # 로컬 GPU 모드: 토크나이저로 계산
        tokenizer = _get_tokenizer(role)
        if tokenizer is not None:
            input_tokens  = len(tokenizer.encode(prompt, add_special_tokens=False))
            output_tokens = len(tokenizer.encode(text,   add_special_tokens=False))
        else:
            input_tokens = output_tokens = 0

    return response, input_tokens, output_tokens
