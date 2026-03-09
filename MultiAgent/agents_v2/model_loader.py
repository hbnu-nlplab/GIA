
import torch
import gc
import sys
from pathlib import Path
from langchain_openai import ChatOpenAI
from langchain_huggingface import HuggingFacePipeline
from transformers import pipeline, BitsAndBytesConfig
from transformers import AutoModelForCausalLM, AutoTokenizer
import os

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
from config.load_env import load_louter
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
# === 설정 ===
USE_LOCAL = True
MAX_LOADED_MODELS =1


class DynamicModelLoader:
    def __init__(self, model_map):
        self.model_map = model_map
        self.loaded_models = {} # {model_id: pipeline}
        self.access_history = [] # For LRU
        
        self.bnb_config = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True,
            llm_int8_enable_fp32_cpu_offload=True 
        )

    def load_model(self, role):
        model_id = self.model_map[role]
        
        if model_id in self.loaded_models:
            return self.loaded_models[model_id]

        print(f"🚀 [Role {role}] Loading Model: {model_id} across ALL GPUs...")

        # 1. 모든 GPU를 골고루 사용하기 위한 설정
        # 특정 GPU를 지정하지 않고 "auto"로 두면 시스템의 모든 GPU를 사용합니다.
        device_map = "auto" 
        max_memory = {
    0: "22GiB",
    1: "22GiB",
    2: "22GiB",
    3: "5GiB",  # 24GB 중 10GB만 모델 로드에 쓰고, 14GB는 답변 생성용으로 비워둠
    "cpu": "100GiB"
}
        # 2. 모델 로드 (AutoModel 사용 권장)
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map=device_map,           # 0, 1, 2, 3번 GPU 자동 분산
            quantization_config=self.bnb_config,
            dtype=torch.float16,
            trust_remote_code=True,
            low_cpu_mem_usage=True
        )

        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)

        # 3. Pipeline 생성
        pipe = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            max_new_tokens=1024,
            temperature=0.01
        )

        hf_pipe = HuggingFacePipeline(pipeline=pipe)
        self.loaded_models[model_id] = hf_pipe
        return hf_pipe

class LazyModelProxy:
    def __init__(self, loader, role):
        self.loader = loader
        self.role = role
        
    def invoke(self, *args, **kwargs):
        model = self.loader.load_model(self.role)
        return model.invoke(*args, **kwargs)

_LLM_DICT = {}

def init_models():
    global _LLM_DICT
    if _LLM_DICT: return _LLM_DICT
    
    models = {} # Initialize models dict here for both branches
    if not USE_LOCAL:
        print(" [Mode] Using OpenRouter (Cloud)")
        try:
            api_key, base_url, model1, model2 = load_louter()
        except ImportError:
            print("Check config/load_env.py implementation")
            return {}

        common_params = {"base_url": base_url, "api_key": api_key, "temperature": 0, "max_tokens": 1024}

        models['A'] = ChatOpenAI(model=model1, **common_params)
        models['B'] = ChatOpenAI(model=model2, **common_params)

    else:
        print("🖥️ [Mode] Using Local Dynamic Loading (GPU)")
        hf_models = {
            'A': "Qwen/Qwen3.5-9B",
            'B': "zai-org/GLM-4.7-Flash"
        }
        
        loader = DynamicModelLoader(hf_models)
        
        models = {
            'A': LazyModelProxy(loader, 'A'),
            'B': LazyModelProxy(loader, 'B')
        }
    _LLM_DICT = models
    return models

def get_models():
    return init_models()