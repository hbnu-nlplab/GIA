
import torch
import gc
import sys
from pathlib import Path
from langchain_openai import ChatOpenAI
from langchain_huggingface import HuggingFacePipeline
from transformers import pipeline, BitsAndBytesConfig

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
from config.load_env import load_louter

# === 설정 ===
USE_LOCAL = False
MAX_LOADED_MODELS = 1  # GPU 2장이면 안전하게 1~2개만 유지 (모델 크기에 따라 조절)

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
            # Update access history
            if model_id in self.access_history:
                self.access_history.remove(model_id)
            self.access_history.append(model_id)
            return self.loaded_models[model_id]
        
        # Need to load new model. Check if we need to unload.
        if len(self.loaded_models) >= MAX_LOADED_MODELS:
            # Unload Least Recently Used
            lru_model_id = self.access_history.pop(0)
            print(f"♻️  Unloading {lru_model_id} to free VRAM...")
            del self.loaded_models[lru_model_id]
            gc.collect()
            torch.cuda.empty_cache()
            
        print(f"🚀 Loading {role}: {model_id}...")
        
        # Config Setup
        model_kwargs = {"low_cpu_mem_usage": True}
        if "gpt-oss-20b" not in model_id:
            model_kwargs["quantization_config"] = self.bnb_config
            
        pipe = pipeline(
            "text-generation", model=model_id, tokenizer=model_id,
            model_kwargs=model_kwargs,
            device_map="auto",
            max_new_tokens=1024, temperature=0.01
        )
        hf_pipe = HuggingFacePipeline(pipeline=pipe)
        
        self.loaded_models[model_id] = hf_pipe
        self.access_history.append(model_id)
        
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
            api_key, base_url, model1, model2, model3, model4, model5 = load_louter()
        except ImportError:
            print("Check config/load_env.py implementation")
            return {}

        common_params = {"base_url": base_url, "api_key": api_key, "temperature": 0, "max_tokens": 256}

        print(f"   - Model A (Engineer/Judge): {model1}")
        print(f"   - Model B (Auditor/Skeptic): {model2}")
        print(f"   - Model C (Editor/Supporter): {model3}")
        print(f"   - Model D (Synthesizer): {model4}")
        print(f"   - Model E (Synthesizer): {model5}")

        models['A'] = ChatOpenAI(model=model1, **common_params)
        models['B'] = ChatOpenAI(model=model2, **common_params)
        models['C'] = ChatOpenAI(model=model3, **common_params)
        models['D'] = ChatOpenAI(model=model4, **common_params)
        models['E'] = ChatOpenAI(model=model5, **common_params)

        
    else:
        print("🖥️ [Mode] Using Local Dynamic Loading (GPU)")
        hf_models = {
            'A': "meta-llama/Meta-Llama-3.1-8B-Instruct",
            'B': "Qwen/Qwen2.5-14B-Instruct",
            'C': "google/gemma-2-9b-it",
            'D': "google/gemma-2-9b-it"
        }
        
        loader = DynamicModelLoader(hf_models)
        
        models = {
            'A': LazyModelProxy(loader, 'A'),
            'B': LazyModelProxy(loader, 'B'),
            'C': LazyModelProxy(loader, 'C'),
            'D': LazyModelProxy(loader, 'D')
        }
    _LLM_DICT = models
    return models

def get_models():
    return init_models()