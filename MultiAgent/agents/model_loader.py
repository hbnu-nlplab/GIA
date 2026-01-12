import torch
import sys
from pathlib import Path
from langchain_openai import ChatOpenAI
from langchain_huggingface import HuggingFacePipeline
from transformers import pipeline, BitsAndBytesConfig

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
from config.load_env import load_louter

# === 설정 ===
USE_LOCAL = True  # True: GPU, False: OpenRouter

_LLM_DICT = {}

def init_models():
    global _LLM_DICT
    if _LLM_DICT: return _LLM_DICT  
    models = {}
    if not USE_LOCAL:
        print(" [Mode] Using OpenRouter (Cloud)")
        try:
            api_key, base_url, model1, model2, model3, model4 = load_louter()
        except ImportError:
            print("Check config/load_env.py implementation")
            return {}

        common_params = {"base_url": base_url, "api_key": api_key, "temperature": 0, "max_tokens": 256}

        print(f"   - Model A (Engineer/Judge): {model1}")
        print(f"   - Model B (Auditor/Skeptic): {model2}")
        print(f"   - Model C (Editor/Supporter): {model3}")

        models['A'] = ChatOpenAI(model=model1, **common_params)
        models['B'] = ChatOpenAI(model=model2, **common_params)
        models['C'] = ChatOpenAI(model=model3, **common_params)
        models['D'] = ChatOpenAI(model=model4, **common_params)

    else:
        print("🖥️ [Mode] Using Local Hugging Face Models (GPU)")
        hf_models = {
            'A': "meta-llama/Meta-Llama-3.1-8B-Instruct",
            'B': "Qwen/Qwen2.5-3B-Instruct",
            'C': "google/gemma-2-2b-it",
            'D': "openai/gpt-oss-20b" 
        }
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True,
        )

        loaded_pipelines = {} 

        for role, model_id in hf_models.items():
            if model_id in loaded_pipelines:
                print(f"   ...Reusing {model_id} for {role}")
                models[role] = loaded_pipelines[model_id]
            else:
                print(f"   ...Loading {role}: {model_id}")
                
                # openai/gpt-oss-20b는 이미 양자화되어 있어 bnb_config 충돌 방지
                current_model_kwargs = {"low_cpu_mem_usage": True}
                if "gpt-oss-20b" not in model_id:
                    current_model_kwargs["quantization_config"] = bnb_config
                
                pipe = pipeline(
                    "text-generation", model=model_id, tokenizer=model_id,
                    model_kwargs=current_model_kwargs,
                    device_map="auto",  
                    max_new_tokens=256, temperature=0
                )
                hf_pipe = HuggingFacePipeline(pipeline=pipe)
                models[role] = hf_pipe
                loaded_pipelines[model_id] = hf_pipe

    _LLM_DICT = models
    return models

def get_models():
    return init_models()