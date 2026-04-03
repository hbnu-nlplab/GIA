"""
model_loader.py — NetAlly 통합 버전
----------------------------------
OpenRouter API 또는 NetAlly LLMProvider를 통해 LLM 로드.

에이전트는 'A', 'B' 두 개의 모델 키를 사용:
- 'A': 합성/검증 (Synthesizer, Verifier, Supporter)
- 'B': 수집/비판 (Collector, Skeptic)
"""

import os
import logging
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

_LLM_DICT = {}


def init_models():
    """Initialize dual-model configuration."""
    global _LLM_DICT
    if _LLM_DICT:
        return _LLM_DICT

    # Backend detection: vllm > openrouter > openai
    backend = os.getenv("NETALLY_EXECUTOR_LLM_BACKEND", "openai")
    vllm_url = os.getenv("VLLM_BASE_URL", "")
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    base_url = os.getenv("OPENAI_API_BASE", "")

    if backend == "vllm" and vllm_url:
        base_url = vllm_url
        api_key = "sk-no-key-required"
        # Override env vars BEFORE ChatOpenAI reads them
        # (dotenv loads real OPENAI_API_KEY which causes SDK to hit api.openai.com)
        os.environ["OPENAI_API_KEY"] = api_key
        os.environ["OPENAI_API_BASE"] = base_url
        os.environ["OPENAI_BASE_URL"] = base_url
    elif not base_url:
        if api_key.startswith("sk-or-"):
            base_url = "https://openrouter.ai/api/v1"
        else:
            base_url = "https://api.openai.com/v1"

    default_model = os.getenv("NETALLY_EXECUTOR_LLM_MODEL", "gpt-4o-mini")
    model_a = os.getenv("NETALLY_MAS_MODEL_A", default_model)
    model_b = os.getenv("NETALLY_MAS_MODEL_B", model_a)

    common = {
        "openai_api_key": api_key,
        "openai_api_base": base_url,
        "temperature": 0,
        "max_tokens": 4096,
    }

    _LLM_DICT['A'] = ChatOpenAI(model=model_a, **common)
    _LLM_DICT['B'] = ChatOpenAI(model=model_b, **common)

    logger.info(f"Models initialized: A={model_a}, B={model_b}, base={base_url}")
    return _LLM_DICT


def get_models():
    """Get initialized models (init if needed)."""
    if not _LLM_DICT:
        init_models()
    return _LLM_DICT
