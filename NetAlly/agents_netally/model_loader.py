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

    # Prefer OPENAI_API_KEY (works for both OpenAI direct and OpenRouter)
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENROUTER_API_KEY", "")
    base_url = os.getenv("OPENAI_API_BASE", "")

    # Auto-detect: sk-or-* = OpenRouter, sk-proj-* = OpenAI direct
    if not base_url:
        if api_key.startswith("sk-or-"):
            base_url = "https://openrouter.ai/api/v1"
        else:
            base_url = "https://api.openai.com/v1"

    # Model names: OpenRouter needs "openai/" prefix, OpenAI direct does not
    default_model = os.getenv("NETALLY_EXECUTOR_LLM_MODEL", "gpt-4o-mini")
    model_a = os.getenv("NETALLY_MAS_MODEL_A", default_model)
    model_b = os.getenv("NETALLY_MAS_MODEL_B", model_a)

    common = {
        "api_key": api_key,
        "temperature": 0,
        "max_tokens": 4096,
    }
    if base_url and "openrouter" in base_url:
        common["base_url"] = base_url

    _LLM_DICT['A'] = ChatOpenAI(model=model_a, **common)
    _LLM_DICT['B'] = ChatOpenAI(model=model_b, **common)

    logger.info(f"Models initialized: A={model_a}, B={model_b}, base={base_url}")
    return _LLM_DICT


def get_models():
    """Get initialized models (init if needed)."""
    if not _LLM_DICT:
        init_models()
    return _LLM_DICT
