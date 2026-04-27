"""
Helpers for OpenAI-compatible backend configuration.

This keeps OpenAI, OpenRouter, and vLLM environment resolution consistent
across the runtime and direct evaluation scripts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, MutableMapping, Optional


DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
VLLM_PLACEHOLDER_API_KEY = "sk-no-key-required"


@dataclass(frozen=True)
class OpenAICompatConfig:
    backend: str
    api_key: str
    base_url: str
    source: str
    env_updates: Dict[str, str] = field(default_factory=dict)


def resolve_openai_compat_config(
    backend: Optional[str] = None,
    env: Optional[MutableMapping[str, str]] = None,
) -> OpenAICompatConfig:
    mapping = env if env is not None else os.environ
    resolved_backend = str(backend or mapping.get("NETALLY_EXECUTOR_LLM_BACKEND", "openai")).strip().lower()

    openrouter_key = str(mapping.get("OPENROUTER_API_KEY", "") or "").strip()
    openai_key = str(mapping.get("OPENAI_API_KEY", "") or "").strip()
    vllm_url = str(mapping.get("VLLM_BASE_URL", "") or "").strip()

    explicit_base = (
        str(mapping.get("OPENAI_API_BASE", "") or "").strip()
        or str(mapping.get("OPENAI_BASE_URL", "") or "").strip()
    )
    openrouter_base = str(mapping.get("OPENROUTER_BASE_URL", "") or "").strip()

    if resolved_backend == "vllm" and vllm_url:
        return OpenAICompatConfig(
            backend=resolved_backend,
            api_key=VLLM_PLACEHOLDER_API_KEY,
            base_url=vllm_url,
            source="vllm",
            env_updates={
                "OPENAI_API_KEY": VLLM_PLACEHOLDER_API_KEY,
                "OPENAI_API_BASE": vllm_url,
                "OPENAI_BASE_URL": vllm_url,
            },
        )

    api_key = openrouter_key or openai_key
    source = "explicit"

    if explicit_base:
        base_url = explicit_base
    elif openrouter_base:
        base_url = openrouter_base
        source = "openrouter"
    elif openrouter_key or api_key.startswith("sk-or-"):
        base_url = DEFAULT_OPENROUTER_BASE_URL
        source = "openrouter"
    else:
        base_url = DEFAULT_OPENAI_BASE_URL
        source = "openai"

    env_updates: Dict[str, str] = {
        "OPENAI_API_BASE": base_url,
        "OPENAI_BASE_URL": base_url,
    }
    if api_key:
        env_updates["OPENAI_API_KEY"] = api_key

    return OpenAICompatConfig(
        backend=resolved_backend,
        api_key=api_key,
        base_url=base_url,
        source=source,
        env_updates=env_updates,
    )


def apply_openai_compat_env(
    backend: Optional[str] = None,
    env: Optional[MutableMapping[str, str]] = None,
) -> OpenAICompatConfig:
    mapping = env if env is not None else os.environ
    resolved = resolve_openai_compat_config(backend=backend, env=mapping)
    for key, value in resolved.env_updates.items():
        if value:
            mapping[key] = value
    return resolved
