from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, MutableMapping

from agent.openai_compat import resolve_openai_compat_config


def infer_provider_label(base_url: str, backend: str) -> str:
    normalized_base = str(base_url or "").strip().lower()
    normalized_backend = str(backend or "").strip().lower()

    if normalized_backend == "vllm":
        return "vllm"
    if normalized_backend == "ollama":
        return "ollama"
    if "openrouter.ai" in normalized_base:
        return "openrouter"
    if "api.openai.com" in normalized_base:
        return "openai"
    return normalized_backend or "unknown"


def infer_lab_folder(dataset_path: Path | str, dataset_meta: Mapping[str, Any] | None = None) -> str:
    meta = dataset_meta or {}
    meta_lab_folder = str(meta.get("lab_folder", "") or "").strip()
    if meta_lab_folder:
        return meta_lab_folder

    path = Path(dataset_path)
    parts = list(path.parts)
    for idx, part in enumerate(parts):
        if part.lower() == "dataset" and idx > 0:
            return parts[idx - 1]

    if len(path.parents) >= 3:
        return path.parents[2].name
    if len(path.parents) >= 2:
        return path.parents[1].name
    return path.parent.name


def collect_runtime_meta(env: MutableMapping[str, str] | None = None) -> dict[str, Any]:
    mapping = env if env is not None else os.environ
    resolved = resolve_openai_compat_config(env=mapping)
    executor_backend = str(mapping.get("NETALLY_EXECUTOR_LLM_BACKEND", "") or "").strip()
    provider = infer_provider_label(resolved.base_url, executor_backend)

    executor_model = str(mapping.get("NETALLY_EXECUTOR_LLM_MODEL", "") or "").strip()
    mas_model_a = str(mapping.get("NETALLY_MAS_MODEL_A", "") or executor_model).strip()
    mas_model_b = str(mapping.get("NETALLY_MAS_MODEL_B", "") or mas_model_a or executor_model).strip()

    return {
        "agent_backend": str(mapping.get("NETALLY_AGENT_BACKEND", "") or "").strip(),
        "tool_backend": str(mapping.get("NETALLY_TOOL_BACKEND", "") or "").strip(),
        "executor_llm_backend": executor_backend,
        "executor_llm_model": executor_model,
        "mas_model_a": mas_model_a,
        "mas_model_b": mas_model_b,
        "provider": provider,
        "provider_base_url": resolved.base_url,
        "provider_config_source": resolved.source,
    }
