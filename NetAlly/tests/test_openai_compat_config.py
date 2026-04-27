import importlib
import sys
import types

import pytest


def test_model_loader_honors_openai_base_url_alias(monkeypatch: pytest.MonkeyPatch):
    class FakeChatOpenAI:
        calls = []

        def __init__(self, model, **kwargs):
            self.model = model
            self.kwargs = kwargs
            FakeChatOpenAI.calls.append((model, kwargs))

    monkeypatch.setitem(
        sys.modules,
        "langchain_openai",
        types.SimpleNamespace(ChatOpenAI=FakeChatOpenAI),
    )

    monkeypatch.setenv("NETALLY_EXECUTOR_LLM_BACKEND", "openai")
    monkeypatch.setenv("NETALLY_EXECUTOR_LLM_MODEL", "mistralai/Ministral-3-8B-Instruct-2512")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openrouter.ai/api/custom")
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)

    import agents_netally.model_loader as model_loader

    model_loader = importlib.reload(model_loader)
    model_loader._LLM_DICT.clear()

    try:
        model_loader.init_models()
    finally:
        model_loader._LLM_DICT.clear()

    assert FakeChatOpenAI.calls
    assert FakeChatOpenAI.calls[0][1]["openai_api_base"] == "https://openrouter.ai/api/custom"


def test_openai_compat_backfills_openrouter_env_aliases(monkeypatch: pytest.MonkeyPatch):
    from agent.openai_compat import apply_openai_compat_env

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v42")

    resolved = apply_openai_compat_env()

    assert resolved.api_key == "sk-or-test"
    assert resolved.base_url == "https://openrouter.ai/api/v42"
    assert resolved.backend == "openai"
    assert resolved.source == "openrouter"
    assert resolved.env_updates["OPENAI_API_KEY"] == "sk-or-test"
    assert resolved.env_updates["OPENAI_API_BASE"] == "https://openrouter.ai/api/v42"
    assert resolved.env_updates["OPENAI_BASE_URL"] == "https://openrouter.ai/api/v42"


def test_openai_compat_prefers_explicit_openai_api_base(monkeypatch: pytest.MonkeyPatch):
    from agent.openai_compat import resolve_openai_compat_config

    monkeypatch.setenv("NETALLY_EXECUTOR_LLM_BACKEND", "openai")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/fallback")
    monkeypatch.setenv("OPENAI_API_BASE", "https://openrouter.ai/api/preferred")

    resolved = resolve_openai_compat_config()

    assert resolved.base_url == "https://openrouter.ai/api/preferred"
    assert resolved.source == "explicit"
