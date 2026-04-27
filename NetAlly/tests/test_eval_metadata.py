from pathlib import Path

import pytest


def test_infer_lab_folder_prefers_parent_before_dataset() -> None:
    from agent.eval_metadata import infer_lab_folder

    dataset_path = Path(
        "../Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/Dataset/20260325_101536/"
        "LabB_NCN_Basic_SP_20nodes_dataset_batfish_20260325_101536_en.json"
    )

    assert infer_lab_folder(dataset_path, {}) == "LabB_NCN_Basic_SP_20nodes"


def test_collect_runtime_meta_captures_openrouter_model_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent.eval_metadata import collect_runtime_meta

    monkeypatch.setenv("NETALLY_AGENT_BACKEND", "team_multi_adapter")
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_EXECUTOR_LLM_BACKEND", "openai")
    monkeypatch.setenv("NETALLY_EXECUTOR_LLM_MODEL", "mistralai/ministral-8b-2512")
    monkeypatch.setenv("NETALLY_MAS_MODEL_A", "mistralai/ministral-8b-2512")
    monkeypatch.setenv("NETALLY_MAS_MODEL_B", "openai/gpt-4o-mini")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENAI_API_BASE", "https://openrouter.ai/api/v1")

    meta = collect_runtime_meta()

    assert meta["agent_backend"] == "team_multi_adapter"
    assert meta["tool_backend"] == "mcp"
    assert meta["executor_llm_backend"] == "openai"
    assert meta["executor_llm_model"] == "mistralai/ministral-8b-2512"
    assert meta["mas_model_a"] == "mistralai/ministral-8b-2512"
    assert meta["mas_model_b"] == "openai/gpt-4o-mini"
    assert meta["provider"] == "openrouter"
    assert meta["provider_base_url"] == "https://openrouter.ai/api/v1"
    assert meta["provider_config_source"] == "explicit"
