import json

import pytest

from agent import runtime as runtime_module


@pytest.mark.asyncio
async def test_team_multi_adapter_emits_standard_sse_sequence(monkeypatch: pytest.MonkeyPatch):
    def _fake_run(
        question: str,
        history,
        answer_type: str,
        *,
        module_name: str,
        dataset_type: str,
        context: str | None,
    ):
        assert question == "team question"
        assert answer_type == "text"
        assert isinstance(history, list)
        assert module_name
        assert dataset_type
        assert context is None
        return {
            "ok": True,
            "stage": "done",
            "answer": "team final answer",
            "meta": {"duration_ms": 17},
            "result": {"final_answer": "team final answer"},
        }

    monkeypatch.setattr(runtime_module, "run_team_multi_query", _fake_run)
    runtime = runtime_module.TeamMultiAdapterRuntime()

    events = []
    async for event in runtime.astream(
        {
            "message": "team question",
            "history": [{"role": "user", "content": "previous"}],
            "answer_type": "text",
        }
    ):
        events.append(event)

    assert [e["type"] for e in events] == ["planning", "tool_call", "tool_output", "answer"]
    assert events[0]["agent_backend"] == "team_multi_adapter"
    assert events[1]["tool"] == "team_multi_invoke"
    parsed_output = json.loads(events[2]["content"])
    assert parsed_output["ok"] is True
    assert events[3]["content"] == "team final answer"


@pytest.mark.asyncio
async def test_team_multi_adapter_emits_failure_answer(monkeypatch: pytest.MonkeyPatch):
    def _fake_run(*_args, **_kwargs):
        return {
            "ok": False,
            "stage": "load",
            "error": "module import failed",
            "answer": "",
        }

    monkeypatch.setattr(runtime_module, "run_team_multi_query", _fake_run)
    runtime = runtime_module.TeamMultiAdapterRuntime()

    events = []
    async for event in runtime.astream({"message": "q", "history": [], "answer_type": "text"}):
        events.append(event)

    assert events[-1]["type"] == "answer"
    assert "team_multi_adapter 실행 실패(load)" in events[-1]["content"]
