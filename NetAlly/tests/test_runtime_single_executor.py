import pytest
from langchain_core.messages import AIMessage

from agent import runtime as runtime_module


class _FakeLLM:
    def __init__(self, invoke_fn):
        self._invoke_fn = invoke_fn
        self.bound_tools = []

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self

    def invoke(self, messages):
        return self._invoke_fn(messages)


def test_single_executor_uses_core_tools_in_mcp_mode(monkeypatch: pytest.MonkeyPatch):
    fake_llm = _FakeLLM(lambda _messages: AIMessage(content="ok"))
    monkeypatch.setattr(runtime_module.LLMProvider, "create", lambda _cfg: fake_llm)

    runtime = runtime_module.SingleExecutorRuntime(tool_backend="mcp")
    names = [t.name for t in runtime.tools]

    assert runtime.bound_tool_count == 16
    assert len(names) == 16
    assert "network_query" not in names
    assert "lab_bootstrap" not in names


@pytest.mark.asyncio
async def test_single_executor_includes_history_in_prompt_context(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def _invoke(messages):
        captured["messages"] = list(messages)
        return AIMessage(content="answer")

    fake_llm = _FakeLLM(_invoke)
    monkeypatch.setattr(runtime_module.LLMProvider, "create", lambda _cfg: fake_llm)

    runtime = runtime_module.SingleExecutorRuntime(tool_backend="mcp")
    events = []
    async for event in runtime.astream(
        {
            "message": "current question",
            "answer_type": "text",
            "history": [
                {"role": "user", "content": "previous user"},
                {"role": "assistant", "content": "previous assistant"},
            ],
        }
    ):
        events.append(event)

    assert events[0]["type"] == "planning"
    assert events[-1]["type"] == "answer"

    msgs = captured["messages"]
    # system + user history + assistant history + current user
    assert len(msgs) == 4
    assert str(msgs[1].content) == "previous user"
    assert str(msgs[2].content) == "previous assistant"
    assert str(msgs[3].content) == "current question"


@pytest.mark.asyncio
async def test_single_executor_emits_limit_answer_when_tool_loop_exceeds_step_limit(
    monkeypatch: pytest.MonkeyPatch,
):
    def _invoke(_messages):
        return AIMessage(
            content="",
            tool_calls=[{"name": "nso_list_devices", "args": {}, "id": "tc-1"}],
        )

    fake_llm = _FakeLLM(_invoke)
    monkeypatch.setattr(runtime_module.LLMProvider, "create", lambda _cfg: fake_llm)

    runtime = runtime_module.SingleExecutorRuntime(tool_backend="mcp", step_limit=2)

    async def _fake_invoke_tool(_name: str, _args):
        return {"devices": []}

    monkeypatch.setattr(runtime, "_invoke_tool", _fake_invoke_tool)

    events = []
    async for event in runtime.astream({"message": "q", "history": [], "answer_type": "text"}):
        events.append(event)

    assert events[-1]["type"] == "answer"
    assert "도구 호출 한도 도달" in events[-1]["content"]
