from types import SimpleNamespace

import pytest

import main


class FakeGraph:
    async def astream(self, initial_state, stream_mode="updates"):
        yield {"orchestrator": {"selected_skills": ["core"], "reasoning": "plan"}}
        yield {
            "executor": {
                "messages": [
                    SimpleNamespace(
                        tool_calls=[{"name": "network_query", "args": {"category": "device"}}],
                        content="",
                    )
                ],
                "is_complete": False,
            }
        }
        yield {"tools": {"messages": [SimpleNamespace(content='{"devices": []}')]}}
        yield {
            "executor": {
                "messages": [SimpleNamespace(tool_calls=[], content="final answer")],
                "is_complete": True,
                "final_answer": "final answer",
            }
        }


@pytest.mark.asyncio
async def test_chat_sse_event_order(monkeypatch):
    monkeypatch.setattr(main, "AUTO_PREPARE_ON_CHAT", False)

    request = main.ChatRequest(message="show devices", history=[], answer_type="text")
    chunks = []
    async for chunk in main.chat_stream_generator(request, FakeGraph()):
        chunks.append(chunk)

    events = []
    for chunk in chunks:
        for line in chunk.splitlines():
            if line.startswith("event: "):
                events.append(line.split("event: ", 1)[1])

    assert events == ["planning", "tool_call", "tool_output", "answer", "complete"]
