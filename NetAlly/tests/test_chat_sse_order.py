import pytest

import main


class FakeRuntime:
    async def astream(self, payload):
        assert payload["message"] == "show devices"
        assert payload["history"] == []
        assert payload["answer_type"] == "text"
        yield {"type": "planning", "skills": [], "reasoning": "plan", "mode": "prompt_only"}
        yield {"type": "tool_call", "tool": "nso_list_devices", "input": {}, "call_id": 1}
        yield {"type": "tool_output", "tool": "nso_list_devices", "content": '{"devices": []}', "call_id": 1}
        yield {"type": "answer", "content": "final answer"}


@pytest.mark.asyncio
async def test_chat_sse_event_order(monkeypatch):
    monkeypatch.setattr(main, "AUTO_PREPARE_ON_CHAT", False)

    request = main.ChatRequest(message="show devices", history=[], answer_type="text")
    chunks = []
    async for chunk in main.chat_stream_generator(request, FakeRuntime()):
        chunks.append(chunk)

    events = []
    for chunk in chunks:
        for line in chunk.splitlines():
            if line.startswith("event: "):
                events.append(line.split("event: ", 1)[1])

    assert events == ["planning", "tool_call", "tool_output", "answer", "complete"]
