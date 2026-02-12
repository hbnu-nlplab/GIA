import json

import pytest

import main


class FakeRuntimeWithVizAndTool:
    async def astream(self, payload):
        assert payload["history"] == []
        assert payload["answer_type"] == "text"
        yield {"type": "planning", "skills": [], "reasoning": "plan", "mode": "prompt_only"}
        yield {
            "type": "tool_call",
            "tool": "batfish_path_check",
            "input": {"src": "R1", "dst": "R2", "test_type": "traceroute"},
            "call_id": 7,
        }
        yield {
            "type": "tool_output",
            "tool": "batfish_path_check",
            "call_id": 7,
            "content": json.dumps({
                "status": "success",
                "summary": "Traceroute path found",
                "path": ["R1", "R3", "R2"],
            }),
        }
        yield {"type": "answer", "content": "R1 can reach R2 via R3."}


def _parse_sse_events(chunks):
    events = []
    current_event = None
    for chunk in chunks:
        for line in chunk.splitlines():
            if line.startswith("event: "):
                current_event = line.split("event: ", 1)[1].strip()
            elif line.startswith("data: "):
                payload = json.loads(line.split("data: ", 1)[1])
                events.append((current_event or payload.get("type"), payload))
    return events


@pytest.mark.asyncio
async def test_chat_sse_includes_grounding_and_viz_contract(monkeypatch):
    monkeypatch.setattr(main, "AUTO_PREPARE_ON_CHAT", False)

    request = main.ChatRequest(message="check path", history=[], answer_type="text")
    chunks = []
    async for chunk in main.chat_stream_generator(request, FakeRuntimeWithVizAndTool()):
        chunks.append(chunk)

    events = _parse_sse_events(chunks)
    by_event = {}
    for event_name, payload in events:
        by_event.setdefault(event_name, []).append(payload)

    tool_output_payload = by_event["tool_output"][0]
    assert tool_output_payload["citation"]["tool"] == "batfish_path_check"
    assert tool_output_payload["citation"]["call_id"] == 7
    assert tool_output_payload["citation"]["status"] == "success"
    assert tool_output_payload["viz"]["schema_version"] == 1
    assert tool_output_payload["viz"]["mode"] == "path"

    answer_payload = by_event["answer"][0]
    assert answer_payload["grounding"]["supported_by_tools"] is True
    assert answer_payload["grounding"]["citation_count"] >= 1
    assert answer_payload["citations"][0]["call_id"] == 7
    assert answer_payload["viz"]["schema_version"] == 1
    assert answer_payload["viz"]["query"] == "check path"
