from pathlib import Path

from agent import team_multi_bridge as bridge


def test_run_team_multi_query_maps_output_and_state(monkeypatch):
    captured = {}

    class _FakeApp:
        def invoke(self, state):
            captured["state"] = state
            return {
                "final_answer": "result from team graph",
                "candidate_answer": "candidate",
            }

    monkeypatch.setattr(bridge, "_resolve_team_root", lambda: Path("/tmp/fake-team"))
    monkeypatch.setattr(bridge, "_load_cached_graph", lambda _root, _module: (object(), _FakeApp()))

    result = bridge.run_team_multi_query(
        "what is the answer?",
        history=[{"role": "user", "content": "prev question"}],
        answer_type="map",
        module_name="agents.main_netconfig",
        dataset_type="netconfig",
        context="context payload",
    )

    assert result["ok"] is True
    assert result["answer"] == "result from team graph"
    assert result["meta"]["module_name"] == "agents.main_netconfig"
    assert result["meta"]["dataset_type"] == "netconfig"
    assert captured["state"]["question"].endswith("[answer_type=map]")
    assert captured["state"]["context"] == "context payload"


def test_run_team_multi_query_returns_load_error(monkeypatch):
    monkeypatch.setattr(bridge, "_resolve_team_root", lambda: Path("/tmp/fake-team"))

    def _raise(_root, _module):
        raise RuntimeError("import failed")

    monkeypatch.setattr(bridge, "_load_cached_graph", _raise)

    result = bridge.run_team_multi_query("q")
    assert result["ok"] is False
    assert result["stage"] == "load"
    assert "import failed" in result["error"]


def test_run_team_multi_query_uses_history_context_when_no_other_context(monkeypatch):
    captured = {}

    class _FakeApp:
        def invoke(self, state):
            captured["state"] = state
            return {"final_answer": "ok"}

    monkeypatch.setattr(bridge, "_resolve_team_root", lambda: Path("/tmp/fake-team"))
    monkeypatch.setattr(bridge, "_load_cached_graph", lambda _root, _module: (object(), _FakeApp()))
    monkeypatch.delenv("NETALLY_TEAM_MULTI_CONTEXT", raising=False)
    monkeypatch.delenv("NETALLY_TEAM_MULTI_CONTEXT_PATH", raising=False)

    result = bridge.run_team_multi_query(
        "question",
        history=[{"role": "assistant", "content": "previous answer"}],
        dataset_type="descriptive",
        context=None,
    )

    assert result["ok"] is True
    assert "Conversation history:" in captured["state"]["context"]
