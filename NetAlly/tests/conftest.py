import pytest


@pytest.fixture(autouse=True)
def _disable_langsmith_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Keep tests self-contained.

    Some environments may have LangSmith tracing enabled globally which can
    cause noisy network calls (and 403s) during CI/local test runs.
    """
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    monkeypatch.delenv("LANGCHAIN_API_KEY", raising=False)

