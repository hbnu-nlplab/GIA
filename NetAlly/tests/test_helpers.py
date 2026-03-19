"""Unit tests for NetAlly helper functions added in simplify session.

Tests:
- _classify_llm_error: 에러 분류 정확도
- _make_sse_event: SSE 포맷 정확도
- _build_metrics: 메트릭 dict 구성
"""

import json
import pytest


# ── _classify_llm_error ──

class TestClassifyLlmError:
    @pytest.fixture(autouse=True)
    def _import(self):
        from main import _classify_llm_error
        self.classify = _classify_llm_error

    def test_auth_api_key(self):
        code, status = self.classify(Exception("Invalid api_key provided"))
        assert code == "LLM_AUTH_ERROR"
        assert status == 401

    def test_auth_apikey(self):
        code, _ = self.classify(Exception("apikey is expired"))
        assert code == "LLM_AUTH_ERROR"

    def test_auth_authentication(self):
        code, _ = self.classify(Exception("authentication failed"))
        assert code == "LLM_AUTH_ERROR"

    def test_rate_limit(self):
        code, status = self.classify(Exception("rate limit exceeded"))
        assert code == "LLM_RATE_LIMIT"
        assert status == 429

    def test_timeout(self):
        code, status = self.classify(Exception("request timeout"))
        assert code == "LLM_TIMEOUT"
        assert status == 504

    def test_generic_error(self):
        code, status = self.classify(Exception("something went wrong"))
        assert code == "LLM_ERROR"
        assert status == 502

    def test_keyerror_not_misclassified(self):
        """KeyError는 AUTH로 오분류되면 안 됨."""
        code, _ = self.classify(KeyError("missing_field"))
        assert code != "LLM_AUTH_ERROR", "KeyError should NOT be classified as AUTH"

    def test_key_in_message_not_auth(self):
        """일반 'key' 단어가 AUTH로 잡히면 안 됨."""
        code, _ = self.classify(Exception("the key insight is..."))
        assert code != "LLM_AUTH_ERROR"


# ── _make_sse_event ──

class TestMakeSseEvent:
    @pytest.fixture(autouse=True)
    def _import(self):
        from main import _make_sse_event
        self.make = _make_sse_event

    def test_format(self):
        result = self.make("answer", {"content": "hello"})
        assert result.startswith("event: answer\n")
        assert "data: " in result
        assert result.endswith("\n\n")

    def test_json_payload(self):
        result = self.make("test", {"key": "value"})
        data_line = result.split("\n")[1]
        payload = json.loads(data_line.replace("data: ", ""))
        assert payload == {"key": "value"}

    def test_korean_not_escaped(self):
        """한글이 unicode escape 안 되고 그대로 나와야 함."""
        result = self.make("answer", {"content": "도구 호출 결과"})
        assert "도구 호출 결과" in result
        assert "\\u" not in result


# ── _build_metrics ──

class TestBuildMetrics:
    @pytest.fixture(autouse=True)
    def _import(self):
        from agent.runtime import _build_metrics
        self.build = _build_metrics

    def test_all_keys_present(self):
        m = self.build(3, 5, 1, 4, 1234.56)
        assert set(m.keys()) == {"llm_calls", "tool_calls", "tool_errors", "steps", "total_ms"}

    def test_values(self):
        m = self.build(3, 5, 1, 4, 1234.567)
        assert m["llm_calls"] == 3
        assert m["tool_calls"] == 5
        assert m["tool_errors"] == 1
        assert m["steps"] == 4
        assert m["total_ms"] == 1234.6  # round(1234.567, 1)

    def test_zero_values(self):
        m = self.build(0, 0, 0, 0, 0.0)
        assert m["total_ms"] == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
