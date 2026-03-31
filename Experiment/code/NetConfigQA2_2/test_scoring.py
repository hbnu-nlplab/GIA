"""Unit tests for TA-Acc scoring functions (analyze_results.py).

Tests cover:
- canonical_answer_type normalization
- TypeAwareScorer: _score_path, _score_boolean, _score_set, _score_numeric, _score_map, _score_text
- clean_prediction / clean_gold
- score() dispatch integration
"""

import sys
import os
import pytest

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from analyze_results import canonical_answer_type, NetConfigQAScorer as TypeAwareScorer


# ── canonical_answer_type ──

class TestCanonicalAnswerType:
    def test_number_aliases(self):
        for alias in ("numeric", "num", "numbers", "int", "integer", "float", "scalar_int"):
            assert canonical_answer_type(alias) == "number", f"Failed for {alias}"

    def test_set_aliases(self):
        for alias in ("list_str", "set_str", "edge_set", "set_string", "list"):
            assert canonical_answer_type(alias) == "set", f"Failed for {alias}"

    def test_map_aliases(self):
        for alias in ("dict", "map_str_str", "map_str_int", "json"):
            assert canonical_answer_type(alias) == "map", f"Failed for {alias}"

    def test_text_aliases(self):
        for alias in ("scalar_str", "enum"):
            assert canonical_answer_type(alias) == "text", f"Failed for {alias}"

    def test_boolean_aliases(self):
        assert canonical_answer_type("bool") == "boolean"
        assert canonical_answer_type("boolean") == "boolean"

    def test_path_identity(self):
        assert canonical_answer_type("path") == "path"

    def test_none_defaults_to_text(self):
        assert canonical_answer_type(None) == "text"

    def test_unknown_passthrough(self):
        assert canonical_answer_type("unknown_type") == "unknown_type"

    def test_case_insensitive(self):
        assert canonical_answer_type("NUMERIC") == "number"
        assert canonical_answer_type("Set_Str") == "set"

    def test_whitespace_stripped(self):
        assert canonical_answer_type("  number  ") == "number"


# ── _score_path ──

class TestScorePath:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_exact_match(self):
        r = self.scorer._score_path("P1 -> P2 -> PE1", "P1 -> P2 -> PE1")
        assert r["score"] == 1.0

    def test_case_insensitive(self):
        r = self.scorer._score_path("p1 -> p2 -> pe1", "P1 -> P2 -> PE1")
        assert r["score"] == 1.0

    def test_wrong_order(self):
        r = self.scorer._score_path("P2 -> P1 -> PE1", "P1 -> P2 -> PE1")
        assert r["score"] == 0.0

    def test_unicode_arrow(self):
        r = self.scorer._score_path("P1 → P2 → PE1", "P1 -> P2 -> PE1")
        assert r["score"] == 1.0

    def test_fat_arrow(self):
        r = self.scorer._score_path("P1 => P2 => PE1", "P1 -> P2 -> PE1")
        assert r["score"] == 1.0

    def test_single_node(self):
        r = self.scorer._score_path("PE1", "PE1")
        assert r["score"] == 1.0

    def test_empty_both(self):
        r = self.scorer._score_path("", "")
        assert r["score"] == 1.0

    def test_empty_pred_nonempty_gold(self):
        r = self.scorer._score_path("", "P1 -> P2")
        assert r["score"] == 0.0

    def test_extra_spaces(self):
        r = self.scorer._score_path("  P1  ->  P2  ", "P1 -> P2")
        assert r["score"] == 1.0

    def test_quoted_path(self):
        r = self.scorer._score_path('"P1 -> P2"', "P1 -> P2")
        assert r["score"] == 1.0


# ── _score_boolean ──

class TestScoreBoolean:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_true_true(self):
        assert self.scorer._score_boolean("true", "true")["score"] == 1.0

    def test_yes_true(self):
        assert self.scorer._score_boolean("yes", "true")["score"] == 1.0

    def test_enabled_true(self):
        assert self.scorer._score_boolean("enabled", "true")["score"] == 1.0

    def test_up_true(self):
        assert self.scorer._score_boolean("up", "true")["score"] == 1.0

    def test_disabled_false(self):
        assert self.scorer._score_boolean("disabled", "false")["score"] == 1.0

    def test_down_false(self):
        assert self.scorer._score_boolean("down", "false")["score"] == 1.0

    def test_not_configured_false(self):
        assert self.scorer._score_boolean("not configured", "false")["score"] == 1.0

    def test_true_false_mismatch(self):
        assert self.scorer._score_boolean("true", "false")["score"] == 0.0

    def test_enabled_disabled_mismatch(self):
        assert self.scorer._score_boolean("enabled", "disabled")["score"] == 0.0

    def test_korean_yes(self):
        assert self.scorer._score_boolean("예", "true")["score"] == 1.0

    def test_unparseable_fallback_match(self):
        assert self.scorer._score_boolean("maybe", "maybe")["score"] == 1.0

    def test_unparseable_fallback_mismatch(self):
        assert self.scorer._score_boolean("maybe", "probably")["score"] == 0.0


# ── _score_set ──

class TestScoreSet:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_exact_match(self):
        r = self.scorer._score_set('["a", "b", "c"]', '["a", "b", "c"]')
        assert r["score"] == 1.0

    def test_order_independent(self):
        r = self.scorer._score_set('["c", "a", "b"]', '["a", "b", "c"]')
        assert r["score"] == 1.0

    def test_partial_overlap(self):
        r = self.scorer._score_set('["a", "b"]', '["a", "b", "c"]')
        assert 0.0 < r["score"] < 1.0

    def test_no_overlap(self):
        r = self.scorer._score_set('["x", "y"]', '["a", "b"]')
        assert r["score"] == 0.0

    def test_both_empty(self):
        r = self.scorer._score_set("[]", "[]")
        assert r["score"] == 1.0

    def test_comma_separated(self):
        r = self.scorer._score_set("a, b, c", '["a", "b", "c"]')
        assert r["score"] == 1.0

    def test_case_insensitive(self):
        r = self.scorer._score_set('["PE1", "PE2"]', '["pe1", "pe2"]')
        assert r["score"] == 1.0


# ── _score_numeric ──

class TestScoreNumeric:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_exact_integer(self):
        r = self.scorer._score_numeric("5", "5")
        assert r["score"] == 1.0

    def test_float_to_int(self):
        r = self.scorer._score_numeric("5.0", "5")
        assert r["score"] == 1.0

    def test_wrong_number(self):
        r = self.scorer._score_numeric("3", "5")
        assert r["score"] == 0.0

    def test_text_with_number(self):
        """LLM이 'The answer is 5'라고 답한 경우"""
        r = self.scorer._score_numeric("The answer is 5", "5")
        assert r["score"] == 1.0

    def test_zero(self):
        r = self.scorer._score_numeric("0", "0")
        assert r["score"] == 1.0


# ── _score_text ──

class TestScoreText:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_exact_match(self):
        r = self.scorer._score_text("Enabled", "Enabled")
        assert r["score"] == 1.0

    def test_case_insensitive(self):
        r = self.scorer._score_text("enabled", "Enabled")
        assert r["score"] == 1.0

    def test_mismatch(self):
        r = self.scorer._score_text("Disabled", "Enabled")
        assert r["score"] == 0.0

    def test_both_empty(self):
        r = self.scorer._score_text("", "")
        assert r["score"] == 1.0

    def test_ip_cidr_normalization(self):
        r = self.scorer._score_text("10.0.0.1/31", "10.0.0.1")
        assert r["score"] == 1.0


# ── _score_map ──

class TestScoreMap:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_exact_json(self):
        r = self.scorer._score_map('{"a": 1, "b": 2}', '{"a": 1, "b": 2}')
        assert r["score"] == 1.0

    def test_partial_keys(self):
        r = self.scorer._score_map('{"a": 1}', '{"a": 1, "b": 2}')
        assert 0.0 < r["score"] < 1.0

    def test_wrong_value(self):
        r = self.scorer._score_map('{"a": 999}', '{"a": 1}')
        assert r["score"] == 0.0

    def test_gold_unparseable(self):
        r = self.scorer._score_map('{"a": 1}', 'broken{gold')
        assert r["score"] == 0.0
        assert "parse_error" in r

    def test_both_empty(self):
        r = self.scorer._score_map('{}', '{}')
        assert r["score"] == 1.0


# ── score() dispatch integration ──

class TestScoreDispatch:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def _call(self, pred, gold, atype, status="OK"):
        pred = self.scorer.clean_prediction(pred, atype)
        return self.scorer.score(pred, gold, atype, status=status)

    def test_dispatches_to_numeric(self):
        r = self._call("5", "5", "scalar_int")
        assert r["score"] == 1.0

    def test_dispatches_to_set(self):
        r = self._call('["a","b"]', '["a","b"]', "set_str")
        assert r["score"] == 1.0

    def test_dispatches_to_boolean(self):
        r = self._call("enabled", "true", "bool")
        assert r["score"] == 1.0

    def test_dispatches_to_path(self):
        r = self._call("P1 -> P2", "P1 -> P2", "path")
        assert r["score"] == 1.0

    def test_dispatches_to_map(self):
        r = self._call('{"a": 1}', '{"a": 1}', "map_str_int")
        assert r["score"] == 1.0

    def test_dispatches_to_text(self):
        r = self._call("Enabled", "Enabled", "text")
        assert r["score"] == 1.0

    def test_not_configured_abstention(self):
        r = self._call("not configured", "", "text", status="NOT_CONFIGURED")
        assert r["score"] == 1.0


class TestNegativeEvaluation:
    def setup_method(self):
        self.scorer = TypeAwareScorer()

    def test_explicit_not_configured_counts_for_both(self):
        r = self.scorer.evaluate_negative_prediction("NOT_CONFIGURED", "null", "text")
        assert r["semantic_negative_correct"] is True
        assert r["explicit_abstention_correct"] is True
        assert r["contract_compliant"] is True

    def test_blank_prediction_is_not_semantic_negative(self):
        r = self.scorer.evaluate_negative_prediction("", "[]", "set")
        assert r["semantic_negative_correct"] is False
        assert r["blank_prediction"] is True

    def test_empty_set_counts_as_semantic_negative_only(self):
        r = self.scorer.evaluate_negative_prediction("[]", "[]", "set_str")
        assert r["semantic_negative_correct"] is True
        assert r["explicit_abstention_correct"] is False
        assert r["contract_compliant"] is False

    def test_zero_counts_as_semantic_negative_only(self):
        r = self.scorer.evaluate_negative_prediction("0", "0", "number")
        assert r["semantic_negative_correct"] is True
        assert r["explicit_abstention_correct"] is False

    def test_disabled_text_counts_as_semantic_negative_only(self):
        r = self.scorer.evaluate_negative_prediction("Disabled", '"Disabled"', "text")
        assert r["semantic_negative_correct"] is True
        assert r["explicit_abstention_correct"] is False

    def test_null_negative_requires_explicit_token(self):
        r = self.scorer.evaluate_negative_prediction("Disabled", "null", "text")
        assert r["semantic_negative_correct"] is False
        assert r["detail"] == "null_negative_requires_explicit"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
