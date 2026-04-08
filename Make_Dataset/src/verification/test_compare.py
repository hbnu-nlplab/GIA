"""Unit tests for verification/compare.py TA-Acc scoring functions.

Tests cover:
- compare_answers dispatch
- _score_path, _score_set, _score_number, _score_boolean, _score_map, _score_text
- canonical_answer_type routing
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from compare import compare_answers


# ── compare_answers dispatch ──

class TestCompareDispatch:
    def test_number_exact(self):
        r = compare_answers(5, 5, "number")
        assert r["score"] == 1.0
        assert r["answer_type"] == "number"

    def test_number_from_scalar_int(self):
        r = compare_answers(5, 5, "scalar_int")
        assert r["score"] == 1.0
        assert r["answer_type"] == "number"

    def test_number_mismatch(self):
        r = compare_answers(3, 5, "number")
        assert r["score"] == 0.0

    def test_set_exact(self):
        r = compare_answers(["a", "b"], ["a", "b"], "set")
        assert r["score"] == 1.0

    def test_set_from_set_str(self):
        r = compare_answers(["a", "b"], ["b", "a"], "set_str")
        assert r["score"] == 1.0
        assert r["answer_type"] == "set"

    def test_set_partial(self):
        r = compare_answers(["a"], ["a", "b"], "set")
        assert 0.0 < r["score"] < 1.0

    def test_boolean_match(self):
        r = compare_answers("true", "yes", "boolean")
        assert r["score"] == 1.0

    def test_boolean_from_bool(self):
        r = compare_answers("true", "true", "bool")
        assert r["answer_type"] == "boolean"

    def test_boolean_mismatch(self):
        r = compare_answers("true", "false", "boolean")
        assert r["score"] == 0.0

    def test_text_exact(self):
        r = compare_answers("hello", "hello", "text")
        assert r["score"] == 1.0

    def test_text_mismatch(self):
        r = compare_answers("hello", "world", "text")
        assert r["score"] == 0.0

    def test_map_exact(self):
        r = compare_answers({"a": 1}, {"a": 1}, "map")
        assert r["score"] == 1.0

    def test_map_missing_key(self):
        r = compare_answers({"a": 1}, {"a": 1, "b": 2}, "map")
        assert r["score"] < 1.0  # missing key "b" penalizes score


# ── _score_path via dispatch ──

class TestScorePath:
    def test_exact(self):
        r = compare_answers("P1 -> P2 -> PE1", "P1 -> P2 -> PE1", "path")
        assert r["score"] == 1.0
        assert r["answer_type"] == "path"

    def test_case_insensitive(self):
        r = compare_answers("p1 -> p2", "P1 -> P2", "path")
        assert r["score"] == 1.0

    def test_unicode_arrow(self):
        r = compare_answers("P1 → P2 → PE1", "P1 -> P2 -> PE1", "path")
        assert r["score"] == 1.0

    def test_fat_arrow(self):
        r = compare_answers("P1 => P2", "P1 -> P2", "path")
        assert r["score"] == 1.0

    def test_wrong_order(self):
        r = compare_answers("P2 -> P1", "P1 -> P2", "path")
        assert r["score"] == 0.0

    def test_single_node(self):
        r = compare_answers("PE1", "PE1", "path")
        assert r["score"] == 1.0

    def test_empty_both(self):
        r = compare_answers("", "", "path")
        assert r["score"] == 1.0

    def test_empty_pred(self):
        r = compare_answers("", "P1 -> P2", "path")
        assert r["score"] == 0.0

    def test_extra_whitespace(self):
        r = compare_answers("  P1  ->  P2  ", "P1 -> P2", "path")
        assert r["score"] == 1.0


# ── Edge cases ──

class TestEdgeCases:
    def test_unknown_type_falls_to_text(self):
        r = compare_answers("hello", "hello", "unknown_type_xyz")
        assert r["score"] == 1.0
        assert r["answer_type"] == "unknown_type_xyz"

    def test_error_handling(self):
        """Scoring errors should not crash — return score=0.0"""
        r = compare_answers(None, None, "map")
        assert "score" in r

    def test_number_string_coercion(self):
        r = compare_answers("5", 5, "number")
        assert r["score"] == 1.0

    def test_set_string_input(self):
        r = compare_answers("a, b, c", '["a", "b", "c"]', "set")
        assert r["score"] == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
