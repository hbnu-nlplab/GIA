"""
NetConfigQA 파이프라인 단위 테스트

테스트 대상:
1. _canonicalize 함수
2. validate_answer 함수
3. AnswerResult 반환 검증
4. _build_evidence 함수
"""

import sys
from pathlib import Path

# 경로 추가
sys.path.insert(0, str(Path(__file__).parent))

import unittest
from core_batfish.batfish_builder import (
    _canonicalize, 
    _build_evidence, 
    AnswerResult,
    CanonicalizationError
)
from main_batfish import validate_answer, ANSWER_SCHEMAS


class TestCanonicalize(unittest.TestCase):
    """_canonicalize 함수 테스트"""
    
    def test_set_str_removes_duplicates_and_sorts(self):
        """set_str: 중복 제거 및 정렬"""
        result = _canonicalize(["b", "a", "c", "a"], "set_str")
        self.assertEqual(result, ["a", "b", "c"])
    
    def test_set_str_empty_list(self):
        """set_str: 빈 리스트"""
        result = _canonicalize([], "set_str")
        self.assertEqual(result, [])
    
    def test_edge_set_normalizes_and_sorts(self):
        """edge_set: 방향 정규화 및 정렬"""
        result = _canonicalize([["b", "a"], ["c", "d"]], "edge_set")
        # 각 edge가 정렬되고, edge 목록도 정렬됨
        self.assertEqual(result, [["a", "b"], ["c", "d"]])
    
    def test_map_str_int_sorts_keys(self):
        """map_str_int: 키 정렬"""
        result = _canonicalize({"z": 1, "a": 2}, "map_str_int")
        self.assertEqual(list(result.keys()), ["a", "z"])
    
    def test_path_preserves_order(self):
        """path: 순서 유지"""
        result = _canonicalize(["r1", "r2", "r3"], "path")
        self.assertEqual(result, ["r1", "r2", "r3"])
    
    def test_scalar_str_unchanged(self):
        """scalar_str: 그대로 반환"""
        result = _canonicalize("hello", "scalar_str")
        self.assertEqual(result, "hello")
    
    def test_bool_unchanged(self):
        """bool: 그대로 반환"""
        self.assertEqual(_canonicalize(True, "bool"), True)
        self.assertEqual(_canonicalize(False, "bool"), False)
    
    def test_none_value(self):
        """None 값 처리"""
        result = _canonicalize(None, "set_str")
        self.assertIsNone(result)


class TestValidateAnswer(unittest.TestCase):
    """validate_answer 함수 테스트"""
    
    def test_set_str_valid(self):
        """set_str: 유효한 문자열 배열"""
        is_valid, error = validate_answer(["a", "b"], "set_str")
        self.assertTrue(is_valid)
        self.assertEqual(error, "")
    
    def test_set_str_invalid_type(self):
        """set_str: 잘못된 타입"""
        is_valid, error = validate_answer("not a list", "set_str")
        self.assertFalse(is_valid)
    
    def test_map_str_int_valid(self):
        """map_str_int: 유효한 맵"""
        is_valid, error = validate_answer({"a": 1, "b": 2}, "map_str_int")
        self.assertTrue(is_valid)
    
    def test_bool_valid(self):
        """bool: 유효한 boolean"""
        is_valid, error = validate_answer(True, "bool")
        self.assertTrue(is_valid)
    
    def test_bool_invalid_string(self):
        """bool: 문자열은 무효"""
        is_valid, error = validate_answer("true", "bool")
        self.assertFalse(is_valid)
    
    def test_path_valid(self):
        """path: 유효한 경로"""
        is_valid, error = validate_answer(["r1", "r2", "r3"], "path")
        self.assertTrue(is_valid)
    
    def test_unknown_type_passes(self):
        """알 수 없는 타입은 통과"""
        is_valid, error = validate_answer("anything", "unknown_type")
        self.assertTrue(is_valid)


class TestBuildEvidence(unittest.TestCase):
    """_build_evidence 함수 테스트"""
    
    def test_basic_evidence(self):
        """기본 evidence 생성"""
        evidence = _build_evidence("traceroute", {"src": "r1", "dst": "r2"}, "baseline")
        
        self.assertEqual(evidence["query"], "traceroute")
        self.assertEqual(evidence["params"], {"src": "r1", "dst": "r2"})
        self.assertEqual(evidence["snapshot"], "baseline")
    
    def test_no_timestamp(self):
        """timestamp가 없어야 함 (재현성)"""
        evidence = _build_evidence("test", {})
        self.assertNotIn("timestamp", evidence)
    
    def test_empty_params(self):
        """빈 파라미터"""
        evidence = _build_evidence("detectLoops", {})
        self.assertEqual(evidence["params"], {})


class TestAnswerResult(unittest.TestCase):
    """AnswerResult NamedTuple 테스트"""
    
    def test_create_ok_result(self):
        """OK 상태 결과"""
        result = AnswerResult(
            status="OK",
            value=["a", "b"],
            answer_type="set_str",
            evidence={"query": "test"},
            unknown_reason=""
        )
        self.assertEqual(result.status, "OK")
        self.assertEqual(result.value, ["a", "b"])
        self.assertEqual(result.unknown_reason, "")
    
    def test_create_unknown_result(self):
        """UNKNOWN 상태 결과"""
        result = AnswerResult(
            status="UNKNOWN",
            value=None,
            answer_type="set_str",
            evidence={},
            unknown_reason="BATFISH_QUERY_ERROR"
        )
        self.assertEqual(result.status, "UNKNOWN")
        self.assertIsNone(result.value)
        self.assertEqual(result.unknown_reason, "BATFISH_QUERY_ERROR")
    
    def test_create_not_configured_result(self):
        """NOT_CONFIGURED 상태 결과"""
        result = AnswerResult(
            status="NOT_CONFIGURED",
            value=[],
            answer_type="set_str",
            evidence={},
            unknown_reason=""
        )
        self.assertEqual(result.status, "NOT_CONFIGURED")
        self.assertEqual(result.value, [])


if __name__ == "__main__":
    # 테스트 실행
    unittest.main(verbosity=2)
