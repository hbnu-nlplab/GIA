"""
Type-aware 채점기
기존 NetConfigQA2/NetConfigQA3 평가 로직 재사용
"""
import re
import json
import ast
from typing import Any, Dict, Optional


def normalize_answer(answer: str, answer_type: str) -> str:
    """답변 정규화
    
    Args:
        answer: 원본 답변
        answer_type: 답변 타입
        
    Returns:
        정규화된 답변
    """
    if answer is None:
        return ""
    
    s = str(answer).strip()
    
    # Final Answer: 프리픽스 제거
    s = re.sub(r'^\s*final\s+answer\s*:\s*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'^\s*answer\s*:\s*', '', s, flags=re.IGNORECASE)
    s = s.strip()
    
    at = answer_type.lower()
    
    if at in ("map", "json", "dictionary", "map_str_str"):
        return _normalize_map(s)
    elif at in ("set", "list", "set_str", "list_str"):
        return _normalize_set(s)
    elif at in ("numeric", "number", "scalar_int", "int", "integer"):
        return _normalize_number(s)
    elif at == "boolean":
        return _normalize_boolean(s)
    else:  # text
        return _normalize_text(s)


def _normalize_map(s: str) -> str:
    """Map 타입 정규화"""
    # JSON 파싱 시도
    for candidate in (s, s.strip('`'), s.strip()):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                canon = {str(k): ("" if v is None else str(v)) for k, v in obj.items()}
                return json.dumps(canon, ensure_ascii=False, sort_keys=True)
        except:
            pass
    
    # Python literal 파싱 시도
    try:
        obj = ast.literal_eval(s)
        if isinstance(obj, dict):
            canon = {str(k): ("" if v is None else str(v)) for k, v in obj.items()}
            return json.dumps(canon, ensure_ascii=False, sort_keys=True)
    except:
        pass
    
    return s


def _normalize_set(s: str) -> str:
    """Set 타입 정규화"""
    # JSON 배열 파싱 시도
    for candidate in (s, s.strip('`'), s.strip()):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, list):
                canon = sorted(["" if v is None else str(v) for v in obj])
                return json.dumps(canon, ensure_ascii=False)
        except:
            pass
    
    # Python literal 파싱 시도
    try:
        obj = ast.literal_eval(s)
        if isinstance(obj, (list, tuple, set)):
            canon = sorted(["" if v is None else str(v) for v in list(obj)])
            return json.dumps(canon, ensure_ascii=False)
    except:
        pass
    
    return s


def _normalize_number(s: str) -> str:
    """Number 타입 정규화"""
    m = re.search(r'-?\d+(\.\d+)?', s)
    if not m:
        return s
    num = m.group(0)
    try:
        f = float(num)
        if f.is_integer():
            return str(int(f))
        return str(f)
    except:
        return num


def _normalize_boolean(s: str) -> str:
    """Boolean 타입 정규화"""
    lower = s.lower()
    if 'true' in lower or 'yes' in lower or lower == '1':
        return "true"
    elif 'false' in lower or 'no' in lower or lower == '0':
        return "false"
    return "false"


def _normalize_text(s: str) -> str:
    """Text 타입 정규화"""
    # 따옴표 제거
    s = s.strip('"\'')
    # 소문자 변환 (대소문자 무시 비교용)
    return s.lower().strip()


class TypeAwareScorer:
    """Type-aware 채점기"""
    
    def score(
        self,
        pred: str,
        gold: str,
        answer_type: str,
    ) -> Dict[str, Any]:
        """답변 채점
        
        Args:
            pred: 예측 답변
            gold: 정답
            answer_type: 답변 타입
            
        Returns:
            채점 결과 딕셔너리
        """
        # 정규화
        pred_norm = normalize_answer(pred, answer_type)
        gold_norm = normalize_answer(gold, answer_type)
        
        at = answer_type.lower()
        
        # 타입별 비교
        if at in ("map", "json", "dictionary", "map_str_str"):
            is_correct = self._compare_map(pred_norm, gold_norm)
        elif at in ("set", "list", "set_str", "list_str"):
            is_correct = self._compare_set(pred_norm, gold_norm)
        elif at in ("numeric", "number", "scalar_int", "int", "integer"):
            is_correct = self._compare_number(pred_norm, gold_norm)
        elif at == "boolean":
            is_correct = pred_norm == gold_norm
        else:  # text
            is_correct = pred_norm == gold_norm
        
        return {
            "is_correct": is_correct,
            "score": 1.0 if is_correct else 0.0,
            "pred": pred,
            "gold": gold,
            "pred_normalized": pred_norm,
            "gold_normalized": gold_norm,
            "answer_type": answer_type,
        }
    
    def _compare_map(self, pred: str, gold: str) -> bool:
        """Map 비교"""
        try:
            pred_dict = json.loads(pred)
            gold_dict = json.loads(gold)
            return pred_dict == gold_dict
        except:
            return pred == gold
    
    def _compare_set(self, pred: str, gold: str) -> bool:
        """Set 비교 (순서 무관)"""
        try:
            pred_list = json.loads(pred)
            gold_list = json.loads(gold)
            return set(pred_list) == set(gold_list)
        except:
            return pred == gold
    
    def _compare_number(self, pred: str, gold: str) -> bool:
        """Number 비교"""
        try:
            pred_num = float(pred)
            gold_num = float(gold)
            # 부동소수점 허용오차
            return abs(pred_num - gold_num) < 1e-6
        except:
            return pred == gold


# 싱글톤 인스턴스
scorer = TypeAwareScorer()


def score(pred: str, gold: str, answer_type: str) -> Dict[str, Any]:
    """편의 함수"""
    return scorer.score(pred, gold, answer_type)


if __name__ == "__main__":
    # 테스트
    test_cases = [
        ("p1", "p1", "text"),
        ("5", "5", "numeric"),
        ('["a", "b"]', '["b", "a"]', "set"),
        ('{"k1": "v1"}', '{"k1": "v1"}', "map"),
        ("true", "True", "boolean"),
    ]
    
    for pred, gold, at in test_cases:
        result = score(pred, gold, at)
        print(f"[{at}] pred='{pred}' gold='{gold}' → {result['is_correct']}")
