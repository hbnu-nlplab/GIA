from __future__ import annotations
from typing import Dict, Any, List

_semantic_map = {
    "idle": {"down", "끊김", "비정상", "idle"},
    "established": {"up", "정상", "유지", "established"},
    # boolean truthy/falsy 확장
    "true": {"예", "참", "활성", "켜짐", "true", "있음", "존재", "yes", "present", "available"},
    "false": {"아니오", "거짓", "비활성", "꺼짐", "false", "없음", "무", "none", "no", "not present", "존재하지 않음"},
}

class IntentInspector:
    def inspect(self, tests_by_cat: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        for cat, arr in (tests_by_cat or {}).items():
            for t in arr:
                t.setdefault("verification", {})
                t["verification"].setdefault("status", "PASS")
                t["verification"].setdefault("needs_review", False)
                self._auto_tag_difficulty_and_type(t)
        return tests_by_cat

    def _normalize_scalar(self, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, bool):
            return "true" if v else "false"
        return str(v).strip().lower()

    def _normalize_collection(self, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, dict):
            return [self._normalize_scalar(k)+":"+self._normalize_scalar(v.get(k)) for k in sorted(v.keys())]
        if isinstance(v, (list, set, tuple)):
            return sorted([self._normalize_scalar(x) for x in v])
        return [self._normalize_scalar(v)]

    def _semantic_alias(self, s: str) -> str:
        s = s.strip().lower()
        for k, al in _semantic_map.items():
            if s in al:
                return k
        return s

    def _boolean_like(self, s: str) -> str | None:
        s2 = self._semantic_alias(s)
        if s2 in ("true", "false"):
            return s2
        return None

    def _to_number(self, x: Any) -> float | None:
        try:
            if isinstance(x, (int, float)):
                return float(x)
            xs = self._normalize_scalar(x)
            if xs in ("",):
                return None
            return float(xs)
        except Exception:
            return None

    def _match_boolean_to_numeric_or_collection(self, bool_text: str, gt_value: Any) -> bool:
        # true ↔ (numeric>0 or len(collection)>0), false ↔ (==0 or empty)
        truthy = (bool_text == "true")
        if isinstance(gt_value, (int, float)):
            return (gt_value > 0) if truthy else (gt_value == 0)
        if isinstance(gt_value, (list, set, tuple, dict)):
            ln = len(gt_value.keys() if isinstance(gt_value, dict) else gt_value)
            return (ln > 0) if truthy else (ln == 0)
        return self._normalize_scalar(gt_value) == bool_text

    def _iter_cited_values(self, cited_values: Any):
        if cited_values is None:
            return []
        if isinstance(cited_values, dict):
            return list(cited_values.values())
        if isinstance(cited_values, (list, tuple, set)):
            return list(cited_values)
        return [cited_values]

    def compare_answers(self, predicted_answer: Any, ground_truth_value: Any, cited_values: Any | None = None) -> bool:
        # 1) cited_values 우선 비교 (타입 관대)
        for cv in self._iter_cited_values(cited_values):
            try:
                # 불리언 의미어 처리("없음" → false)
                bt = self._boolean_like(self._normalize_scalar(cv))
                if bt is not None:
                    if self._match_boolean_to_numeric_or_collection(bt, ground_truth_value):
                        return True
                # 수치값 처리
                num = self._to_number(cv)
                if num is not None:
                    if isinstance(ground_truth_value, (int, float)):
                        if float(ground_truth_value) == num:
                            return True
                    elif isinstance(ground_truth_value, (list, set, tuple, dict)):
                        ln = len(ground_truth_value.keys() if isinstance(ground_truth_value, dict) else ground_truth_value)
                        if float(ln) == num:
                            return True
                # 컬렉션 동치 비교
                if isinstance(ground_truth_value, (list, set, tuple, dict)) or isinstance(cv, (list, set, tuple, dict)):
                    if self._normalize_collection(cv) == self._normalize_collection(ground_truth_value):
                        return True
                # 스칼라 동치 비교
                if self._normalize_scalar(cv) == self._normalize_scalar(ground_truth_value):
                    return True
            except Exception:
                continue

        # 2) 일반 비교
        try:
            import json as _json
            if isinstance(predicted_answer, str):
                ps = predicted_answer.strip()
                try:
                    pred = _json.loads(ps)
                except Exception:
                    pred = ps
            else:
                pred = predicted_answer
        except Exception:
            pred = predicted_answer

        # 컬렉션 비교
        if isinstance(ground_truth_value, (list, set, tuple, dict)) or isinstance(pred, (list, set, tuple, dict)):
            return self._normalize_collection(pred) == self._normalize_collection(ground_truth_value)
        # 불리언 텍스트 ↔ 수치/집합 길이 매핑
        bt = self._boolean_like(self._normalize_scalar(pred))
        if bt is not None:
            return self._match_boolean_to_numeric_or_collection(bt, ground_truth_value)
        # 스칼라 비교 + 의미 매핑
        a = self._semantic_alias(self._normalize_scalar(pred))
        b = self._semantic_alias(self._normalize_scalar(ground_truth_value))
        return a == b

    def _auto_tag_difficulty_and_type(self, t: Dict[str, Any]) -> None:
        q = (t.get("question") or "").lower()
        intent = t.get("intent") or {}
        sim = intent.get("simulation_conditions") or []
        expected_error = intent.get("expected_error")
        tags = set(t.get("tags") or [])
        if expected_error:
            tags.add("adversarial")
        elif sim:
            tags.add("inferential")
        else:
            tags.add("factual")
        if "모든" in q or "전체" in q or expected_error or sim:
            t["level"] = max(3, int(t.get("level") or 3))
        else:
            t["level"] = t.get("level") or 1
        t["tags"] = sorted(tags)

    def validate_llm(self, facts: Any, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        from utils.builder_core import execute_intent
        validated: List[Dict[str, Any]] = []
        for idx, it in enumerate(items or []):
            intent = (it or {}).get("intent")
            hypo = (it or {}).get("hypothesis") or {}
            question = (hypo or {}).get("question")
            if not intent or not question:
                continue
            try:
                gt = execute_intent(intent, facts)
                cited = None
                if isinstance(hypo, dict):
                    cited = hypo.get("cited_values")
                is_error = (gt.get("answer_type") == "error") or isinstance(gt.get("value"), dict) and gt.get("value", {}).get("error")
                ok = False if is_error else self.compare_answers(hypo.get("predicted_answer"), gt.get("value"), cited_values=cited)
                test = {
                    "category": "LLM_Exploration",
                    "origin": "LLM_Explorer",
                    "question": question,
                    "level": 3,
                    "test_id": f"LLM-{idx+1:03d}",
                    "expected_answer": {"value": gt.get("value")},
                    "answer_type": gt.get("answer_type"),
                    "verification": {"status": "PASS" if ok else "FAIL", "needs_review": (not ok)},
                    "intent": intent,
                    "hypothesis": hypo,
                }
                self._auto_tag_difficulty_and_type(test)
                validated.append(test)
            except Exception:
                continue
        return validated
