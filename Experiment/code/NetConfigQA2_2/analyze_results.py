"""
NetConfigQA Result Analyzer (Scoring Only)

이 스크립트는 run_netconfigqa_eval_vllm.py의 raw 결과를 분석합니다:
- 예측 전처리 (think 태그 제거, 정규화)
- 점수 계산 (answer_type별)
- 통계 분석
- Markdown/JSON 채점표 생성

시각화는 별도로 Figure.py에서 수행합니다.
"""

import json
import re
import os
import argparse
import csv
from pathlib import Path
from typing import Any, Dict, List, Set
from collections import defaultdict
from datetime import datetime


# Network domain labels for answer types (RFC 6020 YANG / RFC 2578 SNMP)
ANSWER_TYPE_LABEL = {
    "text": "Scalar Attribute",
    "scalar_str": "Scalar Attribute",
    "scalar_int": "Scalar Counter",
    "number": "Scalar Counter",
    "numeric": "Scalar Counter",
    "set_str": "Resource Inventory",
    "set": "Resource Inventory",
    "edge_set": "Resource Inventory",
    "bool": "Configuration State",
    "boolean": "Configuration State",
    "path": "Forwarding Sequence",
    "map_str_str": "Property Table",
    "map_str_int": "Metric Table",
    "map": "Property Table",
    "json": "Property Table",
}


# Unified alias dict — keep in sync with ground_truth_contracts._CANONICAL_TYPE_ALIASES
_CANONICAL_ALIASES = {
    # number
    'numeric': 'number', 'num': 'number', 'numbers': 'number',
    'int': 'number', 'integer': 'number', 'float': 'number', 'scalar_int': 'number',
    # set
    'list_str': 'set', 'set_str': 'set', 'edge_set': 'set', 'set_string': 'set', 'list': 'set',
    # map
    'dict': 'map', 'map_str_str': 'map', 'map_str_int': 'map', 'json': 'map',
    # text
    'scalar_str': 'text', 'enum': 'text',
    # boolean
    'bool': 'boolean', 'boolean': 'boolean',
    # path (identity)
    'path': 'path',
}


def display_answer_type(answer_type: str) -> str:
    """Normalize answer types for reporting while preserving numeric vs number split."""
    if answer_type is None:
        return "text"
    atype = str(answer_type).strip().lower()
    if atype == "numeric":
        return "numeric"
    if atype in {"num", "numbers", "int", "integer", "float", "scalar_int", "number"}:
        return "number"
    if atype in {"list_str", "set_str", "edge_set", "set_string", "list", "set"}:
        return "set"
    if atype in {"dict", "map_str_str", "map_str_int", "json", "map"}:
        return "map"
    if atype in {"scalar_str", "enum", "text"}:
        return "text"
    if atype in {"bool", "boolean"}:
        return "boolean"
    if atype == "path":
        return "path"
    return canonical_answer_type(atype)


def canonical_answer_type(answer_type: str) -> str:
    """Normalize answer_type values to a canonical set used by the scorer/reports.

    Canonical set: {text, number, set, map, boolean, path}
    Source of truth: Make_Dataset/src/ground_truth_contracts.py (_CANONICAL_TYPE_ALIASES)
    """
    if answer_type is None:
        return 'text'
    atype = str(answer_type).strip().lower()
    return _CANONICAL_ALIASES.get(atype, atype)

# Traditional metrics
try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    ROUGE_AVAILABLE = False
    print("[WARNING] rouge-score not available. Install with: pip install rouge-score")

try:
    from bert_score import score as bert_score
    BERTSCORE_AVAILABLE = True
except ImportError:
    BERTSCORE_AVAILABLE = False
    print("[WARNING] bert-score not available. Install with: pip install bert-score")

try:
    import nltk
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    print("[WARNING] nltk not available. Install with: pip install nltk")

try:
    import torch
except ImportError:
    torch = None


# ==================== Traditional Metrics Calculator ====================

class TraditionalMetricsCalculator:
    """Calculate traditional NLP evaluation metrics."""
    
    def __init__(self):
        self.rouge_scorer = None
        if ROUGE_AVAILABLE:
            self.rouge_scorer = rouge_scorer.RougeScorer(
                ['rouge1', 'rouge2', 'rougeL'], 
                use_stemmer=True
            )
    
    def normalize_text(self, text: str) -> str:
        """Normalize text for fair comparison."""
        text = text.lower().strip()
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        return text
    
    def calculate_exact_match(self, pred: str, gold: str) -> float:
        """Exact Match: 1.0 if exactly same, 0.0 otherwise."""
        pred_norm = self.normalize_text(pred)
        gold_norm = self.normalize_text(gold)
        return 1.0 if pred_norm == gold_norm else 0.0
    
    def calculate_token_f1(self, pred: str, gold: str) -> Dict[str, float]:
        """Token-level F1 score."""
        pred_tokens = set(self.normalize_text(pred).split())
        gold_tokens = set(self.normalize_text(gold).split())
        
        if not gold_tokens and not pred_tokens:
            return {"token_f1": 1.0, "token_precision": 1.0, "token_recall": 1.0}
        if not gold_tokens or not pred_tokens:
            return {"token_f1": 0.0, "token_precision": 0.0, "token_recall": 0.0}
        
        common = pred_tokens & gold_tokens
        precision = len(common) / len(pred_tokens) if pred_tokens else 0.0
        recall = len(common) / len(gold_tokens) if gold_tokens else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "token_f1": f1,
            "token_precision": precision,
            "token_recall": recall
        }
    
    def calculate_rouge(self, pred: str, gold: str) -> Dict[str, float]:
        """Calculate ROUGE-1, ROUGE-2, ROUGE-L scores."""
        if not ROUGE_AVAILABLE or not self.rouge_scorer:
            return {
                "rouge1": None,
                "rouge2": None,
                "rougeL": None
            }
        
        try:
            scores = self.rouge_scorer.score(gold, pred)
            return {
                "rouge1": scores['rouge1'].fmeasure,
                "rouge2": scores['rouge2'].fmeasure,
                "rougeL": scores['rougeL'].fmeasure
            }
        except:
            return {"rouge1": None, "rouge2": None, "rougeL": None}
    
    def calculate_bleu(self, pred: str, gold: str) -> float:
        """Calculate BLEU score."""
        if not NLTK_AVAILABLE:
            return None
        
        pred_tokens = self.normalize_text(pred).split()
        gold_tokens = [self.normalize_text(gold).split()]
        
        if not pred_tokens or not gold_tokens[0]:
            return 0.0
            
        try:
            # Use smoothing to avoid 0.0 for short sequences
            smooth = SmoothingFunction().method1
            return sentence_bleu(gold_tokens, pred_tokens, smoothing_function=smooth)
        except:
            return 0.0
    
    def calculate_all(self, pred: str, gold: str) -> Dict[str, float]:
        """Calculate all traditional metrics (except BERTScore which should be batched)."""
        metrics = {}
        
        # Exact Match
        metrics['exact_match'] = self.calculate_exact_match(pred, gold)
        
        # Token F1
        token_metrics = self.calculate_token_f1(pred, gold)
        metrics.update(token_metrics)
        
        # ROUGE
        rouge_metrics = self.calculate_rouge(pred, gold)
        metrics.update(rouge_metrics)

        # BLEU
        metrics['bleu'] = self.calculate_bleu(pred, gold)
        
        return metrics


# ==================== Scorer ====================

class NetConfigQAScorer:
    """Handles scoring based on answer types."""

    def __init__(self):
        self.warnings: List[Dict[str, str]] = []
        self.explicit_negative_token = "NOT_CONFIGURED"
    
    def clean_prediction(self, pred: str, answer_type: str = None) -> str:
        """
        Clean model prediction — minimal, language-neutral.

        Strategy:
        1. Remove reasoning tokens (<think>...</think>) if present
        2. Take first non-empty line (answer should be one line)
        3. Strip markdown code blocks and quotes
        4. Normalize nulls
        """
        if not pred:
            return ""

        answer_type = canonical_answer_type(answer_type)

        # 1. Remove reasoning tokens (model-specific patterns)
        # GPT-OSS-20B: "analysis...reasoning...assistantfinal ANSWER"
        if 'assistantfinal' in pred:
            pred = pred.split('assistantfinal')[-1].strip()
        # Qwen/GLM: "<think>...reasoning...</think> ANSWER"
        elif '</think>' in pred:
            pred = pred.split('</think>')[-1].strip()
        elif '<think>' in pred:
            pred = pred.split('<think>')[0].strip()
        # reasoning delimiter 없이 폭주한 경우 → 답변 추출 불가
        elif pred.lstrip().startswith('analysis') or len(pred) > 5000:
            pred = ""

        # 2. Strip markdown code blocks (```...```)
        pred = re.sub(r'```[\s\S]*?```', '', pred).strip()

        # 3. Handle multi-line vs single-line answers
        # If the answer starts with [ or {, it might be multi-line JSON — keep it whole
        stripped = pred.strip()
        if stripped.startswith('[') or stripped.startswith('{'):
            # JSON answer: collapse to single line
            pred = ' '.join(l.strip() for l in pred.split('\n') if l.strip())
        else:
            # Non-JSON: take first non-empty line
            lines = [l.strip() for l in pred.split('\n') if l.strip()]
            if not lines:
                return ""
            pred = lines[0]

        # 4. Remove common answer prefixes
        prefix_patterns = [
            r'^the answer is[:\s]*',
            r'^answer[:\s]*',
            r'^result[:\s]*',
            r'^\**answer\**[:\s]*',
        ]
        for pattern in prefix_patterns:
            pred = re.sub(pattern, '', pred, flags=re.IGNORECASE).strip()

        # 5. Unquote (balanced quotes only)
        if len(pred) >= 2 and pred[0] == pred[-1] and pred[0] in ('"', "'"):
            pred = pred[1:-1]

        # 6. Normalize explicit negative answers, but do not reward blank output.
        if pred.lower() in ['null', 'none', 'n/a', 'not configured', 'not_configured', '미설정']:
            pred = self.explicit_negative_token

        return pred.strip()

    def clean_gold(self, gold: str, status: str = "OK") -> str:
        """Clean gold answer with same normalization as prediction."""
        gold = str(gold).strip()

        if str(status).strip().upper() == "NOT_CONFIGURED":
            return self.explicit_negative_token
        
        # Unquote gold
        if len(gold) >= 2 and ((gold.startswith('"') and gold.endswith('"')) or \
                               (gold.startswith("'") and gold.endswith("'"))):
            gold = gold[1:-1]
            
        return gold

    def _score_negative_abstention(self, pred: str) -> Dict[str, float]:
        pred_norm = pred.strip().lower().replace("-", "_").replace(" ", "_")
        if pred_norm == "not_configured":
            return {"score": 1.0, "detail": "explicit_not_configured"}
        return {"score": 0.0, "detail": "missing_explicit_not_configured"}

    def _is_explicit_not_configured(self, pred: str) -> bool:
        pred_norm = str(pred or "").strip().lower().replace("-", "_").replace(" ", "_")
        return pred_norm == "not_configured"

    def _unwrap_raw_gold(self, gold_raw: str) -> Any:
        text = str(gold_raw).strip()
        try:
            return json.loads(text)
        except Exception:
            pass

        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            text = text[1:-1]
        return text

    def evaluate_negative_prediction(self, pred: str, gold_raw: str, answer_type: str) -> Dict[str, Any]:
        """Evaluate negative samples with strict and relaxed views.

        Strict:
        - exact canonical token `NOT_CONFIGURED`

        Relaxed semantic-negative:
        - exact canonical token, or
        - a non-blank prediction that matches the dataset's raw negative form
          in a type-aware manner (e.g. [] / {} / 0 / "Disabled")
        """
        answer_type = canonical_answer_type(answer_type)
        pred = str(pred or "").strip()

        explicit_abstention = self._is_explicit_not_configured(pred)
        if explicit_abstention:
            return {
                "semantic_negative_correct": True,
                "explicit_abstention_correct": True,
                "contract_compliant": True,
                "blank_prediction": False,
                "detail": "explicit_not_configured",
            }

        if not pred:
            return {
                "semantic_negative_correct": False,
                "explicit_abstention_correct": False,
                "contract_compliant": False,
                "blank_prediction": True,
                "detail": "blank_prediction",
            }

        raw_gold = self._unwrap_raw_gold(gold_raw)
        semantic_negative_correct = False
        detail = "negative_mismatch"

        # Null/empty negatives must remain explicit to avoid rewarding lookup failure.
        if raw_gold is None:
            detail = "null_negative_requires_explicit"
        elif isinstance(raw_gold, str):
            gold_text = str(raw_gold).strip()
            if not gold_text:
                detail = "empty_negative_requires_explicit"
            elif answer_type == "boolean":
                semantic_negative_correct = self._score_boolean(pred, gold_text)["score"] == 1.0
            elif answer_type == "number":
                semantic_negative_correct = self._score_numeric(pred, gold_text)["score"] == 1.0
            elif answer_type == "path":
                semantic_negative_correct = self._score_path(pred, gold_text)["score"] == 1.0
            else:
                semantic_negative_correct = self._score_text(pred, gold_text)["score"] == 1.0
            if semantic_negative_correct:
                detail = "typed_negative_match"
        elif isinstance(raw_gold, list):
            if answer_type == "path":
                if not raw_gold:
                    semantic_negative_correct = pred == "[]"
                else:
                    gold_path = " -> ".join(str(node) for node in raw_gold)
                    semantic_negative_correct = self._score_path(pred, gold_path)["score"] == 1.0
            else:
                gold_json = json.dumps(raw_gold, ensure_ascii=False)
                semantic_negative_correct = self._score_set(pred, gold_json)["score"] == 1.0
            if semantic_negative_correct:
                detail = "typed_negative_match"
        elif isinstance(raw_gold, dict):
            gold_json = json.dumps(raw_gold, ensure_ascii=False, sort_keys=True)
            semantic_negative_correct = self._score_map(pred, gold_json)["score"] == 1.0
            if semantic_negative_correct:
                detail = "typed_negative_match"
        elif isinstance(raw_gold, bool):
            semantic_negative_correct = self._score_boolean(pred, str(raw_gold).lower())["score"] == 1.0
            if semantic_negative_correct:
                detail = "typed_negative_match"
        elif isinstance(raw_gold, (int, float)) and not isinstance(raw_gold, bool):
            semantic_negative_correct = self._score_numeric(pred, str(raw_gold))["score"] == 1.0
            if semantic_negative_correct:
                detail = "typed_negative_match"

        return {
            "semantic_negative_correct": semantic_negative_correct,
            "explicit_abstention_correct": False,
            "contract_compliant": False,
            "blank_prediction": False,
            "detail": detail,
        }

    def score(self, pred: str, gold: str, answer_type: str, status: str = "OK", question_id: str = "") -> Dict[str, float]:
        """Score prediction against gold answer based on answer type.

        TA-Acc 정의 (IEEE TNMS):
        - set_str / set     → F1 Score (순서 무관)
        - path (text+arrow) → Ordered Exact Match
        - scalar_str / text → 정규화 후 Exact Match (Token F1 fallback 없음)
        - scalar_int/number → 숫자 추출 후 Exact Match
        - bool / boolean    → 정규화 비교
        - map_str_int / map → Key-Value F1
        """
        # Expects pre-cleaned pred (caller must call clean_prediction beforehand)
        answer_type = canonical_answer_type(answer_type)
        gold = self.clean_gold(gold, status=status)

        if str(status).strip().upper() == "NOT_CONFIGURED":
            return self._score_negative_abstention(pred)

        try:
            if answer_type in ["numeric", "scalar_int", "number"]:
                return self._score_numeric(pred, gold)
            elif answer_type in ["set", "set_str", "list"]:
                return self._score_set(pred, gold)
            elif answer_type in ["map", "map_str_str", "map_str_int", "dictionary", "json"]:
                return self._score_map(pred, gold, question_id=question_id)
            elif answer_type in ["boolean"]:
                return self._score_boolean(pred, gold)
            elif answer_type in ["path"]:
                return self._score_path(pred, gold)
            elif answer_type in ["text"]:
                # Path 감지 fallback: answer_type이 text인데 gold에 "->"/"→" 포함
                if "->" in gold or "→" in gold:
                    return self._score_path(pred, gold)
                return self._score_text(pred, gold)
            else:
                return self._score_text(pred, gold)
        except Exception as e:
            return {"score": 0.0, "error": str(e)}

    def _extract_number(self, val: str) -> float:
        """Extract number from string, including word-to-digit conversion."""
        try:
            # First try direct digit extraction
            match = re.search(r'-?\d+(\.\d+)?', val)
            if match:
                return float(match.group())
            
            # If no digit found, try to extract number words
            # Map of English number words to digits
            word_to_num = {
                'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4,
                'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9,
                'ten': 10, 'eleven': 11, 'twelve': 12, 'thirteen': 13,
                'fourteen': 14, 'fifteen': 15, 'sixteen': 16, 'seventeen': 17,
                'eighteen': 18, 'nineteen': 19, 'twenty': 20,
                'thirty': 30, 'forty': 40, 'fifty': 50,
                'sixty': 60, 'seventy': 70, 'eighty': 80, 'ninety': 90,
                'hundred': 100, 'thousand': 1000
            }
            
            val_lower = val.lower()
            
            # Look for patterns like "totaling five network interfaces"
            patterns = [
                r'totaling\s+(\w+)',
                r'lists\s+(\w+)',
                r'has\s+exactly\s+(\w+)',
                r'total\s+of\s+(\w+)',
                r'consists?\s+of\s+(\w+)',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, val_lower)
                if match:
                    word = match.group(1)
                    if word in word_to_num:
                        return float(word_to_num[word])
            
            # Try to find any number word in the string
            for word, num in word_to_num.items():
                if re.search(r'\b' + word + r'\b', val_lower):
                    return float(num)
            
            return None
        except:
            return None

    def _score_numeric(self, pred: str, gold: str) -> Dict[str, float]:
        p_num = self._extract_number(pred)
        g_num = self._extract_number(gold)
        if p_num is None or g_num is None:
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
        return {"score": 1.0 if p_num == g_num else 0.0}

    def _parse_set(self, val: str) -> Set[str]:
        """
        Parse set from various formats:
        - JSON array: ["item1", "item2"]
        - Set notation: {"item1", "item2"}
        - Tuple: ("item1", "item2")
        - Comma-separated: item1, item2
        """
        val = val.strip()
        
        try:
            # 1. JSON 형식 파싱 시도 (대괄호, 중괄호, 소괄호 모두 지원)
            val_normalized = val.replace("'", '"')
            if (val_normalized.startswith('[') and val_normalized.endswith(']')) or \
               (val_normalized.startswith('{') and val_normalized.endswith('}')) or \
               (val_normalized.startswith('(') and val_normalized.endswith(')')):
                # 중괄호/소괄호를 대괄호로 변환 (JSON은 array만 지원)
                val_normalized = val_normalized.replace('{', '[').replace('}', ']')
                val_normalized = val_normalized.replace('(', '[').replace(')', ']')
                items = json.loads(val_normalized)
                return set(str(i).strip().lower() for i in items)
        except:
            pass
        
        # 2. Fallback: 쉼표 구분 파싱
        # 괄호 제거 후 쉼표로 split
        val_cleaned = val.strip('[]{}()"\' ').strip()
        if ',' in val_cleaned:
            return set(i.strip().lower() for i in val_cleaned.split(',') if i.strip())
        elif val_cleaned:
            return {val_cleaned.lower()}
        
        return set()

    def _score_set(self, pred: str, gold: str) -> Dict[str, float]:
        p_set = self._parse_set(pred)
        g_set = self._parse_set(gold)
        if not g_set and not p_set:
            return {"score": 1.0, "f1": 1.0}
        
        intersection = len(p_set & g_set)
        precision = intersection / len(p_set) if p_set else 0.0
        recall = intersection / len(g_set) if g_set else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return {"score": f1, "f1": f1, "precision": precision, "recall": recall}

    def _normalize_ip_value(self, value: str) -> str:
        """
        Normalize IP address or status value for comparison.
        Removes CIDR notation if present.
        Maps 'shutdown' to 'down'.
        
        Examples:
        - "10.0.0.1/31" -> "10.0.0.1"
        - "10.0.0.1" -> "10.0.0.1"
        - "shutdown" -> "down"
        - "" -> ""
        """
        value = str(value).strip().lower()

        # Map shutdown to down (network status normalization)
        if value == 'shutdown':
            return 'down'
            
        # Remove CIDR notation (e.g., /31, /24, /32)
        if '/' in value:
            value = value.split('/')[0].strip()
        return value

    def _parse_legacy_map_text(self, pred: str, expected_keys: List[str] | None = None) -> Dict[str, Any] | None:
        text = str(pred).strip()
        if not text:
            return None

        # Special fallback for structured compare maps (host1_count, host2_count, difference)
        if expected_keys and set(expected_keys) == {"host1_count", "host2_count", "difference"}:
            numbers = re.findall(r'[:=]\s*(-?\d+)', text)
            if len(numbers) < 3:
                numbers = re.findall(r'-?\d+', text)
            if len(numbers) >= 3:
                return {
                    "host1_count": int(numbers[0]),
                    "host2_count": int(numbers[1]),
                    "difference": int(numbers[2]),
                }

        # Generic key:value extraction
        pairs = re.findall(r'([A-Za-z0-9_./-]+)\s*[:=]\s*([A-Za-z0-9_./-]+)', text)
        if pairs:
            obj: Dict[str, Any] = {}
            for k, v in pairs:
                if re.fullmatch(r'-?\d+', v):
                    obj[k] = int(v)
                else:
                    obj[k] = v
            if obj:
                return obj

        return None

    def _coerce_to_gold_type(self, pred_value: Any, gold_value: Any) -> Any:
        if isinstance(gold_value, bool):
            if isinstance(pred_value, bool):
                return pred_value
            sval = str(pred_value).strip().lower()
            if sval in {"true", "1", "yes"}:
                return True
            if sval in {"false", "0", "no"}:
                return False
            return pred_value
        if isinstance(gold_value, int) and not isinstance(gold_value, bool):
            if isinstance(pred_value, int):
                return pred_value
            if isinstance(pred_value, float) and pred_value.is_integer():
                return int(pred_value)
            sval = str(pred_value).strip()
            if re.fullmatch(r'-?\d+', sval):
                return int(sval)
            return pred_value
        if isinstance(gold_value, float):
            try:
                return float(pred_value)
            except Exception:
                return pred_value
        # string-like fallback
        return self._normalize_ip_value(str(pred_value))
    
    def _score_map(self, pred: str, gold: str, question_id: str = "") -> Dict[str, float]:
        """
        Score map answers with Key-Value F1.
        논문 정의: map_str_int → Key-Value F1
        (key, value) 쌍을 원소로 보고 precision/recall/F1 계산.
        """
        legacy_fallback_used = False
        try:
            g_obj = json.loads(gold.replace("'", '"'))
        except Exception:
            g_obj = self._parse_legacy_map_text(gold, expected_keys=None)
            if g_obj is None:
                return {"score": 0.0, "parse_error": "gold_map_unparseable"}

        try:
            p_obj = json.loads(pred.replace("'", '"'))
        except Exception:
            p_obj = self._parse_legacy_map_text(pred, expected_keys=list(g_obj.keys()) if isinstance(g_obj, dict) else None)
            legacy_fallback_used = p_obj is not None

        if not isinstance(p_obj, dict) or not isinstance(g_obj, dict):
            return {"score": 1.0 if str(p_obj) == str(g_obj) else 0.0, "legacy_fallback_used": legacy_fallback_used}

        # Key-Value F1: (key, normalized_value) 쌍을 원소로 취급
        def normalize_kv_pair(k, v):
            if isinstance(v, str):
                return (str(k).lower(), self._normalize_ip_value(v))
            return (str(k).lower(), v)

        gold_pairs = set()
        for k, v in g_obj.items():
            gold_pairs.add(normalize_kv_pair(k, v))

        pred_pairs = set()
        for k, v in p_obj.items():
            coerced_v = self._coerce_to_gold_type(v, g_obj.get(k, v))
            pred_pairs.add(normalize_kv_pair(k, coerced_v))

        # F1 계산
        if not gold_pairs and not pred_pairs:
            f1 = 1.0
        elif not gold_pairs or not pred_pairs:
            f1 = 0.0
        else:
            intersection = len(gold_pairs & pred_pairs)
            precision = intersection / len(pred_pairs) if pred_pairs else 0.0
            recall = intersection / len(gold_pairs) if gold_pairs else 0.0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        if legacy_fallback_used:
            self.warnings.append({
                "type": "map_legacy_fallback",
                "question_id": str(question_id),
            })
        result = {"score": f1, "f1": f1, "legacy_fallback_used": legacy_fallback_used}
        if gold_pairs and pred_pairs:
            result["precision"] = len(gold_pairs & pred_pairs) / len(pred_pairs)
            result["recall"] = len(gold_pairs & pred_pairs) / len(gold_pairs)
        return result

    def _normalize_for_comparison(self, text: str) -> str:
        """
        Normalize text for comparison (language-neutral).
        No Korean/English hardcoding — pure normalization only.
        """
        import re

        text = text.lower().strip()

        # 1. Remove surrounding quotes
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            text = text[1:-1]

        # 2. Normalize whitespace
        text = re.sub(r'\s+', ' ', text)

        # 3. Normalize punctuation spacing
        text = re.sub(r'\s*:\s*', ':', text)
        text = re.sub(r'\s*,\s*', ',', text)

        # 4. Normalize arrows (network paths)
        text = text.replace('→', '->').replace('=>', '->')
        text = re.sub(r'\s*->\s*', ' -> ', text)

        # 5. Remove CIDR notation for IP comparison (10.0.0.1/31 -> 10.0.0.1)
        text = re.sub(r'(/\d{1,2})(?=\s|$|,)', '', text)

        # 6. Normalize interface shutdown status
        text = text.replace('shutdown', 'down')

        # 7. Normalize network-specific aliases
        text = text.replace('does not traverse', 'not_traversed')
        text = text.replace('not traversed', 'not_traversed')
        text = text.replace('traversed', 'traversed')

        # 8. Normalize Korean→English network patterns
        # "X에서 NO_ROUTE" → "no_route at X"
        import re as _re
        text = _re.sub(r'(\w+)에서\s+no_route', r'no_route at \1', text)
        text = _re.sub(r'(\w+)에서\s+no route', r'no_route at \1', text)

        # 9. Normalize "not configured" variants
        # "None", "null", "not configured", "n/a", "none" → all same
        _nc_patterns = {'none', 'null', 'n/a', 'not configured', 'not_configured', 'na', 'no',
                        'not applicable', 'not set', 'disabled'}
        if text in _nc_patterns:
            text = 'n/a'

        # 10. Normalize single-element array to scalar
        # '["65000"]' → '65000', '[0]' → '0'
        m = _re.fullmatch(r'\[\s*"?([^"\[\]]+)"?\s*\]', text)
        if m:
            text = m.group(1).strip()

        # 11. Strip Cisco IOS config line prefixes → extract value only
        # "transport input ssh" → "ssh"
        # "login local" → "local"
        # "service password-encryption" → "enabled"
        _cfg_prefixes = [
            (r'^transport input\s+', ''),
            (r'^login\s+', ''),
            (r'^logging buffered \d+\s+', ''),  # "logging buffered 51200 warnings" → "warnings"
        ]
        for pattern, repl in _cfg_prefixes:
            new_text = _re.sub(pattern, repl, text)
            if new_text != text:
                text = new_text
                break

        return text.strip()

    def _score_text(self, pred: str, gold: str) -> Dict[str, float]:
        """
        Score text answers using Normalized Exact Match only.
        논문 정의: scalar_str → 정규화 후 Exact Match
        Token F1 fallback 제거 (점수 과대 평가 방지)
        """
        # Handle 'false' or '0' which some models use for NOT_CONFIGURED text fields
        if pred.lower() in ['false', '0']:
            pred = ""

        # Apply normalization (number extraction + synonym mapping)
        pred_norm = self._normalize_for_comparison(pred)
        gold_norm = self._normalize_for_comparison(gold)

        # Both empty = match (NOT_CONFIGURED case)
        if not gold_norm and not pred_norm:
            return {"score": 1.0}

        # Normalized Exact Match only
        if pred_norm == gold_norm:
            return {"score": 1.0}

        return {"score": 0.0}

    def _score_boolean(self, pred: str, gold: str) -> Dict[str, float]:
        """
        Score boolean answers with normalization.
        논문 정의: bool → 정규화 비교
        """
        TRUTHY = {"true", "yes", "1", "예", "enabled", "up", "configured", "active", "established"}
        FALSY = {"false", "no", "0", "아니오", "disabled", "down", "not configured", "inactive"}

        pred_lower = pred.strip().lower()
        gold_lower = gold.strip().lower()

        pred_bool = True if pred_lower in TRUTHY else (False if pred_lower in FALSY else None)
        gold_bool = True if gold_lower in TRUTHY else (False if gold_lower in FALSY else None)

        if pred_bool is None or gold_bool is None:
            # 파싱 불가 시 text EM fallback
            return {"score": 1.0 if pred_lower == gold_lower else 0.0}

        return {"score": 1.0 if pred_bool == gold_bool else 0.0}

    def _score_path(self, pred: str, gold: str) -> Dict[str, float]:
        """
        Score path answers with Ordered Exact Match.
        논문 정의: path → Ordered Exact Match
        노드 시퀀스를 추출하여 순서까지 비교.
        """
        def extract_nodes(text: str) -> List[str]:
            """경로 문자열에서 노드 시퀀스 추출"""
            # 화살표 통일
            text = text.replace("→", "->").replace("=>", "->")
            # 따옴표 제거
            text = text.strip().strip('"\'')
            # "->" 로 split
            if "->" in text:
                nodes = [n.strip().lower() for n in text.split("->") if n.strip()]
            else:
                stripped = text.strip().lower()
                nodes = [stripped] if stripped else []
            return nodes

        pred_nodes = extract_nodes(pred)
        gold_nodes = extract_nodes(gold)

        # Both empty
        if not gold_nodes and not pred_nodes:
            return {"score": 1.0}

        # Ordered exact match
        if pred_nodes == gold_nodes:
            return {"score": 1.0}

        return {"score": 0.0}


# ==================== Markdown Report Generator ====================

class ScorecardGenerator:
    """Generates Markdown scorecard from analysis results."""
    
    def generate(self, stats: dict, meta: dict, error_samples: list = None) -> str:
        """Generate a comprehensive Markdown scorecard."""
        def fmt_pct(value) -> str:
            return "N/A" if value is None else f"{value*100:.2f}%"

        def fmt_seconds(value) -> str:
            try:
                if value is None:
                    return "N/A"
                return f"{float(value):.1f}s"
            except (TypeError, ValueError):
                return "N/A"

        lines = []
        
        # Header
        model_name = meta.get("model", "Unknown Model")
        lines.append(f"# NetConfigQA Evaluation Scorecard\n")
        lines.append(f"> **Model**: `{model_name}`  ")
        lines.append(f"> **Date**: {meta.get('date', datetime.now().isoformat())}  ")
        lines.append(f"> **Dataset**: `{meta.get('dataset', 'Unknown')}`\n")
        
        
        # Overall Score with all metrics
        lines.append("## 📊 Overall Performance\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Type-Aware Accuracy** | **{stats['accuracy']*100:.2f}%** |")
        
        trad_metrics = stats.get('traditional_metrics', {})
        lines.append(f"| Exact Match (EM) | {fmt_pct(trad_metrics.get('exact_match'))} |")
        lines.append(f"| Token F1 | {fmt_pct(trad_metrics.get('token_f1'))} |")
        lines.append(f"| BLEU | {fmt_pct(trad_metrics.get('bleu'))} |")
        lines.append(f"| BERTScore F1 | {fmt_pct(trad_metrics.get('bertscore_f1'))} |")
        lines.append(f"| ROUGE-L | {fmt_pct(trad_metrics.get('rougeL'))} |")
        lines.append(f"| ROUGE-1 | {fmt_pct(trad_metrics.get('rouge1'))} |")
        lines.append(f"| ROUGE-2 | {fmt_pct(trad_metrics.get('rouge2'))} |")
        lines.append(f"| Total Samples | {stats['total_samples']} |")
        lines.append(f"| Inference Time | {fmt_seconds(meta.get('duration_sec', meta.get('duration', 0)))} |")
        lines.append("")

        # Positive / Negative testing emphasis for paper reporting
        lines.append("## 🎯 Hallucination-Sensitive Evaluation\n")
        lines.append("| Slice | Meaning | Accuracy |")
        lines.append("|-------|---------|----------|")
        ok_acc = stats.get('by_status', {}).get('OK')
        neg_acc = stats.get('by_status', {}).get('NOT_CONFIGURED')
        negative_eval = stats.get('negative_eval', {})
        semantic_neg_acc = negative_eval.get('semantic_negative_accuracy')
        explicit_neg_acc = negative_eval.get('explicit_abstention_accuracy', neg_acc)
        contract_compliance = negative_eval.get('contract_compliance')
        lines.append(f"| Positive (OK) | Configured facts / values that should be extracted | {fmt_pct(ok_acc)} |")
        lines.append(f"| Explicit Abstention (Strict) | Negative samples answered with exact `NOT_CONFIGURED` | {fmt_pct(explicit_neg_acc)} |")
        lines.append(f"| Semantic Negative (Relaxed) | Metric-consistent negative form accepted; blank outputs remain wrong | {fmt_pct(semantic_neg_acc)} |")
        lines.append(f"| Contract Compliance | Fraction of semantic negatives that used canonical `NOT_CONFIGURED` | {fmt_pct(contract_compliance)} |")
        if ok_acc is not None and explicit_neg_acc is not None:
            gap = ok_acc - explicit_neg_acc
            lines.append(f"| Gap (OK - Strict Negative) | Hallucination sensitivity gap | {gap*100:.2f}%p |")
        lines.append("")
        lines.append(
            "> `Explicit Abstention (Strict)` requires the exact token `NOT_CONFIGURED`. "
            "`Semantic Negative (Relaxed)` accepts metric-consistent negative forms such as `[]`, `{}`, `0`, or `Disabled`, "
            "but never rewards blank outputs. `Contract Compliance` measures how often semantically-correct negative answers "
            "also obey the canonical output contract.\n"
        )
        
        # Metric Comparison by Answer Type
        lines.append("## 📊 Metric Comparison by Answer Type\n")
        lines.append("| Metric | Number | Numeric | Set | Map | Text | **Overall** |")
        lines.append("|--------|--------|---------|-----|-----|------|-------------|")
        lines.append("\n> Note: `Number`는 주로 정수/카운트(개수) 유형, `Numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.\n")
        
        # Type-Aware row
        ta_row = "| **Type-Aware** |"
        for atype in ['number', 'numeric', 'set', 'map', 'text']:
            ta_val = stats['by_type'].get(atype)
            ta_row += f" {('N/A' if ta_val is None else f'{ta_val*100:.1f}%')} |"
        ta_row += f" **{stats['accuracy']*100:.1f}%** |"
        lines.append(ta_row)
        
        # Traditional metrics rows
        trad_by_type = stats.get('trad_by_type', {})
        for metric_name, metric_label in [
            ('exact_match', 'Exact Match'),
            ('token_f1', 'Token F1'),
            ('bertscore_f1', 'BERTScore F1'),
            ('rougeL', 'ROUGE-L')
        ]:
            row = f"| {metric_label} |"
            for atype in ['number', 'numeric', 'set', 'map', 'text']:
                val = trad_by_type.get(atype, {}).get(metric_name)
                row += f" {('N/A' if val is None else f'{val*100:.1f}%')} |"
            overall_val = trad_metrics.get(metric_name)
            row += f" {('N/A' if overall_val is None else f'{overall_val*100:.1f}%')} |"
            lines.append(row)
        
        lines.append("")
        
        # By Level
        lines.append("## 📈 Type-Aware Accuracy by Difficulty Level\n")
        lines.append("| Level | Description | Accuracy | Status |")
        lines.append("|-------|-------------|----------|--------|")
        level_desc = {
            'L1': 'Single Device Extraction',
            'L2': 'Multi-Device Aggregation',
            'L3': 'Cross-Device Comparison',
            'L4': 'Reachability Analysis',
            'L5': 'What-If Analysis'
        }
        for level in ['L1', 'L2', 'L3', 'L4', 'L5']:
            acc = stats['by_level'].get(level, 0) * 100
            desc = level_desc.get(level, '')
            status = "✅" if acc >= 70 else "⚠️" if acc >= 40 else "❌"
            lines.append(f"| {level} | {desc} | {acc:.1f}% | {status} |")
        lines.append("")
        
        # By Answer Type
        lines.append("## 📝 Accuracy by Answer Type\n")
        lines.append("| Type | Label | Accuracy |")
        lines.append("|------|-------|----------|")
        for atype, acc in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
            label = ANSWER_TYPE_LABEL.get(canonical_answer_type(atype), atype)
            lines.append(f"| {atype} | {label} | {acc*100:.1f}% |")
        lines.append("")
        
        # By Status (Positive/Negative Testing)
        lines.append("## 🔬 Positive vs Negative Testing\n")
        lines.append("| Test Type | Accuracy |")
        lines.append("|-----------|----------|")
        lines.append(f"| Positive (OK) | {ok_acc*100:.1f}% |" if ok_acc is not None else "| Positive (OK) | N/A |")
        lines.append(
            f"| Explicit Abstention (Strict) | {explicit_neg_acc*100:.1f}% |"
            if explicit_neg_acc is not None else "| Explicit Abstention (Strict) | N/A |"
        )
        lines.append(
            f"| Semantic Negative (Relaxed) | {semantic_neg_acc*100:.1f}% |"
            if semantic_neg_acc is not None else "| Semantic Negative (Relaxed) | N/A |"
        )
        lines.append(
            f"| Contract Compliance | {contract_compliance*100:.1f}% |"
            if contract_compliance is not None else "| Contract Compliance | N/A |"
        )
        lines.append("")
        
        # Error Analysis (if provided)
        if error_samples:
            lines.append("## ❌ Sample Errors\n")
            lines.append("| ID | Status | Type | Gold(raw) | Gold(scored) | Pred | Score |")
            lines.append("|----|--------|------|-----------|--------------|------|-------|")
            for e in error_samples[:15]:
                gold_raw_short = e['gold_raw'][:25] + "..." if len(e['gold_raw']) > 25 else e['gold_raw']
                gold_scored_short = e['gold_scored'][:25] + "..." if len(e['gold_scored']) > 25 else e['gold_scored']
                pred_short = e['pred'][:25] + "..." if len(e['pred']) > 25 else e['pred']
                lines.append(
                    f"| {e['id']} | {e['status']} | {e['type']} | `{gold_raw_short}` | "
                    f"`{gold_scored_short}` | `{pred_short}` | {e['score']:.2f} |"
                )
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Generated by NetConfigQA Analyzer on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(lines)


class SummaryReportGenerator:
    """Generates a concise summary report with specific tables requested by the user."""
    
    def generate(self, all_stats_meta: List[tuple]) -> str:
        """
        Generate a comparison report for multiple models.
        all_stats_meta: List of (stats, meta) tuples
        """
        def fmt_pct(value) -> str:
            return "N/A" if value is None else f"{value*100:.2f}"

        lines = []
        lines.append(f"# NetConfigQA Comparison Report\n")
        lines.append(f"> **Generated on**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Table 1: Traditional Metrics
        lines.append("### 1. Traditional NLP Metrics\n")
        lines.append("| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        
        for stats, meta in all_stats_meta:
            model_name = meta.get("model", "Unknown")
            trad = stats.get('traditional_metrics', {})
            r1 = trad.get('rouge1')
            r2 = trad.get('rouge2')
            rl = trad.get('rougeL')
            em = trad.get('exact_match')
            bleu = trad.get('bleu')
            bs = trad.get('bertscore_f1')
            f1 = trad.get('token_f1')
            ta_acc = stats.get('accuracy', 0)
            
            lines.append(
                f"| {model_name} | {fmt_pct(r1)} | {fmt_pct(r2)} | {fmt_pct(rl)} | "
                f"{fmt_pct(em)} | {fmt_pct(bleu)} | {fmt_pct(bs)} | {fmt_pct(f1)} | {fmt_pct(ta_acc)} |"
            )
        
        lines.append("\n---\n")
        
        # Table 2: Answer Type Scores
        lines.append("### 2. Type-Aware Accuracy by Answer Type\n")
        lines.append("| 모델 | map | numeric | text | number | set |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")
        
        for stats, meta in all_stats_meta:
            model_name = meta.get("model", "Unknown")
            by_type = stats.get('by_type', {})
            m_score = by_type.get('map')
            n_score = by_type.get('numeric')
            t_score = by_type.get('text')
            num_score = by_type.get('number')
            s_score = by_type.get('set')
            
            lines.append(
                f"| {model_name} | {fmt_pct(m_score)} | {fmt_pct(n_score)} | {fmt_pct(t_score)} | "
                f"{fmt_pct(num_score)} | {fmt_pct(s_score)} |"
            )

        lines.append("\n> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.\n")
        
        lines.append("\n---\n")
        
        # Table 3: Level Scores
        lines.append("### 3. Type-Aware Accuracy by Level\n")
        lines.append("| 모델 | L1 | L2 | L3 | L4 | L5 |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")
        
        for stats, meta in all_stats_meta:
            model_name = meta.get("model", "Unknown")
            by_level = stats.get('by_level', {})
            l1 = by_level.get('L1', 0) * 100
            l2 = by_level.get('L2', 0) * 100
            l3 = by_level.get('L3', 0) * 100
            l4 = by_level.get('L4', 0) * 100
            l5 = by_level.get('L5', 0) * 100
            
            lines.append(f"| {model_name} | {l1:.2f} | {l2:.2f} | {l3:.2f} | {l4:.2f} | {l5:.2f} |")
        
        lines.append("\n---\n")

        # Table 4: Positive vs Negative testing
        lines.append("### 4. Positive vs Negative Testing\n")
        lines.append("| 모델 | OK | Explicit NC | Semantic NC | Compliance | Gap (OK-Explicit) |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")

        for stats, meta in all_stats_meta:
            model_name = meta.get("model", "Unknown")
            by_status = stats.get('by_status', {})
            ok = by_status.get('OK')
            negative_eval = stats.get('negative_eval', {})
            explicit_nc = negative_eval.get('explicit_abstention_accuracy', by_status.get('NOT_CONFIGURED'))
            semantic_nc = negative_eval.get('semantic_negative_accuracy')
            compliance = negative_eval.get('contract_compliance')
            gap = None if ok is None or explicit_nc is None else ok - explicit_nc
            lines.append(
                f"| {model_name} | {fmt_pct(ok)} | {fmt_pct(explicit_nc)} | {fmt_pct(semantic_nc)} | "
                f"{fmt_pct(compliance)} | {('N/A' if gap is None else f'{gap*100:.2f}')} |"
            )

        lines.append(
            "\n> `Explicit NC` = exact `NOT_CONFIGURED`; `Semantic NC` = relaxed metric-consistent negative answer; "
            "`Compliance` = explicit / semantic.\n"
        )
        
        return "\n".join(lines)


# ==================== Main Analyzer ====================

def normalize_levels(levels: List[str]) -> Set[str]:
    """Normalize level tokens (e.g., l5 -> L5)."""
    return {str(level).strip().upper() for level in levels if str(level).strip()}


STRUCTURED_METRICS = {
    "compare_bgp_neighbor_count",
    "compare_interface_count",
    "compare_vrf_count",
}


def infer_metric_name(row: Dict[str, Any]) -> str:
    metric = row.get("metric") or row.get("source_metric")
    if metric:
        return str(metric).strip().lower()
    qid = str(row.get("question_id", row.get("id", ""))).strip().lower()
    for m in STRUCTURED_METRICS:
        if qid.startswith(m) or m in qid:
            return m
    return ""


def structured_answer_is_valid(gold_raw: str) -> bool:
    try:
        obj = json.loads(str(gold_raw).replace("'", '"'))
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    keys = {"host1_count", "host2_count", "difference"}
    if set(obj.keys()) != keys:
        return False
    return all(isinstance(obj[k], int) for k in keys)


def analyze_results(
    json_file: str,
    verbose: bool = False,
    include_levels: List[str] = None,
    exclude_levels: List[str] = None,
):
    """메인 분석 함수"""

    with open(json_file, 'r', encoding='utf-8') as f:
        payload = json.load(f)

    if isinstance(payload, dict):
        rows = payload.get("results", [])
        meta = payload.get("meta", {})
    elif isinstance(payload, list):
        rows = payload
        meta = {}
    else:
        raise ValueError(f"Unsupported JSON structure in {json_file}")

    include_set = normalize_levels(include_levels or [])
    exclude_set = normalize_levels(exclude_levels or [])

    if include_set:
        rows = [row for row in rows if str(row.get("level", "L1")).strip().upper() in include_set]
    if exclude_set:
        rows = [row for row in rows if str(row.get("level", "L1")).strip().upper() not in exclude_set]

    scorer = NetConfigQAScorer()
    trad_calc = TraditionalMetricsCalculator()
    results = []

    grouped_by_type = defaultdict(list)
    grouped_by_level = defaultdict(list)
    grouped_by_category = defaultdict(list)
    grouped_by_status = defaultdict(list)
    trad_metrics_by_type = defaultdict(lambda: defaultdict(list))

    error_samples = []
    all_preds = []
    all_golds = []
    structured_total = 0
    structured_valid = 0
    negative_total = 0
    semantic_negative_correct = 0
    explicit_abstention_correct = 0
    blank_negative_predictions = 0

    print(f"Analyzing {len(rows)} results from {json_file}...")
    print(
        f"Level filter: include={sorted(include_set) if include_set else 'ALL'}, "
        f"exclude={sorted(exclude_set) if exclude_set else 'NONE'}"
    )
    print("[Step 1/3] Calculating Type-Aware and Traditional metrics...")

    for idx, row in enumerate(rows):
        question_id = str(row.get("question_id", row.get("id", idx)))
        question = row.get("question", "")
        raw_answer_type = row.get('answer_type', row.get('type', 'text'))
        answer_type = canonical_answer_type(raw_answer_type)
        report_type = display_answer_type(raw_answer_type)
        level = str(row.get("level", "L1")).strip().upper()
        category = row.get("category", "General")
        status = row.get("answer_status", row.get("status", "OK"))

        raw_pred = row.get(
            "raw_pred",
            row.get("debate2_answer", row.get("candidate_answer", row.get("pred", ""))),
        )
        pred_input = row.get(
            "pred",
            row.get("raw_pred", row.get("debate2_answer", row.get("candidate_answer", ""))),
        )
        gold_raw = str(row.get("gold", row.get("gold_answer", "")))
        metric_name = infer_metric_name(row)
        if metric_name in STRUCTURED_METRICS:
            structured_total += 1
            if structured_answer_is_valid(gold_raw):
                structured_valid += 1

        clean_pred = scorer.clean_prediction(str(pred_input), answer_type)
        clean_gold = scorer.clean_gold(gold_raw, status=status)
        status_upper = str(status).strip().upper()

        type_aware_metrics = scorer.score(clean_pred, gold_raw, answer_type, status=status, question_id=question_id)
        type_aware_score = type_aware_metrics['score']
        trad_metrics = trad_calc.calculate_all(clean_pred, clean_gold)

        negative_metrics = None
        if status_upper == "NOT_CONFIGURED":
            negative_metrics = scorer.evaluate_negative_prediction(clean_pred, gold_raw, answer_type)
            negative_total += 1
            semantic_negative_correct += int(negative_metrics["semantic_negative_correct"])
            explicit_abstention_correct += int(negative_metrics["explicit_abstention_correct"])
            blank_negative_predictions += int(negative_metrics["blank_prediction"])

        result = {
            "question_id": question_id,
            "level": level,
            "category": category,
            "status": status,
            "question": question,
            "gold": gold_raw,
            "gold_cleaned": clean_gold,
            "raw_pred": raw_pred,
            "pred": clean_pred,
            "type_aware_score": type_aware_score,
            "type": report_type,
            "canonical_type": answer_type,
            "negative_semantic_correct": None if negative_metrics is None else negative_metrics["semantic_negative_correct"],
            "negative_explicit_abstention": None if negative_metrics is None else negative_metrics["explicit_abstention_correct"],
            "negative_contract_compliant": None if negative_metrics is None else negative_metrics["contract_compliant"],
            "negative_blank_prediction": None if negative_metrics is None else negative_metrics["blank_prediction"],
            "negative_eval_detail": None if negative_metrics is None else negative_metrics["detail"],
        }
        result.update({f"type_aware_{k}": v for k, v in type_aware_metrics.items() if k != 'score'})
        result.update(trad_metrics)

        results.append(result)

        grouped_by_type[report_type].append(type_aware_score)
        grouped_by_level[level].append(type_aware_score)
        grouped_by_category[category].append(type_aware_score)
        grouped_by_status[status].append(type_aware_score)

        for metric_name, metric_value in trad_metrics.items():
            if metric_value is not None:
                trad_metrics_by_type[report_type][metric_name].append(metric_value)

        all_preds.append(clean_pred if clean_pred else "[empty]")
        all_golds.append(clean_gold if clean_gold else "[empty]")

        if type_aware_score < 0.99 and len(error_samples) < 20:
            error_samples.append({
                "id": question_id,
                "question": question[:60] + "..." if len(question) > 60 else question,
                "status": status,
                "gold_raw": gold_raw[:40] if gold_raw else "(empty)",
                "gold_scored": clean_gold[:40] if clean_gold else "(empty)",
                "pred": clean_pred[:40] if clean_pred else "(empty)",
                "type": report_type,
                "score": type_aware_score
            })

    print("[Step 2/3] Calculating BERTScore (batch processing)...")
    if BERTSCORE_AVAILABLE and all_preds and all_golds:
        try:
            bert_device = "cuda" if torch is not None and torch.cuda.is_available() else "cpu"
            print(f"   [INFO] BERTScore device: {bert_device}")
            try:
                P, R, F1 = bert_score(all_preds, all_golds, lang='en', verbose=False, device=bert_device)
            except RuntimeError as e:
                if bert_device == "cuda" and "out of memory" in str(e).lower():
                    print("   [WARNING] BERTScore CUDA OOM, retrying on CPU...")
                    P, R, F1 = bert_score(all_preds, all_golds, lang='en', verbose=False, device='cpu')
                else:
                    raise
            for i, result in enumerate(results):
                result['bertscore_precision'] = P[i].item()
                result['bertscore_recall'] = R[i].item()
                result['bertscore_f1'] = F1[i].item()

                answer_type = result['type']
                trad_metrics_by_type[answer_type]['bertscore_f1'].append(F1[i].item())
            print(f"   [OK] BERTScore calculated for {len(results)} samples")
        except Exception as e:
            print(f"   [WARNING] BERTScore calculation failed: {e}")
            for result in results:
                result['bertscore_precision'] = None
                result['bertscore_recall'] = None
                result['bertscore_f1'] = None
    else:
        if not BERTSCORE_AVAILABLE:
            print("   [WARNING] BERTScore not available (install with: pip install bert-score)")
        for result in results:
            result['bertscore_precision'] = None
            result['bertscore_recall'] = None
            result['bertscore_f1'] = None

    n = len(results)
    total_score = sum(r['type_aware_score'] for r in results)
    avg_acc = total_score / n if n > 0 else 0
    structured_coverage = (structured_valid / structured_total) if structured_total > 0 else 1.0
    legacy_map_fallback_count = len(scorer.warnings)

    overall_trad_metrics = {}
    for metric_name in ['exact_match', 'token_f1', 'rouge1', 'rouge2', 'rougeL', 'bertscore_f1', 'bleu']:
        all_values = [r.get(metric_name) for r in results if r.get(metric_name) is not None]
        overall_trad_metrics[metric_name] = sum(all_values) / len(all_values) if all_values else None

    stats = {
        "accuracy": avg_acc,
        "total_samples": n,
        "by_type": {t: sum(s)/len(s) for t, s in grouped_by_type.items()},
        "by_level": {l: sum(s)/len(s) for l, s in grouped_by_level.items()},
        "by_category": {c: sum(s)/len(s) for c, s in grouped_by_category.items()},
        "by_status": {s: sum(sc)/len(sc) for s, sc in grouped_by_status.items()},
        "negative_eval": {
            "total_negative_samples": negative_total,
            "semantic_negative_correct": semantic_negative_correct,
            "explicit_abstention_correct": explicit_abstention_correct,
            "blank_negative_predictions": blank_negative_predictions,
            "semantic_negative_accuracy": (semantic_negative_correct / negative_total) if negative_total > 0 else None,
            "explicit_abstention_accuracy": (explicit_abstention_correct / negative_total) if negative_total > 0 else None,
            "contract_compliance": (
                explicit_abstention_correct / semantic_negative_correct
            ) if semantic_negative_correct > 0 else None,
            "semantic_vs_explicit_gap": (
                (semantic_negative_correct / negative_total) -
                (explicit_abstention_correct / negative_total)
            ) if negative_total > 0 else None,
        },
        "traditional_metrics": overall_trad_metrics,
        "trad_by_type": {
            atype: {
                metric: sum(vals)/len(vals) if vals else None
                for metric, vals in metrics_dict.items()
            }
            for atype, metrics_dict in trad_metrics_by_type.items()
        }
    }

    print("[Step 3/3] Generating reports...")
    print("\n" + "="*80)
    print(" " * 25 + "ANALYSIS RESULTS")
    print("="*80)

    print(f"\n{'Metric':<25} {'Score':>10}")
    print("-" * 40)
    print(f"{'Type-Aware Accuracy':<25} {avg_acc:>9.2%}")
    def _print_metric(name: str, key: str):
        value = overall_trad_metrics.get(key)
        rendered = "N/A" if value is None else f"{value:>9.2%}"
        print(f"{name:<25} {rendered}")

    _print_metric('Exact Match', 'exact_match')
    _print_metric('Token F1', 'token_f1')
    _print_metric('BLEU', 'bleu')
    _print_metric('BERTScore F1', 'bertscore_f1')
    _print_metric('ROUGE-L', 'rougeL')
    _print_metric('ROUGE-1', 'rouge1')
    _print_metric('ROUGE-2', 'rouge2')

    print(f"\n[Type-Aware Score by Answer Type]")
    for t in sorted(grouped_by_type.keys()):
        scores = grouped_by_type[t]
        label = ANSWER_TYPE_LABEL.get(t, t)
        print(f"   {t:12s} ({label}): {sum(scores)/len(scores):.2%} (n={len(scores)})")

    print(f"\n[Type-Aware Score by Level]")
    for lvl in sorted(grouped_by_level.keys()):
        scores = grouped_by_level[lvl]
        print(f"   {lvl:5s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")

    print(f"\n[Type-Aware Score by Status]")
    for current_status in sorted(grouped_by_status.keys()):
        scores = grouped_by_status[current_status]
        print(f"   {current_status:15s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")

    if verbose and error_samples:
        print(f"\n[Sample Errors (first {len(error_samples)})]")
        for i, e in enumerate(error_samples[:10], 1):
            print(f"\n   [{i}] ID: {e['id']} | Type: {e['type']} | Score: {e['score']:.2f}")
            print(f"       Q: {e['question']}")
            print(f"       Gold: {e['gold']}")
            print(f"       Pred: {e['pred']}")

    if "_raw_" in str(json_file):
        output_file = str(json_file).replace("_raw_", "_analyzed_")
    else:
        output_file = str(json_file).replace(".json", "_analyzed.json")

    meta = dict(meta) if isinstance(meta, dict) else {}
    meta["include_levels"] = sorted(include_set) if include_set else []
    meta["exclude_levels"] = sorted(exclude_set) if exclude_set else []
    meta["schema_version"] = meta.get("schema_version", "unknown")
    meta["policy_validation_passed"] = meta.get("policy_validation_passed", False)
    meta["structured_metrics_coverage"] = structured_coverage
    meta["legacy_map_fallback_count"] = legacy_map_fallback_count

    output_data = {
        "meta": meta,
        "stats": stats,
        "results": results,
        "warnings": scorer.warnings,
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Saved analyzed results to: {output_file}")

    error_results = [r for r in results if r['type_aware_score'] < 1.0]
    error_output_file = output_file.replace(".json", "_errors.json")
    error_output_data = {
        "meta": meta,
        "count": len(error_results),
        "results": error_results
    }
    with open(error_output_file, 'w', encoding='utf-8') as f:
        json.dump(error_output_data, f, indent=2, ensure_ascii=False)
    print(f"[OK] Saved error samples to: {error_output_file}")

    csv_file = output_file.replace(".json", "_detailed.csv")
    with open(csv_file, 'w', newline='', encoding='utf-8-sig') as csvf:
        if results:
            fieldnames = ['question_id', 'level', 'category', 'type', 'status',
                         'question', 'gold', 'pred',
                         'type_aware_score', 'negative_semantic_correct',
                         'negative_explicit_abstention', 'negative_contract_compliant',
                         'negative_blank_prediction', 'negative_eval_detail',
                         'exact_match', 'token_f1',
                         'bertscore_f1', 'rougeL', 'rouge1', 'rouge2']
            writer = csv.DictWriter(csvf, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for r in results:
                writer.writerow(r)

    print(f"[OK] Saved detailed CSV to: {csv_file}")

    scorecard_file = output_file.replace(".json", "_scorecard.md")
    scorecard_gen = ScorecardGenerator()
    scorecard_md = scorecard_gen.generate(stats, meta, error_samples)

    with open(scorecard_file, 'w', encoding='utf-8') as f:
        f.write(scorecard_md)

    print(f"[OK] Saved scorecard to: {scorecard_file}")

    summary_file = output_file.replace(".json", "_summary.md")
    summary_gen = SummaryReportGenerator()
    summary_md = summary_gen.generate([(stats, meta)])

    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary_md)

    print(f"[OK] Saved summary report to: {summary_file}")
    print(f"\n[TIP] Run 'python make_figure.py \"{output_file}\"' to generate visualizations.")

    return stats, results, meta


def main():
    parser = argparse.ArgumentParser(description="Analyze NetConfigQA evaluation results")
    parser.add_argument("json_files", nargs="+", help="Path to results json(s) (raw or already analyzed)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed error analysis")
    parser.add_argument("--output_summary", "-o", default="comparison_summary.md", help="Output path for combined summary")
    parser.add_argument(
        "--include_levels",
        nargs="+",
        default=None,
        help="분석에 포함할 level 목록 (예: --include_levels L1 L2 L3 L4 L5)",
    )
    parser.add_argument(
        "--exclude_levels",
        nargs="+",
        default=["L6"],
        help="분석에서 제외할 level 목록 (기본값: L6)",
    )
    args = parser.parse_args()

    all_results = []
    for json_file in args.json_files:
        stats, _, meta = analyze_results(
            json_file,
            verbose=args.verbose,
            include_levels=args.include_levels,
            exclude_levels=args.exclude_levels,
        )
        all_results.append((stats, meta))

    if len(all_results) > 1:
        summary_gen = SummaryReportGenerator()
        comparison_md = summary_gen.generate(all_results)

        with open(args.output_summary, 'w', encoding='utf-8') as f:
            f.write(comparison_md)

        print(f"\n" + "="*80)
        print(f"[SUCCESS] Generated combined comparison report: {args.output_summary}")
        print("="*80)


if __name__ == "__main__":
    main()
