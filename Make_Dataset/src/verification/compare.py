#!/usr/bin/env python3
"""Type-Aware Accuracy (TA-Acc) comparison functions for Ground Truth verification.

Extracted and simplified from Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py.
This module compares independent-parser answers against Batfish-generated dataset answers.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Set


# ── Type Normalization ──────────────────────────────────────────────

CANONICAL_TYPE_MAP = {
    "numbers": "number", "num": "number", "int": "number", "integer": "number",
    "float": "number", "scalar_int": "number", "numeric": "number",
    "list_str": "set", "set_str": "set", "edge_set": "set", "set_string": "set",
    "dict": "map", "map_str_str": "map", "map_str_int": "map", "json": "map",
    "bool": "boolean",
}


def canonical_answer_type(answer_type: str | None) -> str:
    if answer_type is None:
        return "text"
    return CANONICAL_TYPE_MAP.get(str(answer_type).strip().lower(), str(answer_type).strip().lower())


# ── Parsing Helpers ─────────────────────────────────────────────────

def _parse_set(val: Any) -> Set[str]:
    """Parse set from various representations (list, JSON string, comma-separated)."""
    if isinstance(val, (set, frozenset)):
        return {str(v).strip().lower() for v in val}
    if isinstance(val, (list, tuple)):
        return {str(v).strip().lower() for v in val if str(v).strip()}
    if not isinstance(val, str):
        val = str(val)
    val = val.strip()
    if not val:
        return set()

    # Try JSON parsing
    try:
        normalized = val.replace("'", '"')
        for open_b, close_b in [("{", "}"), ("(", ")")]:
            normalized = normalized.replace(open_b, "[").replace(close_b, "]")
        if normalized.startswith("[") and normalized.endswith("]"):
            items = json.loads(normalized)
            return {str(i).strip().lower() for i in items if str(i).strip()}
    except Exception:
        pass

    # Fallback: comma-separated
    cleaned = val.strip("[]{}()\"' ")
    if "," in cleaned:
        return {i.strip().lower() for i in cleaned.split(",") if i.strip()}
    if cleaned:
        return {cleaned.lower()}
    return set()


def _parse_map(val: Any) -> Dict[str, Any] | None:
    """Parse a map/dict from various representations."""
    if isinstance(val, dict):
        return val
    if not isinstance(val, str):
        return None
    val = val.strip()
    if not val:
        return None
    try:
        obj = json.loads(val.replace("'", '"'))
        if isinstance(obj, dict):
            return obj
        return None
    except Exception:
        pass
    # key:value text extraction
    pairs = re.findall(r'([A-Za-z0-9_./-]+)\s*[:=]\s*([A-Za-z0-9_./-]+)', val)
    if pairs:
        result: Dict[str, Any] = {}
        for k, v in pairs:
            result[k] = int(v) if re.fullmatch(r'-?\d+', v) else v
        return result
    return None


def _extract_number(val: Any) -> float | None:
    """Extract a number from a value."""
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).strip()
    match = re.search(r'-?\d+(\.\d+)?', s)
    if match:
        return float(match.group())
    return None


def _normalize_str(val: Any) -> str:
    """Normalize a string value for comparison."""
    s = str(val).strip().lower()
    # Strip surrounding quotes
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1]
    # Null aliases
    if s in ("null", "none", "n/a", "not configured", "not found", "미설정"):
        return ""
    return s


def _normalize_ip(val: str) -> str:
    """Remove CIDR notation and normalize."""
    val = val.strip().lower()
    if "/" in val:
        val = val.split("/")[0].strip()
    if val == "shutdown":
        return "down"
    return val


# ── Scoring Functions ───────────────────────────────────────────────

def _score_number(parser: Any, gold: Any) -> Dict[str, Any]:
    p = _extract_number(parser)
    g = _extract_number(gold)
    if p is None or g is None:
        return {"match": _normalize_str(parser) == _normalize_str(gold),
                "score": 1.0 if _normalize_str(parser) == _normalize_str(gold) else 0.0,
                "detail": "fallback_string_compare"}
    match = p == g
    return {"match": match, "score": 1.0 if match else 0.0, "detail": f"parser={p}, gold={g}"}


def _score_set(parser: Any, gold: Any) -> Dict[str, Any]:
    p_set = _parse_set(parser)
    g_set = _parse_set(gold)
    if not g_set and not p_set:
        return {"match": True, "score": 1.0, "f1": 1.0, "detail": "both_empty"}
    intersection = len(p_set & g_set)
    precision = intersection / len(p_set) if p_set else 0.0
    recall = intersection / len(g_set) if g_set else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    match = f1 == 1.0
    extra = ""
    if not match:
        missing = g_set - p_set
        extra_items = p_set - g_set
        parts = []
        if missing:
            parts.append(f"missing={missing}")
        if extra_items:
            parts.append(f"extra={extra_items}")
        extra = "; ".join(parts)
    return {"match": match, "score": f1, "f1": f1, "precision": precision, "recall": recall,
            "detail": extra if extra else "exact"}


def _score_map(parser: Any, gold: Any) -> Dict[str, Any]:
    p_obj = _parse_map(parser)
    g_obj = _parse_map(gold)
    if p_obj is None and g_obj is None:
        return {"match": True, "score": 1.0, "detail": "both_none"}
    if p_obj is None or g_obj is None:
        return {"match": False, "score": 0.0, "detail": f"parse_fail: parser={type(parser).__name__}, gold={type(gold).__name__}"}
    if not isinstance(p_obj, dict) or not isinstance(g_obj, dict):
        eq = str(p_obj) == str(g_obj)
        return {"match": eq, "score": 1.0 if eq else 0.0, "detail": "str_fallback"}

    # Key match check
    if set(p_obj.keys()) != set(g_obj.keys()):
        return {"match": False, "score": 0.0,
                "detail": f"key_mismatch: parser={set(p_obj.keys())}, gold={set(g_obj.keys())}"}

    matched = 0
    total = len(g_obj)
    mismatches = []
    for k in g_obj:
        g_val = g_obj[k]
        p_val = p_obj.get(k)
        # Coerce types
        if isinstance(g_val, int):
            try:
                p_val = int(p_val) if p_val is not None else None
            except (ValueError, TypeError):
                pass
        if isinstance(g_val, str):
            g_norm = _normalize_ip(str(g_val))
            p_norm = _normalize_ip(str(p_val)) if p_val is not None else ""
            if p_norm == g_norm:
                matched += 1
            else:
                mismatches.append(f"{k}: parser={p_val}, gold={g_val}")
        else:
            if p_val == g_val:
                matched += 1
            else:
                mismatches.append(f"{k}: parser={p_val}, gold={g_val}")

    score = matched / total if total > 0 else 1.0
    return {"match": score == 1.0, "score": score,
            "detail": "; ".join(mismatches) if mismatches else "exact"}


def _score_text(parser: Any, gold: Any) -> Dict[str, Any]:
    p = _normalize_str(parser)
    g = _normalize_str(gold)
    if p == g:
        return {"match": True, "score": 1.0, "detail": "exact"}

    # Token F1 fallback
    p_tokens = set(p.split())
    g_tokens = set(g.split())
    if not g_tokens:
        eq = not p_tokens
        return {"match": eq, "score": 1.0 if eq else 0.0, "detail": "both_empty" if eq else "gold_empty"}
    common = p_tokens & g_tokens
    if common:
        precision = len(common) / len(p_tokens) if p_tokens else 0.0
        recall = len(common) / len(g_tokens)
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return {"match": f1 == 1.0, "score": f1, "detail": f"token_f1={f1:.3f}"}
    return {"match": False, "score": 0.0, "detail": f"no_overlap: parser='{p}', gold='{g}'"}


def _score_boolean(parser: Any, gold: Any) -> Dict[str, Any]:
    true_vals = {"true", "1", "yes", "ok", "enabled"}
    false_vals = {"false", "0", "no", "disabled", "미설정"}
    p_str = _normalize_str(parser)
    g_str = _normalize_str(gold)
    p_bool = True if p_str in true_vals else (False if p_str in false_vals else None)
    g_bool = True if g_str in true_vals else (False if g_str in false_vals else None)
    if p_bool is not None and g_bool is not None:
        match = p_bool == g_bool
        return {"match": match, "score": 1.0 if match else 0.0, "detail": f"parser={p_bool}, gold={g_bool}"}
    match = p_str == g_str
    return {"match": match, "score": 1.0 if match else 0.0, "detail": "str_fallback"}


# ── Main Entry Point ────────────────────────────────────────────────

def compare_answers(parser_answer: Any, dataset_answer: Any, answer_type: str) -> Dict[str, Any]:
    """Compare parser answer against dataset answer using TA-Acc scoring.

    Returns
    -------
    dict with keys: match (bool), score (float), detail (str), answer_type (str)
    """
    atype = canonical_answer_type(answer_type)
    try:
        if atype in ("number",):
            result = _score_number(parser_answer, dataset_answer)
        elif atype in ("set",):
            result = _score_set(parser_answer, dataset_answer)
        elif atype in ("map",):
            result = _score_map(parser_answer, dataset_answer)
        elif atype in ("boolean",):
            result = _score_boolean(parser_answer, dataset_answer)
        else:
            result = _score_text(parser_answer, dataset_answer)
    except Exception as e:
        result = {"match": False, "score": 0.0, "detail": f"error: {e}"}
    result["answer_type"] = atype
    return result
