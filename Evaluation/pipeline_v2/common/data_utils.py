from __future__ import annotations

from typing import Tuple, List, Dict
import pandas as pd
import re
import tiktoken


def load_test_data(csv_path: str) -> pd.DataFrame:
    """CSV 로드 및 기본 컬럼 확인"""
    df = pd.read_csv(csv_path)
    required = ["question", "ground_truth"]
    for col in required:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    # optional columns: explanation, origin
    if "explanation" not in df.columns:
        df["explanation"] = ""
    return df


def parse_answer_sections(answer: str) -> Tuple[str, str]:
    """[GROUND_TRUTH], [EXPLANATION] 섹션 분리"""
    ground_truth = ""
    explanation = ""
    gt_match = re.search(r"\[GROUND_TRUTH\](.*?)(?:\[EXPLANATION\]|$)", answer, re.DOTALL | re.IGNORECASE)
    if gt_match:
        ground_truth = gt_match.group(1).strip()
    exp_match = re.search(r"\[EXPLANATION\](.*?)$", answer, re.DOTALL | re.IGNORECASE)
    if exp_match:
        explanation = exp_match.group(1).strip()
    if not ground_truth and not explanation:
        explanation = answer.strip()
        if len(answer.strip().split()) <= 10:
            ground_truth = answer.strip()
    return ground_truth, explanation


def num_tokens_from_string(string: str, encoding_name: str = "cl100k_base") -> int:
    encoding = tiktoken.get_encoding(encoding_name)
    return len(encoding.encode(string))


# -----------------------------
# Preprocessing utilities
# -----------------------------

def _normalize_whitespace(text: str) -> str:
    """Flatten newlines and collapse multiple spaces to single space."""
    if text is None:
        return ""
    # replace newlines and tabs with spaces
    s = str(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # collapse multiple spaces
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def clean_ground_truth_text(text: str) -> str:
    """Clean GROUND_TRUTH: remove labels, brackets, and normalize whitespace.

    - Removes newline (\n) and extra spaces
    - Strips common labels like '정답:', '답:', 'answer:', 'ground truth:' (case-insensitive)
    - Removes outer quotes
    """
    s = _normalize_whitespace(text)
    # remove bracket tags if mistakenly included
    s = re.sub(r"^\[\s*ground_truth\s*\]\s*", "", s, flags=re.I)
    # remove leading labels
    s = re.sub(r"^(정답|답|answer|ground\s*truth)\s*[:：]\s*", "", s, flags=re.I)
    # trim enclosing quotes
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        s = s[1:-1].strip()
    return s


def clean_explanation_text(text: str) -> str:
    """Clean EXPLANATION: flatten newlines and collapse spaces only."""
    return _normalize_whitespace(text)


def extract_and_preprocess(answer: str) -> Tuple[str, str, str, str]:
    """Parse answer and return (raw_gt, raw_ex, pre_gt, pre_ex)."""
    gt_raw, ex_raw = parse_answer_sections(answer or "")
    pre_gt = clean_ground_truth_text(gt_raw)
    pre_ex = clean_explanation_text(ex_raw)
    return gt_raw, ex_raw, pre_gt, pre_ex

