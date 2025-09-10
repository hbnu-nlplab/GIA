from __future__ import annotations

from typing import Dict, List
import pandas as pd

try:
    from bert_score import score as bert_score
except Exception:
    bert_score = None

try:
    from rouge import Rouge  # type: ignore
except Exception:
    Rouge = None  # type: ignore

from .data_utils import parse_answer_sections, clean_ground_truth_text


def normalize_boolean_text(text: str) -> str:
    """Boolean 텍스트를 정규화 (TRUE/FALSE, True/False, true/false 등을 통일)"""
    text = str(text).strip().lower()
    
    # Boolean 값들을 표준화
    if text in ['true', 'yes', '1', 'enabled', 'active', 'on']:
        return 'true'
    elif text in ['false', 'no', '0', 'disabled', 'inactive', 'off']:
        return 'false'
    
    return text


def calculate_exact_match(predictions: List[str], ground_truths: List[str]) -> float:
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    correct = 0
    for pred, gt in zip(predictions, ground_truths):
        # Boolean 값들을 정규화해서 비교
        normalized_pred = normalize_boolean_text(pred)
        normalized_gt = normalize_boolean_text(gt)
        if normalized_pred == normalized_gt:
            correct += 1
    return correct / len(predictions) if predictions else 0.0


def calculate_relaxed_exact_match(predictions: List[str], ground_truths: List[str]) -> float:
    """순서에 무관하게 집합 비교로 정확도 계산"""
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    correct = 0
    for pred, gt in zip(predictions, ground_truths):
        # 쉼표로 분리하여 집합으로 비교 (Boolean 정규화 포함)
        pred_items = set(normalize_boolean_text(item) for item in str(pred).split(',') if item.strip())
        gt_items = set(normalize_boolean_text(item) for item in str(gt).split(',') if item.strip())
        if pred_items == gt_items:
            correct += 1
    return correct / len(predictions) if predictions else 0.0


def calculate_f1_score(predictions: List[str], ground_truths: List[str]) -> float:
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    f1_scores: List[float] = []
    for pred, gt in zip(predictions, ground_truths):
        # Boolean 정규화 적용 후 토큰화
        normalized_pred = normalize_boolean_text(pred)
        normalized_gt = normalize_boolean_text(gt)
        pred_tokens = set(normalized_pred.split())
        gt_tokens = set(normalized_gt.split())
        if len(gt_tokens) == 0:
            f1_scores.append(1.0 if len(pred_tokens) == 0 else 0.0)
            continue
        inter = pred_tokens.intersection(gt_tokens)
        precision = len(inter) / len(pred_tokens) if pred_tokens else 0.0
        recall = len(inter) / len(gt_tokens) if gt_tokens else 0.0
        f1_scores.append(0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall))
    return sum(f1_scores) / len(f1_scores) if f1_scores else 0.0


def calculate_relaxed_f1_score(predictions: List[str], ground_truths: List[str]) -> float:
    """순서에 무관하게 항목별로 F1 점수 계산"""
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    f1_scores: List[float] = []
    for pred, gt in zip(predictions, ground_truths):
        # 쉼표로 분리하여 각 항목을 토큰으로 처리 (Boolean 정규화 포함)
        pred_items = set(normalize_boolean_text(item) for item in str(pred).split(',') if item.strip())
        gt_items = set(normalize_boolean_text(item) for item in str(gt).split(',') if item.strip())
        
        if len(gt_items) == 0:
            f1_scores.append(1.0 if len(pred_items) == 0 else 0.0)
            continue
            
        inter = pred_items.intersection(gt_items)
        precision = len(inter) / len(pred_items) if pred_items else 0.0
        recall = len(inter) / len(gt_items) if gt_items else 0.0
        f1_scores.append(0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall))
    return sum(f1_scores) / len(f1_scores) if f1_scores else 0.0


def _calculate_bert_score(pred: List[str], gt: List[str]) -> Dict[str, float]:
    """BERTScore를 한국어로 계산."""
    if not bert_score:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    P, R, F1 = bert_score(pred, gt, lang="ko", verbose=False)
    return {"precision": P.mean().item(), "recall": R.mean().item(), "f1": F1.mean().item()}


def _calculate_rouge_scores(pred: List[str], gt: List[str]) -> Dict[str, float]:
    if not Rouge:
        return {"rouge-1": 0.0, "rouge-2": 0.0, "rouge-l": 0.0}
    rouge = Rouge()
    scores = rouge.get_scores(pred, gt, avg=True)
    return {"rouge-1": scores["rouge-1"]["f"], "rouge-2": scores["rouge-2"]["f"], "rouge-l": scores["rouge-l"]["f"]}

# Relaxed helpers
def _list_items_relaxed(s: str) -> list[str]:
    import re
    return [x.strip() for x in re.split(r"[;,]", s) if x.strip()]

def _normalize_for_relaxed(s: str) -> str:
    return clean_ground_truth_text(str(s)).lower()


def evaluate_predictions(predictions: List[Dict], test_data: pd.DataFrame) -> Dict:
    """예측 결과 평가 (origin 분리 + optional BERT/ROUGE)"""
    pred_ground_truths: List[str] = []
    pred_explanations: List[str] = []
    gt_ground_truths = [str(x) for x in test_data["ground_truth"].tolist()]
    gt_explanations = [str(x) for x in test_data.get("explanation", []).tolist()] if "explanation" in test_data.columns else [""] * len(predictions)

    if "origin" in test_data.columns:
        origins = test_data["origin"].tolist()
    else:
        origins = ["general"] * len(predictions)

    for pred in predictions:
        gt, exp = parse_answer_sections(pred.get("final_answer", ""))
        pred_ground_truths.append(gt)
        pred_explanations.append(exp)

    # index groups
    if "origin" in test_data.columns:
        rule_idx = [i for i, o in enumerate(origins) if o == "rule_based"]
        enhanced_idx = [i for i, o in enumerate(origins) if o == "enhanced_llm_with_agent"]
    else:
        rule_idx, enhanced_idx = [], []

    # overall
    gt_em_overall = calculate_exact_match(pred_ground_truths, gt_ground_truths)
    gt_f1_overall = calculate_f1_score(pred_ground_truths, gt_ground_truths)
    
    # overall relaxed (순서 무관)
    gt_em_relaxed = calculate_relaxed_exact_match(pred_ground_truths, gt_ground_truths)
    gt_f1_relaxed = calculate_relaxed_f1_score(pred_ground_truths, gt_ground_truths)

    # rule-based
    if rule_idx:
        rule_pred_gt = [pred_ground_truths[i] for i in rule_idx]
        rule_true_gt = [gt_ground_truths[i] for i in rule_idx]
        rule_gt_em = calculate_exact_match(rule_pred_gt, rule_true_gt)
        rule_gt_f1 = calculate_f1_score(rule_pred_gt, rule_true_gt)
        rule_gt_em_relaxed = calculate_relaxed_exact_match(rule_pred_gt, rule_true_gt)
        rule_gt_f1_relaxed = calculate_relaxed_f1_score(rule_pred_gt, rule_true_gt)
    else:
        rule_gt_em = rule_gt_f1 = rule_gt_em_relaxed = rule_gt_f1_relaxed = 0.0

    # enhanced llm
    explanation_results = {
        "bert_f1": 0.0,
        "bert_precision": 0.0,
        "bert_recall": 0.0,
        "rouge_1_f1": 0.0,
        "rouge_2_f1": 0.0,
        "rouge_l_f1": 0.0,
        "valid_count": 0,
        "total_count": len(enhanced_idx),
    }
    if enhanced_idx:
        enh_pred_gt = [pred_ground_truths[i] for i in enhanced_idx]
        enh_true_gt = [gt_ground_truths[i] for i in enhanced_idx]
        enh_gt_em = calculate_exact_match(enh_pred_gt, enh_true_gt)
        enh_gt_f1 = calculate_f1_score(enh_pred_gt, enh_true_gt)

        enh_pred_exp = [pred_explanations[i] for i in enhanced_idx]
        enh_true_exp = [gt_explanations[i] for i in enhanced_idx]
        valid = [i for i, exp in enumerate(enh_true_exp) if str(exp).strip()]
        if valid:
            v_pred = [enh_pred_exp[i] for i in valid]
            v_true = [enh_true_exp[i] for i in valid]
            b = _calculate_bert_score(v_pred, v_true)
            r = _calculate_rouge_scores(v_pred, v_true)
            explanation_results = {
                "bert_f1": b.get("f1", 0.0),
                "bert_precision": b.get("precision", 0.0),
                "bert_recall": b.get("recall", 0.0),
                "rouge_1_f1": r.get("rouge-1", 0.0),
                "rouge_2_f1": r.get("rouge-2", 0.0),
                "rouge_l_f1": r.get("rouge-l", 0.0),
                "valid_count": len(valid),
                "total_count": len(enhanced_idx),
                # 선택: 정성 표용 per-sample은 compare 단계에서 별도 계산 가능
            }
    else:
        enh_gt_em = 0.0
        enh_gt_f1 = 0.0

    return {
        "overall": {
            "exact_match": gt_em_overall,
            "f1_score": gt_f1_overall,
            "total_questions": len(predictions),
        },
        "overall_relaxed": {
            "exact_match": gt_em_relaxed,
            "f1_score": gt_f1_relaxed,
            "total_questions": len(predictions),
        },
        "rule_based": {
            "exact_match": rule_gt_em,
            "f1_score": rule_gt_f1,
            "question_count": len(rule_idx),
        },
        "rule_based_relaxed": {
            "exact_match": rule_gt_em_relaxed,
            "f1_score": rule_gt_f1_relaxed,
            "question_count": len(rule_idx),
        },
        "enhanced_llm": {
            "ground_truth": {"exact_match": enh_gt_em, "f1_score": enh_gt_f1},
            "explanation": explanation_results,
            "question_count": len(enhanced_idx),
        },
    }


# ... 기존 evaluate_predictions 함수들 ...

# vvv 아래 함수들을 파일 맨 아래에 추가 vvv
import numpy as np

def recall_at_k(results: list[str], ground_truth_doc_name: str, metadatas: list[dict], k: int) -> float:
    """정답 문서가 top-k 검색 결과 안에 포함되면 1, 아니면 0"""
    # ground_truth는 이제 정답 파일명(예: 'ce1.xml')을 기준으로 함
    filenames_in_results = [meta.get('filename', '') for meta in metadatas[:k]]
    return 1.0 if ground_truth_doc_name in filenames_in_results else 0.0

def reciprocal_rank(results: list[str], ground_truth_doc_name: str, metadatas: list[dict]) -> float:
    """정답 문서가 몇 번째에 등장하는지 Reciprocal Rank 계산"""
    for idx, meta in enumerate(metadatas, start=1):
        if meta.get('filename') == ground_truth_doc_name:
            return 1.0 / idx
    return 0.0

def evaluate_retrieval(pipeline, dataset: pd.DataFrame, query_fn, k_values: list[int]):
    """
    RAG 파이프라인의 검색 단계 성능을 평가합니다.
    - pipeline: get_chromadb_content_for_eval 메서드를 가진 파이프라인 객체
    - dataset: 'question', 'ground_truth_filename' 컬럼을 가진 DataFrame
    """
    recall_scores = {k: [] for k in k_values}
    rr_scores = []

    max_k = max(k_values)
    for _, row in dataset.iterrows():
        question = row["question"]
        gt_filename = row["ground_truth_filename"] # 정답 파일명 사용

        # 1. 쿼리 생성 (Heuristic or LLM)
        query = query_fn(question, "")
        
        # 2. 파이프라인을 통해 검색 및 재정렬 실행
        # n_results는 평가에 필요한 최대 k값으로 설정
        documents, metadatas = pipeline.get_chromadb_content_for_eval(query, n_results=max_k)
        
        # 3. Recall@k 계산
        for k in k_values:
            recall_scores[k].append(recall_at_k(documents, gt_filename, metadatas, k))
        
        # 4. MRR 계산
        rr_scores.append(reciprocal_rank(documents, gt_filename, metadatas))
    
    # 평균 결과 반환
    recall_avg = {k: np.mean(v) for k, v in recall_scores.items()}
    mrr = np.mean(rr_scores)
    return recall_avg, mrr
