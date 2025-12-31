#!/usr/bin/env python3
"""
External Dataset Analyzer
=========================
결과 분석 및 메트릭 집계 (생성과 분석 분리)

Features:
- 폴더 기반 결과 집계
- 전체 메트릭 계산 (EM, F1, ROUGE, BLEU, BERTScore)
- 교집합 문항 비교 (동일 문항으로만 비교)
- 리포트 생성

Usage:
    python analyze_external_dataset.py                    # 전체 분석
    python analyze_external_dataset.py --dataset teleqna  # 특정 데이터셋만
    python analyze_external_dataset.py --compare          # 모델 간 비교 리포트
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from collections import defaultdict

# 메트릭 라이브러리
try:
    import torch
    from evaluate import load as load_metric
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    HAS_METRICS = True
except ImportError:
    HAS_METRICS = False
    print("⚠️ Some metric libraries not installed. Run: pip install evaluate bert-score nltk")

BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parents[2]
RESULT_DIR = PROJECT_ROOT / "Result" / "external_dataset"

sys.path.insert(0, str(PROJECT_ROOT / "code"))
from External_dataset.Local import get_dataset, DATASET_REGISTRY


@dataclass
class AnalysisResult:
    """분석 결과"""
    model_name: str
    dataset_name: str
    metrics: Dict[str, float]
    evaluated_ids: List[str]
    total_items: int


def load_result_file(path: Path) -> Optional[Dict]:
    """결과 파일 로드"""
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_full_metrics(predictions: List[str], references: List[str], dataset_name: str) -> Dict[str, float]:
    """
    전체 메트릭 계산
    - EM, F1: 데이터셋별 정규화 사용
    - ROUGE, BLEU, BERTScore: 공통
    """
    if not HAS_METRICS:
        return {"error": "Metric libraries not installed"}
    
    results = {}
    dataset = get_dataset(dataset_name)
    
    # 1. EM & F1 (데이터셋별 정규화)
    em_scores = []
    f1_scores = []
    
    for pred, ref in zip(predictions, references):
        em_scores.append(dataset.compute_em(pred, ref))
        f1_scores.append(dataset.compute_f1(pred, ref))
    
    results["EM"] = np.mean(em_scores) * 100
    results["F1"] = np.mean(f1_scores) * 100
    
    if dataset_name == "teleqna":
        results["Accuracy"] = results["EM"]
        results["Correct"] = int(sum(em_scores))
    
    # 2. ROUGE
    print("   Computing ROUGE...")
    try:
        rouge_metric = load_metric("rouge")
        rouge_res = rouge_metric.compute(predictions=predictions, references=references)
        results["ROUGE-1"] = rouge_res["rouge1"] * 100
        results["ROUGE-2"] = rouge_res["rouge2"] * 100
        results["ROUGE-L"] = rouge_res["rougeL"] * 100
    except Exception as e:
        print(f"   ⚠️ ROUGE failed: {e}")
    
    # 3. BLEU
    print("   Computing BLEU...")
    try:
        smooth_fn = SmoothingFunction().method1
        bleu_scores = []
        for pred, ref in zip(predictions, references):
            if ref.strip():
                score = sentence_bleu(
                    [ref.split()], pred.split(),
                    weights=(0.25, 0.25, 0.25, 0.25),
                    smoothing_function=smooth_fn
                )
                bleu_scores.append(score)
        results["BLEU"] = np.mean(bleu_scores) * 100 if bleu_scores else 0.0
    except Exception as e:
        print(f"   ⚠️ BLEU failed: {e}")
    
    # 4. BERTScore
    print("   Computing BERTScore...")
    try:
        bert_metric = load_metric("bertscore")
        device = "cuda" if torch.cuda.is_available() else "cpu"
        bert_res = bert_metric.compute(
            predictions=predictions, references=references,
            lang="en", model_type="distilbert-base-uncased", device=device
        )
        results["BERTScore"] = np.mean(bert_res["f1"]) * 100
    except Exception as e:
        print(f"   ⚠️ BERTScore failed: {e}")
    
    results["Total"] = len(predictions)
    return results


def analyze_single_result(result_path: Path, dataset_name: str, recompute: bool = False) -> Optional[AnalysisResult]:
    """단일 결과 파일 분석"""
    data = load_result_file(result_path)
    if not data:
        return None
    
    model_name = data.get("meta", {}).get("model", result_path.parent.name)
    items = data.get("data", [])
    
    if not items:
        return None
    
    print(f"\n{'='*80}")
    print(f"📂 Analyzing: {dataset_name}/{model_name}")
    print(f"   Items: {len(items)}")
    print(f"{'='*80}")
    
    # 메트릭 계산 (기존 메트릭 사용 또는 재계산)
    if recompute or "metrics" not in data or "ROUGE-1" not in data.get("metrics", {}):
        predictions = [item.get("model_answer_parsed", item.get("model_answer_raw", "")) for item in items]
        references = [item.get("gold", "") for item in items]
        metrics = compute_full_metrics(predictions, references, dataset_name)
        
        # 결과 파일 업데이트
        data["metrics"] = metrics
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"   ✓ Metrics updated and saved")
    else:
        metrics = data["metrics"]
        print(f"   ✓ Using cached metrics")
    
    # 결과 출력
    print(f"\n   📊 Metrics:")
    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"      {k:12}: {v:6.2f}%")
        elif isinstance(v, int):
            print(f"      {k:12}: {v}")
    
    return AnalysisResult(
        model_name=model_name,
        dataset_name=dataset_name,
        metrics=metrics,
        evaluated_ids=data.get("evaluated_ids", [item.get("id", str(i)) for i, item in enumerate(items)]),
        total_items=len(items),
    )


def find_intersection_ids(results: List[AnalysisResult]) -> Set[str]:
    """교집합 문항 ID 찾기"""
    if not results:
        return set()
    
    id_sets = [set(r.evaluated_ids) for r in results]
    intersection = id_sets[0]
    for id_set in id_sets[1:]:
        intersection = intersection & id_set
    
    return intersection


def compare_on_intersection(result_dir: Path, dataset_name: str) -> pd.DataFrame:
    """교집합 문항으로만 비교"""
    print(f"\n{'='*80}")
    print(f"🔄 Computing intersection comparison for {dataset_name}")
    print(f"{'='*80}")
    
    # 모든 모델 결과 로드
    model_dirs = [d for d in (result_dir / dataset_name).iterdir() if d.is_dir()]
    all_data = {}
    
    for model_dir in model_dirs:
        result_path = model_dir / "latest.json"
        data = load_result_file(result_path)
        if data:
            all_data[model_dir.name] = data
    
    if len(all_data) < 2:
        print(f"   ⚠️ Need at least 2 models for comparison")
        return pd.DataFrame()
    
    # 교집합 ID 찾기
    id_sets = []
    for model_name, data in all_data.items():
        items = data.get("data", [])
        ids = set(item.get("id", str(i)) for i, item in enumerate(items))
        id_sets.append(ids)
        print(f"   {model_name}: {len(ids)} items")
    
    intersection_ids = id_sets[0]
    for id_set in id_sets[1:]:
        intersection_ids = intersection_ids & id_set
    
    print(f"\n   📌 Intersection: {len(intersection_ids)} items")
    
    if len(intersection_ids) == 0:
        print(f"   ⚠️ No common items found")
        return pd.DataFrame()
    
    # 교집합으로 메트릭 재계산
    dataset = get_dataset(dataset_name)
    comparison_results = []
    
    for model_name, data in all_data.items():
        items = data.get("data", [])
        item_dict = {item.get("id", str(i)): item for i, item in enumerate(items)}
        
        # 교집합 아이템만 추출
        intersection_items = [item_dict[id_] for id_ in intersection_ids if id_ in item_dict]
        
        predictions = [item.get("model_answer_parsed", item.get("model_answer_raw", "")) for item in intersection_items]
        references = [item.get("gold", "") for item in intersection_items]
        
        # 기본 메트릭만 계산 (빠른 비교용)
        em_scores = [dataset.compute_em(p, r) for p, r in zip(predictions, references)]
        f1_scores = [dataset.compute_f1(p, r) for p, r in zip(predictions, references)]
        
        comparison_results.append({
            "Model": model_name,
            "Items": len(intersection_items),
            "EM": np.mean(em_scores) * 100,
            "F1": np.mean(f1_scores) * 100,
        })
        
        if dataset_name == "teleqna":
            comparison_results[-1]["Accuracy"] = comparison_results[-1]["EM"]
    
    df = pd.DataFrame(comparison_results)
    
    # 정렬 (대표 메트릭 기준)
    primary_metric = dataset.primary_metric
    if primary_metric in df.columns:
        df = df.sort_values(primary_metric, ascending=False)
    
    print(f"\n   📊 Intersection Comparison (sorted by {primary_metric}):")
    print(df.to_string(index=False))
    
    return df


def generate_summary_report(result_dir: Path) -> pd.DataFrame:
    """전체 요약 리포트 생성"""
    print(f"\n{'='*80}")
    print(f"📋 Generating Summary Report")
    print(f"{'='*80}")
    
    all_results = []
    
    for dataset_name in DATASET_REGISTRY.keys():
        dataset_dir = result_dir / dataset_name
        if not dataset_dir.exists():
            continue
        
        dataset = get_dataset(dataset_name)
        primary_metric = dataset.primary_metric
        
        for model_dir in dataset_dir.iterdir():
            if not model_dir.is_dir():
                continue
            
            result_path = model_dir / "latest.json"
            data = load_result_file(result_path)
            if not data:
                continue
            
            metrics = data.get("metrics", {})
            
            all_results.append({
                "Dataset": dataset_name,
                "Model": model_dir.name,
                "Primary": primary_metric,
                primary_metric: metrics.get(primary_metric, metrics.get("EM", 0)),
                "EM": metrics.get("EM", 0),
                "F1": metrics.get("F1", 0),
                "ROUGE-L": metrics.get("ROUGE-L", 0),
                "Total": metrics.get("Total", 0),
            })
    
    if not all_results:
        print("   ⚠️ No results found")
        return pd.DataFrame()
    
    df = pd.DataFrame(all_results)
    
    # 데이터셋별 정렬
    print("\n   📊 Summary by Dataset:")
    for dataset_name in df["Dataset"].unique():
        ds_df = df[df["Dataset"] == dataset_name].copy()
        primary = ds_df["Primary"].iloc[0]
        ds_df = ds_df.sort_values(primary, ascending=False)
        print(f"\n   [{dataset_name.upper()}] (Primary: {primary})")
        print(ds_df[["Model", primary, "EM", "F1", "Total"]].to_string(index=False))
    
    # CSV 저장
    report_path = result_dir / "summary_report.csv"
    df.to_csv(report_path, index=False)
    print(f"\n   💾 Report saved: {report_path}")
    
    return df


def main():
    parser = argparse.ArgumentParser(description="External Dataset Result Analyzer")
    parser.add_argument("--dataset", type=str, default=None,
                       help="Specific dataset to analyze (teleqna/telequad/netbench)")
    parser.add_argument("--model", type=str, default=None,
                       help="Specific model to analyze")
    parser.add_argument("--recompute", action="store_true",
                       help="Recompute all metrics (ignore cached)")
    parser.add_argument("--compare", action="store_true",
                       help="Generate intersection comparison report")
    parser.add_argument("--result-dir", type=str, default=None,
                       help="Custom result directory")
    args = parser.parse_args()
    
    result_dir = Path(args.result_dir) if args.result_dir else RESULT_DIR
    
    if not result_dir.exists():
        print(f"❌ Result directory not found: {result_dir}")
        return
    
    print("="*80)
    print("🔍 External Dataset Analyzer")
    print(f"   Result Dir: {result_dir}")
    print("="*80)
    
    # 데이터셋 선택
    if args.dataset:
        dataset_names = [args.dataset]
    else:
        dataset_names = [d.name for d in result_dir.iterdir() if d.is_dir() and d.name in DATASET_REGISTRY]
    
    # 개별 분석
    for dataset_name in dataset_names:
        dataset_dir = result_dir / dataset_name
        if not dataset_dir.exists():
            continue
        
        for model_dir in dataset_dir.iterdir():
            if not model_dir.is_dir():
                continue
            
            if args.model and model_dir.name != args.model:
                continue
            
            result_path = model_dir / "latest.json"
            if result_path.exists():
                analyze_single_result(result_path, dataset_name, args.recompute)
    
    # 교집합 비교
    if args.compare:
        for dataset_name in dataset_names:
            compare_on_intersection(result_dir, dataset_name)
    
    # 요약 리포트
    generate_summary_report(result_dir)


if __name__ == "__main__":
    main()
