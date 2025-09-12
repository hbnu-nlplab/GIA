#!/usr/bin/env python3
"""
기존 실험 결과를 재처리하여 콜론 제거 후 올바른 EM/F1 점수를 계산
"""
import pandas as pd
import json
from pathlib import Path
from typing import List, Dict
from Evaluation.pipeline_v2.common.data_utils import clean_ground_truth_text
from Evaluation.pipeline_v2.common.evaluation import calculate_exact_match, calculate_f1_score, calculate_relaxed_exact_match, calculate_relaxed_f1_score

def reprocess_csv_results(csv_path: str) -> Dict:
    """CSV 결과를 재처리하여 올바른 평가 점수 계산"""
    print(f"재처리 중: {csv_path}")
    
    # CSV 파일 읽기
    df = pd.read_csv(csv_path)
    
    # 예측 결과와 정답 정리
    predictions = []
    ground_truths = []
    
    for _, row in df.iterrows():
        # 예측 결과 정리 (콜론 제거 적용)
        pred_raw = str(row['pre_GT']) if pd.notna(row['pre_GT']) else ""
        pred_clean = clean_ground_truth_text(pred_raw)
        predictions.append(pred_clean)
        
        # 정답 정리
        gt_raw = str(row['ground_truth']) if pd.notna(row['ground_truth']) else ""
        gt_clean = clean_ground_truth_text(gt_raw)
        ground_truths.append(gt_clean)
    
    # 평가 지표 계산
    em = calculate_exact_match(predictions, ground_truths)
    f1 = calculate_f1_score(predictions, ground_truths)
    em_relaxed = calculate_relaxed_exact_match(predictions, ground_truths)
    f1_relaxed = calculate_relaxed_f1_score(predictions, ground_truths)
    
    results = {
        "total_questions": len(predictions),
        "exact_match": em,
        "f1_score": f1,
        "exact_match_relaxed": em_relaxed,
        "f1_score_relaxed": f1_relaxed,
        "sample_comparisons": []
    }
    
    # 샘플 비교 (처음 5개)
    for i in range(min(5, len(predictions))):
        results["sample_comparisons"].append({
            "index": i,
            "question": str(df.iloc[i]['question']),
            "ground_truth": ground_truths[i],
            "prediction_raw": str(df.iloc[i]['pre_GT']),
            "prediction_clean": predictions[i],
            "em_match": predictions[i].strip().lower() == ground_truths[i].strip().lower()
        })
    
    return results

def update_json_results(json_path: str, new_scores: Dict):
    """JSON 결과 파일의 평가 점수 업데이트"""
    print(f"JSON 파일 업데이트: {json_path}")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 전체 평가 결과 업데이트
    if 'evaluation' in data:
        # overall 점수 업데이트
        if 'overall' in data['evaluation']:
            data['evaluation']['overall']['exact_match'] = new_scores['exact_match']
            data['evaluation']['overall']['f1_score'] = new_scores['f1_score']
        
        # overall_relaxed 점수 업데이트
        if 'overall_relaxed' in data['evaluation']:
            data['evaluation']['overall_relaxed']['exact_match'] = new_scores['exact_match_relaxed']
            data['evaluation']['overall_relaxed']['f1_score'] = new_scores['f1_score_relaxed']
        
        # enhanced_llm ground_truth 점수 업데이트
        if 'enhanced_llm' in data['evaluation'] and 'ground_truth' in data['evaluation']['enhanced_llm']:
            data['evaluation']['enhanced_llm']['ground_truth']['exact_match'] = new_scores['exact_match']
            data['evaluation']['enhanced_llm']['ground_truth']['f1_score'] = new_scores['f1_score']
    
    # 백업 파일 생성
    backup_path = json_path.replace('.json', '_backup.json')
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(json.load(open(json_path, 'r', encoding='utf-8')), f, ensure_ascii=False, indent=2)
    
    # 업데이트된 파일 저장
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def main():
    base_dir = Path("runs/exp_ab_k10/results")
    
    # 재처리할 파일들
    files_to_process = [
        ("ragB_after_k10.csv", "ragB_k10.json"),
        ("ragBexp_after_k10.csv", "ragBexp_k10.json"),
    ]
    
    for csv_file, json_file in files_to_process:
        csv_path = base_dir / csv_file
        json_path = base_dir / json_file
        
        if csv_path.exists() and json_path.exists():
            print(f"\n{'='*50}")
            print(f"처리 중: {csv_file} -> {json_file}")
            print(f"{'='*50}")
            
            # CSV 재처리
            new_scores = reprocess_csv_results(str(csv_path))
            
            # 결과 출력
            print(f"\n재처리 결과:")
            print(f"  Total Questions: {new_scores['total_questions']}")
            print(f"  Exact Match: {new_scores['exact_match']:.4f}")
            print(f"  F1 Score: {new_scores['f1_score']:.4f}")
            print(f"  Exact Match (Relaxed): {new_scores['exact_match_relaxed']:.4f}")
            print(f"  F1 Score (Relaxed): {new_scores['f1_score_relaxed']:.4f}")
            
            print(f"\n샘플 비교:")
            for sample in new_scores['sample_comparisons']:
                print(f"  [{sample['index']}] EM Match: {sample['em_match']}")
                print(f"      Question: {sample['question'][:80]}...")
                print(f"      GT: {sample['ground_truth']}")
                print(f"      Pred (raw): {sample['prediction_raw']}")
                print(f"      Pred (clean): {sample['prediction_clean']}")
                print()
            
            # JSON 파일 업데이트
            update_json_results(str(json_path), new_scores)
            print(f"✅ {json_file} 업데이트 완료")
        else:
            print(f"⚠️  파일을 찾을 수 없습니다: {csv_file} 또는 {json_file}")
    
    print(f"\n{'='*50}")
    print("모든 파일 재처리 완료!")
    print("백업 파일들이 _backup.json으로 생성되었습니다.")
    print("이제 compare_results.py를 실행하여 업데이트된 결과를 확인하세요.")
    print(f"{'='*50}")

if __name__ == "__main__":
    main() 