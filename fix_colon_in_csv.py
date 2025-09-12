#!/usr/bin/env python3
"""
CSV 파일에서 pre_GT 컬럼의 콜론을 직접 제거하고 다시 평가
"""
import pandas as pd
import json
from pathlib import Path
from typing import Dict
from Evaluation.pipeline_v2.common.data_utils import clean_ground_truth_text
from Evaluation.pipeline_v2.common.evaluation import calculate_exact_match, calculate_f1_score, calculate_relaxed_exact_match, calculate_relaxed_f1_score

def fix_colon_in_csv(csv_path: str) -> str:
    """CSV 파일에서 pre_GT 컬럼의 콜론을 제거"""
    print(f"콜론 제거 중: {csv_path}")
    
    # CSV 읽기
    df = pd.read_csv(csv_path)
    
    # pre_GT 컬럼에서 콜론 제거
    original_count = 0
    fixed_count = 0
    
    for i, row in df.iterrows():
        if pd.notna(row['pre_GT']):
            original_text = str(row['pre_GT'])
            if original_text.startswith(': '):
                # 맨 앞의 ': ' 제거
                fixed_text = original_text[2:]  # ': ' (2글자) 제거
                df.at[i, 'pre_GT'] = fixed_text
                fixed_count += 1
            original_count += 1
    
    print(f"전체 pre_GT: {original_count}개")
    print(f"콜론 제거: {fixed_count}개")
    
    # 수정된 파일 저장
    output_path = csv_path.replace('.csv', '_fixed.csv')
    df.to_csv(output_path, index=False)
    
    return output_path

def evaluate_fixed_csv(csv_path: str) -> Dict:
    """콜론이 제거된 CSV 재평가"""
    print(f"재평가 중: {csv_path}")
    
    df = pd.read_csv(csv_path)
    
    # 예측 결과와 정답 정리 (이제 콜론이 이미 제거됨)
    predictions = []
    ground_truths = []
    origins = df['origin'].tolist()
    
    for _, row in df.iterrows():
        # 예측 결과 (이미 콜론 제거됨, 추가 정리만)
        pred_raw = str(row['pre_GT']) if pd.notna(row['pre_GT']) else ""
        pred_clean = clean_ground_truth_text(pred_raw)
        predictions.append(pred_clean)
        
        # 정답 정리
        gt_raw = str(row['ground_truth']) if pd.notna(row['ground_truth']) else ""
        gt_clean = clean_ground_truth_text(gt_raw)
        ground_truths.append(gt_clean)
    
    # 인덱스 그룹 분리
    rule_idx = [i for i, o in enumerate(origins) if o == "rule_based"]
    enhanced_idx = [i for i, o in enumerate(origins) if o == "enhanced_llm_with_agent"]
    
    print(f"Rule-based 질문: {len(rule_idx)}개")
    print(f"Enhanced LLM 질문: {len(enhanced_idx)}개")
    
    # 전체 평가
    overall_em = calculate_exact_match(predictions, ground_truths)
    overall_f1 = calculate_f1_score(predictions, ground_truths)
    overall_em_relaxed = calculate_relaxed_exact_match(predictions, ground_truths)
    overall_f1_relaxed = calculate_relaxed_f1_score(predictions, ground_truths)
    
    # Rule-based 평가 (GT만)
    if rule_idx:
        rule_pred_gt = [predictions[i] for i in rule_idx]
        rule_true_gt = [ground_truths[i] for i in rule_idx]
        rule_em = calculate_exact_match(rule_pred_gt, rule_true_gt)
        rule_f1 = calculate_f1_score(rule_pred_gt, rule_true_gt)
        rule_em_relaxed = calculate_relaxed_exact_match(rule_pred_gt, rule_true_gt)
        rule_f1_relaxed = calculate_relaxed_f1_score(rule_pred_gt, rule_true_gt)
    else:
        rule_em = rule_f1 = rule_em_relaxed = rule_f1_relaxed = 0.0
    
    # Enhanced LLM 평가 (GT + 설명)
    if enhanced_idx:
        enhanced_pred_gt = [predictions[i] for i in enhanced_idx]
        enhanced_true_gt = [ground_truths[i] for i in enhanced_idx]
        enhanced_em = calculate_exact_match(enhanced_pred_gt, enhanced_true_gt)
        enhanced_f1 = calculate_f1_score(enhanced_pred_gt, enhanced_true_gt)
        enhanced_em_relaxed = calculate_relaxed_exact_match(enhanced_pred_gt, enhanced_true_gt)
        enhanced_f1_relaxed = calculate_relaxed_f1_score(enhanced_pred_gt, enhanced_true_gt)
    else:
        enhanced_em = enhanced_f1 = enhanced_em_relaxed = enhanced_f1_relaxed = 0.0
    
    # 샘플 비교 출력
    print(f"\n샘플 비교 (처음 5개):")
    for i in range(min(5, len(predictions))):
        pred = predictions[i]
        gt = ground_truths[i]
        match = pred.strip().lower() == gt.strip().lower()
        print(f"  [{i}] EM: {match}")
        print(f"      GT: '{gt}'")
        print(f"      Pred: '{pred}'")
        print()
    
    results = {
        "total_questions": len(predictions),
        "overall": {
            "exact_match": overall_em,
            "f1_score": overall_f1,
            "exact_match_relaxed": overall_em_relaxed,
            "f1_score_relaxed": overall_f1_relaxed
        },
        "rule_based": {
            "question_count": len(rule_idx),
            "exact_match": rule_em,
            "f1_score": rule_f1,
            "exact_match_relaxed": rule_em_relaxed,
            "f1_score_relaxed": rule_f1_relaxed
        },
        "enhanced_llm_with_agent": {
            "question_count": len(enhanced_idx),
            "exact_match": enhanced_em,
            "f1_score": enhanced_f1,
            "exact_match_relaxed": enhanced_em_relaxed,
            "f1_score_relaxed": enhanced_f1_relaxed
        }
    }
    
    return results

def update_json_with_fixed_evaluation(json_path: str, evaluation_results: Dict):
    """JSON 파일을 수정된 평가 결과로 업데이트"""
    print(f"JSON 파일 최종 업데이트: {json_path}")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 최종 백업 생성
    backup_path = json_path.replace('.json', '_before_colon_fix.json')
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    # evaluation 섹션 교체
    if 'evaluation' in data:
        data['evaluation'] = {
            "overall": {
                "exact_match": evaluation_results["overall"]["exact_match"],
                "f1_score": evaluation_results["overall"]["f1_score"],
                "total_questions": evaluation_results["total_questions"]
            },
            "overall_relaxed": {
                "exact_match": evaluation_results["overall"]["exact_match_relaxed"],
                "f1_score": evaluation_results["overall"]["f1_score_relaxed"],
                "total_questions": evaluation_results["total_questions"]
            },
            "rule_based": {
                "exact_match": evaluation_results["rule_based"]["exact_match"],
                "f1_score": evaluation_results["rule_based"]["f1_score"],
                "question_count": evaluation_results["rule_based"]["question_count"]
            },
            "rule_based_relaxed": {
                "exact_match": evaluation_results["rule_based"]["exact_match_relaxed"],
                "f1_score": evaluation_results["rule_based"]["f1_score_relaxed"],
                "question_count": evaluation_results["rule_based"]["question_count"]
            },
            "enhanced_llm": {
                "ground_truth": {
                    "exact_match": evaluation_results["enhanced_llm_with_agent"]["exact_match"],
                    "f1_score": evaluation_results["enhanced_llm_with_agent"]["f1_score"]
                },
                "explanation": data['evaluation'].get('enhanced_llm', {}).get('explanation', {}),
                "question_count": evaluation_results["enhanced_llm_with_agent"]["question_count"]
            }
        }
    
    # 업데이트된 파일 저장
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def main():
    base_dir = Path("runs/exp_ab_k10/results")
    
    # 처리할 파일들
    files_to_process = [
        ("ragA_after_k10_with_origin.csv", "ragA_k10.json"),
        ("ragB_after_k10_with_origin.csv", "ragB_k10.json"),
    ]
    
    for csv_file, json_file in files_to_process:
        csv_path = base_dir / csv_file
        json_path = base_dir / json_file
        
        if csv_path.exists() and json_path.exists():
            print(f"\n{'='*70}")
            print(f"최종 콜론 제거 처리: {csv_file} -> {json_file}")
            print(f"{'='*70}")
            
            # 1. CSV에서 콜론 직접 제거
            fixed_csv = fix_colon_in_csv(str(csv_path))
            print(f"✅ 콜론이 제거된 파일: {fixed_csv}")
            
            # 2. 재평가
            evaluation_results = evaluate_fixed_csv(fixed_csv)
            
            # 3. 결과 출력
            print(f"\n🎯 최종 결과:")
            print(f"  전체 질문: {evaluation_results['total_questions']}개")
            print(f"  Overall EM: {evaluation_results['overall']['exact_match']:.4f}")
            print(f"  Overall F1: {evaluation_results['overall']['f1_score']:.4f}")
            print(f"  Rule-based ({evaluation_results['rule_based']['question_count']}개):")
            print(f"    EM: {evaluation_results['rule_based']['exact_match']:.4f}")
            print(f"    F1: {evaluation_results['rule_based']['f1_score']:.4f}")
            print(f"  Enhanced LLM ({evaluation_results['enhanced_llm_with_agent']['question_count']}개):")
            print(f"    EM: {evaluation_results['enhanced_llm_with_agent']['exact_match']:.4f}")
            print(f"    F1: {evaluation_results['enhanced_llm_with_agent']['f1_score']:.4f}")
            
            # 4. JSON 파일 최종 업데이트
            update_json_with_fixed_evaluation(str(json_path), evaluation_results)
            print(f"✅ {json_file} 최종 업데이트 완료")
            
        else:
            print(f"⚠️  파일을 찾을 수 없습니다: {csv_file} 또는 {json_file}")
    
    print(f"\n{'='*70}")
    print("🎉 모든 콜론 제거 및 최종 평가 완료!")
    print("이제 진짜 정확한 성능 결과가 나왔습니다!")
    print(f"{'='*70}")

if __name__ == "__main__":
    main() 