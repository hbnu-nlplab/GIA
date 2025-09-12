#!/usr/bin/env python3
"""
고급 전처리: TRUE/False 통일, 코드블록 제거, 마크다운 요소 제거
"""
import pandas as pd
import json
import re
from pathlib import Path
from typing import Dict
from Evaluation.pipeline_v2.common.data_utils import clean_ground_truth_text
from Evaluation.pipeline_v2.common.evaluation import calculate_exact_match, calculate_f1_score, calculate_relaxed_exact_match, calculate_relaxed_f1_score

def advanced_clean_text(text: str, question: str = None) -> str:
    """고급 텍스트 정리"""
    if not text or pd.isna(text):
        return ""
    
    text = str(text).strip()
    
    # 1. 코드 블록 제거 (```bash, ```, etc.)
    text = re.sub(r'```(?:bash|python|sh|shell)?\s*([^`]*?)```', r'\1', text, flags=re.DOTALL)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    
    # 2. 마크다운 요소 제거
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)  # **bold**
    text = re.sub(r'\*(.*?)\*', r'\1', text)      # *italic*
    text = re.sub(r'_(.*?)_', r'\1', text)        # _underline_
    
    # 3. 대시(-) 시작 제거
    text = re.sub(r'^-\s*', '', text.strip())
    
    # 4. TRUE/FALSE 표준화
    text = text.strip()
    if text.upper() in ['TRUE', 'True', 'true', 'T']:
        return 'TRUE'
    elif text.upper() in ['FALSE', 'False', 'false', 'F']:
        return 'FALSE'
    
    # 5. user@ vs nso@ 통일 (nso@ -> user@)
    text = re.sub(r'\bnso@', 'user@', text)
    
    # 6. 화살표 vs 쉼표 순서 정규화 (질문에서 화살표를 요구하는 경우에만)
    # 질문에 "→" 또는 "장비명→장비명" 패턴이 있는 경우에만 처리
    if question and ('→' in question or '장비명→' in question or '정답 형식:' in question and '→' in question):
        if ',' in text and ('sample' in text.lower() or 'ce' in text.lower()):
            # 장비명으로 보이는 것들을 화살표로 연결 시도
            parts = [p.strip() for p in text.split(',')]
            equipment_parts = []
            other_parts = []
            
            for part in parts:
                # 장비명 패턴 확인 (sample7, CE1, IP 주소 등)
                if (re.match(r'^(sample\d+|CE\d+|\d+\.\d+\.\d+\.\d+)$', part.strip()) or 
                    part.strip() in ['sample7', 'sample8', 'sample9', 'sample10', 'CE1', 'CE2']):
                    equipment_parts.append(part.strip())
                else:
                    other_parts.append(part.strip())
            
            # 장비가 2개 이상이면 화살표로 연결
            if len(equipment_parts) >= 2:
                equipment_str = '→'.join(equipment_parts)
                if other_parts:
                    text = equipment_str + ',' + ','.join(other_parts)
                else:
                    text = equipment_str
    
    # 7. 기본 정리 (공백, 특수문자)
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

def apply_advanced_preprocessing(csv_path: str) -> str:
    """CSV 파일에 고급 전처리 적용"""
    print(f"고급 전처리 적용 중: {csv_path}")
    
    # CSV 파싱 문제 해결을 위해 더 강력한 옵션 적용
    df = pd.read_csv(csv_path, sep=',', quotechar='"', skipinitialspace=True, on_bad_lines='skip')
    
    # pre_GT와 ground_truth 모두 전처리 적용
    pre_gt_changes = 0
    gt_changes = 0
    
    print("\n변경 사례들:")
    for i, row in df.iterrows():
        # pre_GT 전처리 (질문 컨텍스트 포함)
        if pd.notna(row['pre_GT']):
            original_pred = str(row['pre_GT'])
            question = str(row.get('question', '')) if 'question' in df.columns else None
            cleaned_pred = advanced_clean_text(original_pred, question)
            if original_pred != cleaned_pred:
                df.at[i, 'pre_GT'] = cleaned_pred
                pre_gt_changes += 1
                if pre_gt_changes <= 5:  # 처음 5개 예시 출력
                    print(f"  pre_GT[{i}]: '{original_pred}' -> '{cleaned_pred}'")
        
        # ground_truth 전처리 (비교를 위해)
        if pd.notna(row['ground_truth']):
            original_gt = str(row['ground_truth'])
            question = str(row.get('question', '')) if 'question' in df.columns else None
            cleaned_gt = advanced_clean_text(original_gt, question)
            if original_gt != cleaned_gt:
                df.at[i, 'ground_truth'] = cleaned_gt
                gt_changes += 1
                if gt_changes <= 5:  # 처음 5개 예시 출력
                    print(f"  ground_truth[{i}]: '{original_gt}' -> '{cleaned_gt}'")
    
    print(f"\n전처리 결과:")
    print(f"  pre_GT 변경: {pre_gt_changes}개")
    print(f"  ground_truth 변경: {gt_changes}개")
    
    # 저장
    output_path = csv_path.replace('.csv', '_advanced.csv')
    df.to_csv(output_path, index=False)
    
    return output_path

def evaluate_advanced_csv(csv_path: str) -> Dict:
    """고급 전처리된 CSV 재평가"""
    print(f"\n고급 전처리 결과 재평가: {csv_path}")
    
    df = pd.read_csv(csv_path, sep=',', quotechar='"', skipinitialspace=True, on_bad_lines='skip')
    
    # 예측 결과와 정답 정리 (추가 정리)
    predictions = []
    ground_truths = []
    origins = df['origin'].tolist()
    
    for _, row in df.iterrows():
        # 예측 결과 (이미 고급 전처리됨, 기본 정리만 추가)
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
    
    # TRUE/FALSE 매칭 체크
    true_false_matches = 0
    true_false_total = 0
    
    for i, (pred, gt) in enumerate(zip(predictions, ground_truths)):
        if gt.upper() in ['TRUE', 'FALSE'] or pred.upper() in ['TRUE', 'FALSE']:
            true_false_total += 1
            if pred.upper() == gt.upper():
                true_false_matches += 1
    
    if true_false_total > 0:
        print(f"TRUE/FALSE 질문: {true_false_matches}/{true_false_total} 매칭 ({true_false_matches/true_false_total*100:.1f}%)")
    
    # 전체 평가
    overall_em = calculate_exact_match(predictions, ground_truths)
    overall_f1 = calculate_f1_score(predictions, ground_truths)
    overall_em_relaxed = calculate_relaxed_exact_match(predictions, ground_truths)
    overall_f1_relaxed = calculate_relaxed_f1_score(predictions, ground_truths)
    
    # Rule-based 평가
    if rule_idx:
        rule_pred_gt = [predictions[i] for i in rule_idx]
        rule_true_gt = [ground_truths[i] for i in rule_idx]
        rule_em = calculate_exact_match(rule_pred_gt, rule_true_gt)
        rule_f1 = calculate_f1_score(rule_pred_gt, rule_true_gt)
        rule_em_relaxed = calculate_relaxed_exact_match(rule_pred_gt, rule_true_gt)
        rule_f1_relaxed = calculate_relaxed_f1_score(rule_pred_gt, rule_true_gt)
    else:
        rule_em = rule_f1 = rule_em_relaxed = rule_f1_relaxed = 0.0
    
    # Enhanced LLM 평가
    if enhanced_idx:
        enhanced_pred_gt = [predictions[i] for i in enhanced_idx]
        enhanced_true_gt = [ground_truths[i] for i in enhanced_idx]
        enhanced_em = calculate_exact_match(enhanced_pred_gt, enhanced_true_gt)
        enhanced_f1 = calculate_f1_score(enhanced_pred_gt, enhanced_true_gt)
        enhanced_em_relaxed = calculate_relaxed_exact_match(enhanced_pred_gt, enhanced_true_gt)
        enhanced_f1_relaxed = calculate_relaxed_f1_score(enhanced_pred_gt, enhanced_true_gt)
    else:
        enhanced_em = enhanced_f1 = enhanced_em_relaxed = enhanced_f1_relaxed = 0.0
    
    # 샘플 비교 출력 (TRUE/FALSE 우선)
    print(f"\n샘플 비교 (TRUE/FALSE 우선):")
    shown_samples = 0
    for i, (pred, gt) in enumerate(zip(predictions, ground_truths)):
        if shown_samples >= 10:
            break
        if gt.upper() in ['TRUE', 'FALSE'] or pred.upper() in ['TRUE', 'FALSE']:
            match = pred.upper() == gt.upper()
            print(f"  [{i}] EM: {match}")
            print(f"      GT: '{gt}'")
            print(f"      Pred: '{pred}'")
            print()
            shown_samples += 1
    
    # 일반 샘플들도 몇개 보여주기
    if shown_samples < 5:
        print(f"일반 샘플들:")
        for i in range(min(5-shown_samples, len(predictions))):
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

def update_json_with_advanced_evaluation(json_path: str, evaluation_results: Dict):
    """JSON 파일을 고급 전처리 결과로 업데이트"""
    print(f"JSON 파일 고급 업데이트: {json_path}")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 고급 백업 생성
    backup_path = json_path.replace('.json', '_before_advanced.json')
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
        ("ragA_after_k10_with_origin_fixed.csv", "ragA_k10.json"),
        ("ragB_after_k10_with_origin_fixed.csv", "ragB_k10.json"),
    ]
    
    for csv_file, json_file in files_to_process:
        csv_path = base_dir / csv_file
        json_path = base_dir / json_file
        
        if csv_path.exists() and json_path.exists():
            print(f"\n{'='*80}")
            print(f"고급 전처리: {csv_file} -> {json_file}")
            print(f"{'='*80}")
            
            # 1. 고급 전처리 적용
            advanced_csv = apply_advanced_preprocessing(str(csv_path))
            print(f"✅ 고급 전처리 완료: {advanced_csv}")
            
            # 2. 재평가
            evaluation_results = evaluate_advanced_csv(advanced_csv)
            
            # 3. 결과 출력
            print(f"\n🚀 최종 고급 전처리 결과:")
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
            update_json_with_advanced_evaluation(str(json_path), evaluation_results)
            print(f"✅ {json_file} 고급 업데이트 완료")
            
        else:
            print(f"⚠️  파일을 찾을 수 없습니다: {csv_file} 또는 {json_file}")
    
    print(f"\n{'='*80}")
    print("🎉 모든 고급 전처리 및 최종 평가 완료!")
    print("TRUE/FALSE 통일, 코드블록 제거, 마크다운 정리 모두 적용됨!")
    print(f"{'='*80}")

if __name__ == "__main__":
    main() 