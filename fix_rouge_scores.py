#!/usr/bin/env python3
"""
ROUGE 점수를 직접 올바르게 계산해서 JSON 파일 업데이트
"""
import json
import pandas as pd
from pathlib import Path
from typing import List, Dict

try:
    from rouge import Rouge
    rouge_available = True
except Exception:
    rouge_available = False

def calculate_rouge_properly(pred_explanations: List[str], gt_explanations: List[str]) -> Dict[str, float]:
    """Enhanced LLM 설명들에 대해 올바른 ROUGE 점수 계산"""
    if not rouge_available:
        print("❌ Rouge 패키지를 사용할 수 없습니다!")
        return {"rouge_1_f1": 0.0, "rouge_2_f1": 0.0, "rouge_l_f1": 0.0}
    
    # 빈 설명 제거
    valid_pairs = []
    for pred, gt in zip(pred_explanations, gt_explanations):
        pred_clean = str(pred).strip()
        gt_clean = str(gt).strip()
        if len(pred_clean) > 5 and len(gt_clean) > 5:  # 최소 길이 확인
            valid_pairs.append((pred_clean, gt_clean))
    
    if not valid_pairs:
        print("⚠️  유효한 설명 쌍이 없습니다!")
        return {"rouge_1_f1": 0.0, "rouge_2_f1": 0.0, "rouge_l_f1": 0.0}
    
    print(f"📊 유효한 설명 쌍: {len(valid_pairs)}개")
    
    # ROUGE 계산
    rouge = Rouge()
    preds = [pair[0] for pair in valid_pairs]
    refs = [pair[1] for pair in valid_pairs]
    
    try:
        scores = rouge.get_scores(preds, refs, avg=True)
        result = {
            "rouge_1_f1": scores["rouge-1"]["f"],
            "rouge_2_f1": scores["rouge-2"]["f"], 
            "rouge_l_f1": scores["rouge-l"]["f"]
        }
        print(f"✅ 계산된 ROUGE 점수:")
        print(f"   ROUGE-1 F1: {result['rouge_1_f1']:.4f}")
        print(f"   ROUGE-2 F1: {result['rouge_2_f1']:.4f}") 
        print(f"   ROUGE-L F1: {result['rouge_l_f1']:.4f}")
        return result
    except Exception as e:
        print(f"❌ ROUGE 계산 실패: {e}")
        return {"rouge_1_f1": 0.0, "rouge_2_f1": 0.0, "rouge_l_f1": 0.0}

def fix_rouge_in_json(json_path: str, csv_path: str):
    """JSON 파일의 ROUGE 점수를 올바르게 수정"""
    print(f"\n🔧 {Path(json_path).name} ROUGE 점수 수정 중...")
    
    # CSV에서 Enhanced LLM 데이터 로드
    df = pd.read_csv(csv_path)
    enhanced_df = df[df['origin'] == 'enhanced_llm_with_agent']
    
    print(f"📋 Enhanced LLM 질문: {len(enhanced_df)}개")
    
    # 예측과 정답 설명 추출
    pred_explanations = []
    gt_explanations = []
    
    for _, row in enhanced_df.iterrows():
        pred_exp = str(row['pre_EX']) if 'pre_EX' in enhanced_df.columns else ""
        gt_exp = str(row['explanation'])
        pred_explanations.append(pred_exp)
        gt_explanations.append(gt_exp)
    
    # 올바른 ROUGE 점수 계산
    rouge_scores = calculate_rouge_properly(pred_explanations, gt_explanations)
    
    # JSON 파일 업데이트
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # evaluation.enhanced_llm.explanation 부분 업데이트
    if 'evaluation' in data and 'enhanced_llm' in data['evaluation']:
        explanation_section = data['evaluation']['enhanced_llm'].get('explanation', {})
        explanation_section.update(rouge_scores)
        data['evaluation']['enhanced_llm']['explanation'] = explanation_section
        print("✅ JSON evaluation.enhanced_llm.explanation 섹션 업데이트 완료")
    
    # 백업 생성
    backup_path = str(json_path).replace('.json', '_rouge_backup.json')
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"📄 백업 생성: {backup_path}")
    
    # 업데이트된 파일 저장
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    print(f"🎉 {Path(json_path).name} ROUGE 점수 수정 완료!")

def main():
    base_dir = Path("runs/exp_ab_k10/results")
    
    # ragA 수정
    fix_rouge_in_json(
        str(base_dir / "ragA_k10.json"),
        str(base_dir / "ragA_after_k10_with_origin_fixed_advanced.csv")
    )
    
    # ragB 수정  
    fix_rouge_in_json(
        str(base_dir / "ragB_k10.json"),
        str(base_dir / "ragB_after_k10_with_origin_fixed_advanced.csv")
    )
    
    print("\n🚀 모든 ROUGE 점수 수정 완료! 이제 rag_all_results.json도 업데이트해야 합니다.")

if __name__ == "__main__":
    main() 