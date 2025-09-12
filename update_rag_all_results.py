#!/usr/bin/env python3
"""
rag_all_results.json을 최신 전처리된 ragA_k10.json, ragB_k10.json 성능으로 업데이트
"""
import json
from pathlib import Path

def update_rag_all_results():
    base_dir = Path("runs/exp_ab_k10/results")
    
    # 기존 rag_all_results.json 읽기
    with open(base_dir / "rag_all_results.json", 'r', encoding='utf-8') as f:
        all_results = json.load(f)
    
    print("🔄 rag_all_results.json 업데이트 중...")
    
    # ragA_k10.json에서 최신 evaluation 가져오기
    with open(base_dir / "ragA_k10.json", 'r', encoding='utf-8') as f:
        ragA_data = json.load(f)
        ragA_eval = ragA_data.get('evaluation', {})
        
    # ragB_k10.json에서 최신 evaluation 가져오기  
    with open(base_dir / "ragB_k10.json", 'r', encoding='utf-8') as f:
        ragB_data = json.load(f)
        ragB_eval = ragB_data.get('evaluation', {})
        
    # ragBexp_k10.json도 확인 (혹시나 해서)
    try:
        with open(base_dir / "ragBexp_k10.json", 'r', encoding='utf-8') as f:
            ragBexp_data = json.load(f)
            ragBexp_eval = ragBexp_data.get('evaluation', {})
    except FileNotFoundError:
        ragBexp_eval = {}
    
    # 기존 결과에 최신 evaluation 업데이트
    experiments = all_results.get('experiments', {})
    
    # A_top_k_10 업데이트
    if 'A_top_k_10' in experiments and ragA_eval:
        experiments['A_top_k_10']['evaluation'] = ragA_eval
        print("✅ A_top_k_10 evaluation 업데이트 완료")
        print(f"   Overall EM: {ragA_eval.get('overall', {}).get('exact_match', 0):.4f}")
        print(f"   Overall F1: {ragA_eval.get('overall', {}).get('f1_score', 0):.4f}")
    
    # B_top_k_10 업데이트
    if 'B_top_k_10' in experiments and ragB_eval:
        experiments['B_top_k_10']['evaluation'] = ragB_eval
        print("✅ B_top_k_10 evaluation 업데이트 완료")
        print(f"   Overall EM: {ragB_eval.get('overall', {}).get('exact_match', 0):.4f}")
        print(f"   Overall F1: {ragB_eval.get('overall', {}).get('f1_score', 0):.4f}")
    
    # Bexp_top_k_10 업데이트 (있다면)
    if 'Bexp_top_k_10' in experiments and ragBexp_eval:
        experiments['Bexp_top_k_10']['evaluation'] = ragBexp_eval
        print("✅ Bexp_top_k_10 evaluation 업데이트 완료")
    
    # 백업 생성
    backup_path = base_dir / "rag_all_results_backup.json"
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"📄 기존 파일 백업: {backup_path}")
    
    # 업데이트된 파일 저장
    with open(base_dir / "rag_all_results.json", 'w', encoding='utf-8') as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    
    print("🎉 rag_all_results.json 업데이트 완료!")
    
    # 업데이트 후 최종 성능 요약
    print("\n📊 최종 성능 요약:")
    for exp_name, exp_data in experiments.items():
        eval_data = exp_data.get('evaluation', {})
        overall = eval_data.get('overall', {})
        if overall:
            print(f"  {exp_name}:")
            print(f"    EM: {overall.get('exact_match', 0):.4f}")
            print(f"    F1: {overall.get('f1_score', 0):.4f}")

if __name__ == "__main__":
    update_rag_all_results() 