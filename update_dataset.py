#!/usr/bin/env python3
"""
데이터셋 업데이트 스크립트
dataset_for_evaluation_fin.csv에서 origin=rule_based인 데이터를 
basic_dataset.csv의 데이터로 교체하는 스크립트
"""

import csv
import os
from typing import List, Dict

def read_csv_file(filepath: str) -> List[Dict[str, str]]:
    """CSV 파일을 읽어서 딕셔너리 리스트로 반환"""
    data = []
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data

def write_csv_file(filepath: str, data: List[Dict[str, str]], fieldnames: List[str]):
    """딕셔너리 리스트를 CSV 파일로 저장"""
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def update_evaluation_dataset():
    """데이터셋 업데이트 수행"""
    
    # 파일 경로 설정
    basic_dataset_path = 'output/basic_dataset.csv'
    eval_dataset_path = 'Data/Dataset/dataset_for_evaluation_fin.csv'
    backup_path = 'Data/Dataset/dataset_for_evaluation_fin_backup.csv'
    
    print("=== 데이터셋 업데이트 시작 ===")
    
    # 파일 존재 확인
    if not os.path.exists(basic_dataset_path):
        print(f"ERROR: {basic_dataset_path} 파일이 존재하지 않습니다.")
        return False
    
    if not os.path.exists(eval_dataset_path):
        print(f"ERROR: {eval_dataset_path} 파일이 존재하지 않습니다.")
        return False
    
    # 기본 데이터셋 읽기
    print(f"기본 데이터셋 읽는 중: {basic_dataset_path}")
    basic_data = read_csv_file(basic_dataset_path)
    print(f"기본 데이터셋 레코드 수: {len(basic_data)}")
    
    # 평가 데이터셋 읽기
    print(f"평가 데이터셋 읽는 중: {eval_dataset_path}")
    eval_data = read_csv_file(eval_dataset_path)
    print(f"평가 데이터셋 레코드 수: {len(eval_data)}")
    
    # 백업 생성
    print(f"백업 생성 중: {backup_path}")
    if eval_data:
        fieldnames = list(eval_data[0].keys())
        write_csv_file(backup_path, eval_data, fieldnames)
        print("백업 완료")
    
    # Origin별 데이터 분류
    rule_based_count = len([row for row in eval_data if row['origin'] == 'rule_based'])
    non_rule_based = [row for row in eval_data if row['origin'] != 'rule_based']
    
    print(f"기존 rule_based 데이터: {rule_based_count}개")
    print(f"기존 non-rule_based 데이터: {len(non_rule_based)}개")
    
    # 새로운 데이터셋 생성 (기본 데이터 + non-rule_based 데이터)
    updated_data = basic_data + non_rule_based
    
    print(f"업데이트된 데이터셋 레코드 수: {len(updated_data)}")
    print(f"- 기본 데이터셋에서: {len(basic_data)}개")
    print(f"- 기존 non-rule_based에서: {len(non_rule_based)}개")
    
    # 업데이트된 데이터셋 저장
    if updated_data:
        fieldnames = list(updated_data[0].keys())
        write_csv_file(eval_dataset_path, updated_data, fieldnames)
        print(f"업데이트 완료: {eval_dataset_path}")
    else:
        print("ERROR: 업데이트할 데이터가 없습니다.")
        return False
    
    # 결과 검증
    print("\n=== 업데이트 결과 검증 ===")
    updated_eval_data = read_csv_file(eval_dataset_path)
    
    origin_counts = {}
    for row in updated_eval_data:
        origin = row['origin']
        origin_counts[origin] = origin_counts.get(origin, 0) + 1
    
    print("Origin 값별 데이터 개수:")
    for origin, count in sorted(origin_counts.items()):
        print(f"  - {origin}: {count}개")
    
    print(f"총 레코드 수: {len(updated_eval_data)}")
    print("=== 업데이트 완료 ===")
    
    return True

if __name__ == "__main__":
    success = update_evaluation_dataset()
    if success:
        print("\n✅ 데이터셋 업데이트가 성공적으로 완료되었습니다!")
    else:
        print("\n❌ 데이터셋 업데이트 중 오류가 발생했습니다.") 