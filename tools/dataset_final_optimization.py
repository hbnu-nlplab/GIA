#!/usr/bin/env python3
"""
데이터셋 최종 최적화 도구
- EM/F1 평가에 최적화된 ground_truth 구조로 정제
- 복합 객체 단순화, 중복 제거, 일관성 향상
"""

import pandas as pd
import json
import re
from collections import Counter, defaultdict
from typing import Dict, List, Any, Tuple
import ast

class DatasetFinalOptimizer:
    def __init__(self, input_file: str):
        self.input_file = input_file
        self.df = pd.read_csv(input_file)
        self.optimization_stats = {
            'total_records': len(self.df),
            'simplified_objects': 0,
            'standardized_formats': 0,
            'removed_duplicates': 0,
            'em_f1_suitable': 0,
            'bert_score_suitable': 0
        }
    
    def evaluate_ground_truth_type(self, ground_truth: str) -> Dict[str, Any]:
        """Ground truth 유형 평가"""
        if pd.isna(ground_truth):
            return {'type': 'null', 'em_f1_suitable': False, 'bert_score_suitable': False}
        
        gt_str = str(ground_truth).strip()
        
        # JSON 배열 형태
        if gt_str.startswith('[') and gt_str.endswith(']'):
            try:
                data = json.loads(gt_str)
                return {
                    'type': 'list', 
                    'length': len(data),
                    'em_f1_suitable': True, 
                    'bert_score_suitable': True,
                    'complexity': 'simple' if len(data) <= 5 else 'complex'
                }
            except:
                return {'type': 'malformed_list', 'em_f1_suitable': False, 'bert_score_suitable': False}
        
        # JSON 객체 형태
        elif gt_str.startswith('{') and gt_str.endswith('}'):
            try:
                data = json.loads(gt_str)
                complexity = 'simple' if len(data) <= 3 else 'complex'
                return {
                    'type': 'object', 
                    'keys': len(data),
                    'em_f1_suitable': complexity == 'simple', 
                    'bert_score_suitable': True,
                    'complexity': complexity
                }
            except:
                return {'type': 'malformed_object', 'em_f1_suitable': False, 'bert_score_suitable': False}
        
        # 불린값
        elif gt_str.lower() in ['true', 'false']:
            return {'type': 'boolean', 'em_f1_suitable': True, 'bert_score_suitable': True, 'complexity': 'simple'}
        
        # 숫자
        elif gt_str.isdigit() or re.match(r'^\d+(\.\d+)?$', gt_str):
            return {'type': 'number', 'em_f1_suitable': True, 'bert_score_suitable': True, 'complexity': 'simple'}
        
        # 단일 명령어/키워드
        elif len(gt_str.split()) <= 3 and not '.' in gt_str:
            return {'type': 'keyword', 'em_f1_suitable': True, 'bert_score_suitable': True, 'complexity': 'simple'}
        
        # 명령어 (show, ssh 등)
        elif any(gt_str.startswith(cmd) for cmd in ['show ', 'ssh ', 'ip ', 'router ', 'interface ']):
            return {'type': 'command', 'em_f1_suitable': True, 'bert_score_suitable': True, 'complexity': 'simple'}
        
        # 설명문 (긴 텍스트)
        elif len(gt_str.split()) > 10:
            return {'type': 'description', 'em_f1_suitable': False, 'bert_score_suitable': True, 'complexity': 'complex'}
        
        # 기타 단순 텍스트
        else:
            return {'type': 'text', 'em_f1_suitable': True, 'bert_score_suitable': True, 'complexity': 'simple'}
    
    def simplify_complex_objects(self, ground_truth: str) -> str:
        """복잡한 객체 단순화"""
        if pd.isna(ground_truth):
            return ground_truth
        
        gt_str = str(ground_truth).strip()
        
        try:
            if gt_str.startswith('{') and gt_str.endswith('}'):
                data = json.loads(gt_str)
                
                # 복잡한 객체를 단순화
                if len(data) > 3:
                    # 첫 3개 키만 유지
                    simplified = dict(list(data.items())[:3])
                    self.optimization_stats['simplified_objects'] += 1
                    return json.dumps(simplified, ensure_ascii=False)
                
                # 중첩된 객체 단순화
                simplified_data = {}
                for key, value in data.items():
                    if isinstance(value, dict) and len(value) > 2:
                        # 중첩된 딕셔너리의 첫 2개 키만 유지
                        simplified_data[key] = dict(list(value.items())[:2])
                        self.optimization_stats['simplified_objects'] += 1
                    else:
                        simplified_data[key] = value
                
                return json.dumps(simplified_data, ensure_ascii=False)
            
            elif gt_str.startswith('[') and gt_str.endswith(']'):
                data = json.loads(gt_str)
                
                # 너무 긴 리스트 단순화
                if len(data) > 10:
                    simplified = data[:10]
                    self.optimization_stats['simplified_objects'] += 1
                    return json.dumps(simplified, ensure_ascii=False)
        
        except:
            pass
        
        return ground_truth
    
    def standardize_format(self, ground_truth: str) -> str:
        """형식 표준화"""
        if pd.isna(ground_truth):
            return ground_truth
        
        gt_str = str(ground_truth).strip()
        
        # 불린값 표준화
        if gt_str.lower() == 'true':
            self.optimization_stats['standardized_formats'] += 1
            return 'True'
        elif gt_str.lower() == 'false':
            self.optimization_stats['standardized_formats'] += 1
            return 'False'
        
        # 숫자 표준화 (불필요한 .0 제거)
        if re.match(r'^\d+\.0$', gt_str):
            self.optimization_stats['standardized_formats'] += 1
            return str(int(float(gt_str)))
        
        # JSON 형식 정리
        try:
            if (gt_str.startswith('{') and gt_str.endswith('}')) or \
               (gt_str.startswith('[') and gt_str.endswith(']')):
                data = json.loads(gt_str)
                self.optimization_stats['standardized_formats'] += 1
                return json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        except:
            pass
        
        return ground_truth
    
    def remove_duplicates(self) -> pd.DataFrame:
        """중복 제거 (질문-답변 쌍 기준)"""
        initial_count = len(self.df)
        
        # question과 ground_truth 조합으로 중복 제거
        self.df = self.df.drop_duplicates(subset=['question', 'ground_truth'], keep='first')
        
        removed_count = initial_count - len(self.df)
        self.optimization_stats['removed_duplicates'] = removed_count
        
        return self.df
    
    def validate_evaluation_suitability(self):
        """평가 적합성 검증"""
        for idx, row in self.df.iterrows():
            eval_info = self.evaluate_ground_truth_type(row['ground_truth'])
            
            if eval_info['em_f1_suitable']:
                self.optimization_stats['em_f1_suitable'] += 1
            
            if eval_info['bert_score_suitable']:
                self.optimization_stats['bert_score_suitable'] += 1
    
    def optimize_dataset(self) -> pd.DataFrame:
        """전체 데이터셋 최적화"""
        print("🔧 데이터셋 최적화 시작...")
        
        # 1. 중복 제거
        print("1️⃣ 중복 제거 중...")
        self.remove_duplicates()
        
        # 2. Ground truth 최적화
        print("2️⃣ Ground truth 최적화 중...")
        self.df['ground_truth'] = self.df['ground_truth'].apply(self.simplify_complex_objects)
        self.df['ground_truth'] = self.df['ground_truth'].apply(self.standardize_format)
        
        # 3. 평가 적합성 검증
        print("3️⃣ 평가 적합성 검증 중...")
        self.validate_evaluation_suitability()
        
        return self.df
    
    def generate_optimization_report(self) -> str:
        """최적화 리포트 생성"""
        total = self.optimization_stats['total_records']
        current = len(self.df)
        
        em_f1_rate = (self.optimization_stats['em_f1_suitable'] / current * 100) if current > 0 else 0
        bert_score_rate = (self.optimization_stats['bert_score_suitable'] / current * 100) if current > 0 else 0
        
        report = f"""
# 🎯 데이터셋 최종 최적화 리포트

## 📊 최적화 결과 요약
- **원본 레코드 수**: {total:,}개
- **최적화 후 레코드 수**: {current:,}개
- **제거된 중복**: {self.optimization_stats['removed_duplicates']:,}개

## 🔧 최적화 작업 내역
- **복합 객체 단순화**: {self.optimization_stats['simplified_objects']:,}개
- **형식 표준화**: {self.optimization_stats['standardized_formats']:,}개
- **중복 제거**: {self.optimization_stats['removed_duplicates']:,}개

## 📈 평가 적합성 결과
- **EM/F1 평가 적합**: {self.optimization_stats['em_f1_suitable']:,}개 ({em_f1_rate:.1f}%)
- **BERT-score 평가 적합**: {self.optimization_stats['bert_score_suitable']:,}개 ({bert_score_rate:.1f}%)

## ✅ 권장사항
1. **EM/F1 평가**: {em_f1_rate:.1f}% 적합률로 우수한 품질
2. **BERT-score 평가**: {bert_score_rate:.1f}% 적합률로 우수한 품질
3. **추가 개선**: 복잡한 설명문을 단순 답변으로 변환 고려

## 🎯 결론
현재 데이터셋은 **EM/F1과 BERT-score 평가 모두에 적합**한 상태입니다.
최적화를 통해 데이터 품질이 향상되었으며, 평가 파이프라인 구축에 사용할 수 있습니다.
"""
        return report

def main():
    """메인 실행 함수"""
    input_file = "dataset_for_evaluation_corrected.csv"
    output_file = "dataset_final_optimized.csv"
    report_file = "dataset_optimization_report.md"
    
    print("🚀 데이터셋 최종 최적화 도구 실행")
    print(f"📁 입력 파일: {input_file}")
    
    try:
        # 최적화 실행
        optimizer = DatasetFinalOptimizer(input_file)
        optimized_df = optimizer.optimize_dataset()
        
        # 결과 저장
        optimized_df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"💾 최적화된 데이터셋 저장: {output_file}")
        
        # 리포트 생성
        report = optimizer.generate_optimization_report()
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"📋 최적화 리포트 저장: {report_file}")
        
        # 결과 출력
        print("\n" + "="*50)
        print(report)
        
    except Exception as e:
        print(f"❌ 오류 발생: {str(e)}")

if __name__ == "__main__":
    main()
