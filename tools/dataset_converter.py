#!/usr/bin/env python3
"""
Enhanced Dataset 변환 유틸리티
JSON을 다양한 형태로 변환 (간소화된 JSON, CSV, TSV 등)
"""

import json
import csv
from pathlib import Path
import argparse
from typing import Dict, List, Any, Optional


class DatasetConverter:
    """데이터셋 변환 클래스"""
    
    def __init__(self, input_file: str):
        self.input_file = Path(input_file)
        self.data = []
        self.load_data()
    
    def load_data(self):
        """JSON 데이터 로드"""
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            print(f"✅ 데이터 로드 완료: {len(self.data)}개 항목")
        except Exception as e:
            print(f"❌ 데이터 로드 실패: {e}")
            self.data = []
    
    def extract_fields(self, fields: List[str]) -> List[Dict[str, Any]]:
        """지정된 필드만 추출"""
        extracted_data = []
        
        for item in self.data:
            extracted_item = {}
            for field in fields:
                if field in item:
                    value = item[field]
                    # source_files 리스트는 문자열로 변환
                    if field == 'source_files' and isinstance(value, list):
                        extracted_item[field] = ', '.join(value)
                    else:
                        extracted_item[field] = value
                else:
                    extracted_item[field] = None
            extracted_data.append(extracted_item)
        
        return extracted_data
    
    def to_simplified_json(self, output_file: str, fields: List[str] = None) -> bool:
        """간소화된 JSON으로 변환"""
        if fields is None:
            fields = ['id', 'question', 'ground_truth', 'explanation', 'source_files']
        
        try:
            simplified_data = self.extract_fields(fields)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(simplified_data, f, ensure_ascii=False, indent=2)
            
            print(f"✅ 간소화된 JSON 저장: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ JSON 저장 실패: {e}")
            return False
    
    def to_csv(self, output_file: str, fields: List[str] = None) -> bool:
        """CSV로 변환"""
        if fields is None:
            fields = ['id', 'question', 'ground_truth', 'explanation', 'source_files']
        
        try:
            simplified_data = self.extract_fields(fields)
            
            with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
                if simplified_data:
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(simplified_data)
            
            print(f"✅ CSV 저장: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ CSV 저장 실패: {e}")
            return False
    
    def to_tsv(self, output_file: str, fields: List[str] = None) -> bool:
        """TSV로 변환"""
        if fields is None:
            fields = ['id', 'question', 'ground_truth', 'explanation', 'source_files']
        
        try:
            simplified_data = self.extract_fields(fields)
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if simplified_data:
                    writer = csv.DictWriter(f, fieldnames=fields, delimiter='\t')
                    writer.writeheader()
                    writer.writerows(simplified_data)
            
            print(f"✅ TSV 저장: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ TSV 저장 실패: {e}")
            return False
    
    def to_benchmark_format(self, output_file: str) -> bool:
        """벤치마크 평가용 형태로 변환"""
        try:
            benchmark_data = []
            
            for item in self.data:
                benchmark_item = {
                    'question': item.get('question', ''),
                    'ground_truth': item.get('ground_truth', ''),
                    'explanation': item.get('explanation', ''),
                    'id': item.get('id', ''),
                    'category': item.get('category', 'general'),
                    'complexity': item.get('complexity', 'medium'),
                    'source_files': ', '.join(item.get('source_files', [])) if isinstance(item.get('source_files'), list) else ''
                }
                benchmark_data.append(benchmark_item)
            
            with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
                if benchmark_data:
                    fieldnames = ['question', 'ground_truth', 'explanation', 'id', 'category', 'complexity', 'source_files']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(benchmark_data)
            
            print(f"✅ 벤치마크 형태 CSV 저장: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ 벤치마크 형태 저장 실패: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """데이터 통계 정보"""
        if not self.data:
            return {}
        
        stats = {
            'total_items': len(self.data),
            'fields': {},
            'categories': {},
            'complexity': {},
            'source_files': {}
        }
        
        # 필드별 통계
        all_fields = set()
        for item in self.data:
            all_fields.update(item.keys())
        
        for field in all_fields:
            count = sum(1 for item in self.data if field in item and item[field] is not None)
            stats['fields'][field] = {
                'count': count,
                'percentage': (count / len(self.data)) * 100
            }
        
        # 카테고리별 통계
        categories = [item.get('category', 'unknown') for item in self.data]
        for category in set(categories):
            stats['categories'][category] = categories.count(category)
        
        # 복잡도별 통계
        complexities = [item.get('complexity', 'unknown') for item in self.data]
        for complexity in set(complexities):
            stats['complexity'][complexity] = complexities.count(complexity)
        
        # source_files 통계
        all_source_files = []
        for item in self.data:
            source_files = item.get('source_files', [])
            if isinstance(source_files, list):
                all_source_files.extend(source_files)
        
        for source_file in set(all_source_files):
            stats['source_files'][source_file] = all_source_files.count(source_file)
        
        return stats
    
    def print_statistics(self):
        """통계 정보 출력"""
        stats = self.get_statistics()
        
        if not stats:
            print("❌ 통계 정보를 계산할 수 없습니다.")
            return
        
        print(f"\n📊 데이터셋 통계:")
        print(f"   총 항목 수: {stats['total_items']:,}")
        
        # 필드 통계
        print(f"\n📋 필드별 존재 비율:")
        for field, info in stats['fields'].items():
            print(f"   {field}: {info['count']}/{stats['total_items']} ({info['percentage']:.1f}%)")
        
        # 카테고리 통계
        if stats['categories']:
            print(f"\n🏷️ 카테고리별 분포:")
            for category, count in sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True):
                print(f"   {category}: {count}개")
        
        # 복잡도 통계
        if stats['complexity']:
            print(f"\n⚡ 복잡도별 분포:")
            for complexity, count in sorted(stats['complexity'].items(), key=lambda x: x[1], reverse=True):
                print(f"   {complexity}: {count}개")
        
        # 자주 사용되는 소스 파일
        if stats['source_files']:
            print(f"\n📄 자주 참조되는 소스 파일 (상위 10개):")
            top_files = sorted(stats['source_files'].items(), key=lambda x: x[1], reverse=True)[:10]
            for source_file, count in top_files:
                print(f"   {source_file}: {count}번")


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(description='Enhanced Dataset 변환 유틸리티')
    
    parser.add_argument(
        '--input',
        type=str,
        default='../output/network_qqa/enhanced_dataset.json',
        help='입력 JSON 파일 경로'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='.',
        help='출력 디렉토리'
    )
    
    parser.add_argument(
        '--formats',
        type=str,
        nargs='+',
        choices=['json', 'csv', 'tsv', 'benchmark'],
        default=['json', 'csv'],
        help='변환할 형태 선택'
    )
    
    parser.add_argument(
        '--fields',
        type=str,
        nargs='+',
        default=['id', 'question', 'ground_truth', 'explanation', 'source_files'],
        help='추출할 필드 선택'
    )
    
    parser.add_argument(
        '--prefix',
        type=str,
        default='simplified_dataset',
        help='출력 파일명 접두사'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='통계 정보 출력'
    )
    
    args = parser.parse_args()
    
    print("🔄 Enhanced Dataset 변환 유틸리티")
    print("=" * 50)
    
    # 입력 파일 경로 변환
    current_dir = Path(__file__).parent
    if not Path(args.input).is_absolute():
        input_path = current_dir / args.input
    else:
        input_path = Path(args.input)
    
    print(f"📁 입력 파일: {input_path}")
    print(f"📁 출력 디렉토리: {args.output_dir}")
    print(f"🔧 변환 형태: {args.formats}")
    print(f"📋 추출 필드: {args.fields}")
    
    # 변환기 초기화
    converter = DatasetConverter(str(input_path))
    
    if not converter.data:
        print("❌ 데이터를 로드할 수 없습니다.")
        return
    
    # 통계 정보 출력
    if args.stats:
        converter.print_statistics()
    
    # 출력 디렉토리 생성
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 각 형태로 변환
    results = []
    
    for format_type in args.formats:
        output_file = output_dir / f"{args.prefix}.{format_type}"
        
        if format_type == 'json':
            success = converter.to_simplified_json(str(output_file), args.fields)
        elif format_type == 'csv':
            success = converter.to_csv(str(output_file), args.fields)
        elif format_type == 'tsv':
            success = converter.to_tsv(str(output_file), args.fields)
        elif format_type == 'benchmark':
            success = converter.to_benchmark_format(str(output_file.with_suffix('.csv')))
        else:
            success = False
            
        results.append((format_type, success))
    
    # 결과 요약
    print(f"\n🎉 변환 완료!")
    for format_type, success in results:
        status = "✅" if success else "❌"
        print(f"   {status} {format_type.upper()} 변환")
    
    print(f"\n📊 요약:")
    print(f"   총 항목 수: {len(converter.data):,}")
    print(f"   추출된 필드: {len(args.fields)}개")
    print(f"   성공한 변환: {sum(1 for _, success in results if success)}/{len(results)}")


if __name__ == "__main__":
    main()
