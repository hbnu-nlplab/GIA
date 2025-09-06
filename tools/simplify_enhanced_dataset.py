#!/usr/bin/env python3
"""
Enhanced Dataset JSON 간소화 도구
enhanced_dataset.json에서 필요한 필드만 추출하여 간소화된 JSON 생성

필요한 필드: id, question, ground_truth, explanation, source_files
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
import argparse
from datetime import datetime


def extract_simplified_fields(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    원본 데이터에서 필요한 필드만 추출
    
    Args:
        data: 원본 데이터 리스트
        
    Returns:
        간소화된 데이터 리스트
    """
    simplified_data = []
    
    for item in data:
        simplified_item = {}
        
        # 필수 필드 추출
        required_fields = ['id', 'question', 'ground_truth', 'explanation', 'source_files']
        
        for field in required_fields:
            if field in item:
                simplified_item[field] = item[field]
            else:
                # 누락된 필드에 대한 기본값 설정
                if field == 'source_files':
                    simplified_item[field] = []
                else:
                    simplified_item[field] = None
                    
        simplified_data.append(simplified_item)
    
    return simplified_data


def load_json_file(file_path: str) -> List[Dict[str, Any]]:
    """JSON 파일 로드"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"✅ JSON 파일 로드 성공: {len(data)}개 항목")
        return data
        
    except FileNotFoundError:
        print(f"❌ 파일을 찾을 수 없습니다: {file_path}")
        return []
    except json.JSONDecodeError as e:
        print(f"❌ JSON 파싱 오류: {e}")
        return []
    except Exception as e:
        print(f"❌ 파일 로드 실패: {e}")
        return []


def save_simplified_json(data: List[Dict[str, Any]], output_path: str):
    """간소화된 JSON 저장"""
    try:
        # 출력 디렉토리 생성
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"✅ 간소화된 JSON 저장 완료: {output_path}")
        
        # 파일 크기 정보
        file_size = Path(output_path).stat().st_size
        print(f"   파일 크기: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
        
    except Exception as e:
        print(f"❌ 파일 저장 실패: {e}")


def analyze_data_structure(data: List[Dict[str, Any]]):
    """데이터 구조 분석 및 통계 출력"""
    if not data:
        print("❌ 분석할 데이터가 없습니다.")
        return
    
    print(f"\n📊 데이터 구조 분석:")
    print(f"   총 항목 수: {len(data)}")
    
    # 필드별 존재 비율 확인
    required_fields = ['id', 'question', 'ground_truth', 'explanation', 'source_files']
    field_stats = {}
    
    for field in required_fields:
        count = sum(1 for item in data if field in item and item[field] is not None)
        percentage = (count / len(data)) * 100
        field_stats[field] = {'count': count, 'percentage': percentage}
        print(f"   {field}: {count}/{len(data)} ({percentage:.1f}%)")
    
    # source_files 분석
    source_files_data = [item.get('source_files', []) for item in data if 'source_files' in item]
    if source_files_data:
        total_files = sum(len(files) if isinstance(files, list) else 0 for files in source_files_data)
        avg_files = total_files / len(source_files_data) if source_files_data else 0
        print(f"   평균 source_files 수: {avg_files:.1f}")
    
    # 질문 길이 통계
    questions = [item.get('question', '') for item in data if 'question' in item]
    if questions:
        avg_question_length = sum(len(q) for q in questions) / len(questions)
        print(f"   평균 질문 길이: {avg_question_length:.0f} 글자")
    
    # ground_truth 길이 통계
    answers = [item.get('ground_truth', '') for item in data if 'ground_truth' in item]
    if answers:
        avg_answer_length = sum(len(str(a)) for a in answers) / len(answers)
        print(f"   평균 답변 길이: {avg_answer_length:.0f} 글자")


def preview_simplified_data(data: List[Dict[str, Any]], num_samples: int = 3):
    """간소화된 데이터 미리보기"""
    if not data:
        return
    
    print(f"\n👀 간소화된 데이터 미리보기 (첫 {min(num_samples, len(data))}개):")
    
    for i, item in enumerate(data[:num_samples]):
        print(f"\n--- 샘플 {i+1} ---")
        print(f"ID: {item.get('id', 'N/A')}")
        print(f"질문: {item.get('question', 'N/A')[:100]}...")
        print(f"정답: {str(item.get('ground_truth', 'N/A'))[:100]}...")
        print(f"설명: {item.get('explanation', 'N/A')[:100]}...")
        source_files = item.get('source_files', [])
        print(f"소스 파일: {source_files if isinstance(source_files, list) else 'N/A'}")


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(description='Enhanced Dataset JSON 간소화 도구')
    
    parser.add_argument(
        '--input',
        type=str,
        default='../output/network_qqa/enhanced_dataset.json',
        help='입력 JSON 파일 경로'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='simplified_dataset.json',
        help='출력 JSON 파일 경로'
    )
    
    parser.add_argument(
        '--preview',
        type=int,
        default=3,
        help='미리보기할 샘플 수'
    )
    
    parser.add_argument(
        '--no-analysis',
        action='store_true',
        help='데이터 분석 건너뛰기'
    )
    
    args = parser.parse_args()
    
    print("🔧 Enhanced Dataset JSON 간소화 도구")
    print("=" * 50)
    
    # 입력 파일 절대 경로 변환
    current_dir = Path(__file__).parent
    if not Path(args.input).is_absolute():
        input_path = current_dir / args.input
    else:
        input_path = Path(args.input)
    
    # 출력 파일 절대 경로 변환
    if not Path(args.output).is_absolute():
        output_path = current_dir / args.output
    else:
        output_path = Path(args.output)
    
    print(f"📁 입력 파일: {input_path}")
    print(f"📁 출력 파일: {output_path}")
    
    # 1. JSON 파일 로드
    data = load_json_file(str(input_path))
    if not data:
        return
    
    # 2. 데이터 분석 (옵션)
    if not args.no_analysis:
        analyze_data_structure(data)
    
    # 3. 필요한 필드만 추출
    print(f"\n🔄 필드 추출 중...")
    simplified_data = extract_simplified_fields(data)
    
    # 4. 미리보기
    preview_simplified_data(simplified_data, args.preview)
    
    # 5. 간소화된 JSON 저장
    print(f"\n💾 저장 중...")
    save_simplified_json(simplified_data, str(output_path))
    
    # 6. 완료 요약
    print(f"\n🎉 완료!")
    print(f"   원본: {len(data)}개 항목")
    print(f"   간소화: {len(simplified_data)}개 항목")
    print(f"   추출 필드: id, question, ground_truth, explanation, source_files")
    
    # 파일 크기 비교
    try:
        original_size = input_path.stat().st_size
        simplified_size = output_path.stat().st_size
        reduction = ((original_size - simplified_size) / original_size) * 100
        print(f"   크기 감소: {reduction:.1f}% ({original_size:,} → {simplified_size:,} bytes)")
    except:
        pass


if __name__ == "__main__":
    main()
