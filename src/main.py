"""
네트워크 Q&A 데이터셋 생성 및 검증 통합 실행 스크립트
한 번의 실행으로 생성 → 검증 → 개선까지 완료!
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from integrated_pipeline import NetworkConfigDatasetGenerator, PipelineConfig
from agents.hybrid_validation_system import ValidationMode


# policies.json에서 모든 카테고리 자동 추출
def get_all_categories(policies_path: str) -> List[str]:
        """policies.json에서 모든 카테고리 추출"""
        import json
        with open(policies_path, 'r', encoding='utf-8') as f:
            policies_data = json.load(f)
        
        categories = set()
        for policy in policies_data.get("policies", []):
            category = policy.get("category")
            if category:
                categories.add(category)
        
        return sorted(list(categories))


policies_path = "policies.json"
all_categories = get_all_categories(policies_path)


def main():
    parser = argparse.ArgumentParser(
        description='네트워크 Q&A 데이터셋 생성 및 하이브리드 검증'
    )
    
    # 필수 인자
    parser.add_argument(
        '--xml-dir', 

        default='data/raw/XML_Data',
        help='네트워크 설정 XML 파일 디렉토리'
    )
    parser.add_argument(
        '--policies', 

        default='policies.json',
        help='정책 파일 경로 (YAML)'
    )
    
    # 선택적 인자
    parser.add_argument(
        '--categories',
        nargs='+',
        default=all_categories,
        help='생성할 카테고리 목록'
    )
    parser.add_argument(
        '--output-dir',
        default='output/network_qa',
        help='출력 디렉토리'
    )
    
    # 생성 설정
    parser.add_argument(
        '--basic-per-category',
        type=int,
        default=30,
        help='카테고리당 기본 질문 수'
    )
    parser.add_argument(
        '--enhanced-per-category',
        type=int,
        default=30,
        help='카테고리당 향상된 질문 수'
    )
    
    # 검증 설정
    parser.add_argument(
        '--validation-mode',
        choices=['agent', 'logic', 'hybrid', 'skip'],
        default='hybrid',
        help='검증 모드 (skip: 검증 안 함)'
    )
    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='검증 완전 비활성화 (--validation-mode skip과 동일)'
    )
    parser.add_argument(
        '--skip-feedback', 
        action='store_true',
        help='피드백 루프 비활성화 (검증은 실행하되 개선은 안 함)'
    )
    parser.add_argument(
        '--max-validation-iter',
        type=int,
        default=3,
        help='최대 검증 반복 횟수'
    )
    
    # 실행 옵션
    parser.add_argument(
        '--sample-validation',
        type=int,
        help='검증 시 샘플링 크기 (전체 검증하려면 생략)'
    )
    parser.add_argument(
        '--save-intermediate',
        action='store_true',
        help='중간 결과 저장'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='상세 출력'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("🚀 네트워크 Q&A 데이터셋 생성 및 하이브리드 검증")
    print("="*70)
    print(f"\n설정:")
    print(f"  • XML 디렉토리: {args.xml_dir}")
    print(f"  • 카테고리: {', '.join(args.categories)}")
    
    # 검증/피드백 상태 표시
    if args.skip_validation or args.validation_mode == 'skip':
        print(f"  • 검증: ❌ 비활성화")
        print(f"  • 피드백: ❌ 비활성화 (검증 비활성화로 인해)")
    else:
        print(f"  • 검증 모드: {args.validation_mode}")
        print(f"  • 피드백: {'❌ 비활성화' if args.skip_feedback else '✅ 활성화'}")
    
    print(f"  • 출력 디렉토리: {args.output_dir}")
    print("-"*70)
    
    # 파이프라인 설정
    config = PipelineConfig(
        xml_data_dir=args.xml_dir,
        policies_path=args.policies,
        target_categories=args.categories,
        basic_questions_per_category=args.basic_per_category,
        enhanced_questions_per_category=args.enhanced_per_category,
        output_dir=args.output_dir,
        save_intermediate=args.save_intermediate
    )
    
    # 검증 모드 설정
    if args.skip_validation or args.validation_mode == 'skip':
        config.skip_validation = True
        config.skip_feedback = True  # 검증을 안 하면 피드백도 자동으로 비활성화
    else:
        mode_map = {
            'agent': ValidationMode.AGENT_ONLY,
            'logic': ValidationMode.LOGIC_ONLY,
            'hybrid': ValidationMode.HYBRID
        }
        config.validation_mode = mode_map[args.validation_mode]
        config.max_validation_iterations = args.max_validation_iter
        config.validation_sample_size = args.sample_validation
        config.skip_feedback = args.skip_feedback
    
    # 생성기 초기화 및 실행
    generator = NetworkConfigDatasetGenerator(config)
    
    try:
        # 통합 실행: 생성 → 검증 → 개선
        final_dataset = generator.generate_complete_dataset()
        
        # 최종 결과 저장
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 데이터셋 저장
        dataset_file = output_path / f"dataset_final_{timestamp}.json"
        with open(dataset_file, 'w', encoding='utf-8') as f:
            json.dump(
                final_dataset['dataset'], 
                f, 
                ensure_ascii=False, 
                indent=2
            )
        
        # 리포트 저장
        report_file = output_path / f"report_{timestamp}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(
                final_dataset['report'],
                f,
                ensure_ascii=False,
                indent=2
            )
        
        # 최종 요약 출력
        print("\n" + "="*70)
        print("✅ 완료!")
        print("="*70)
        print(f"\n📊 최종 통계:")
        print(f"  • 총 질문 수: {len(final_dataset['dataset'])}개")
        
        if 'validation_report' in final_dataset:
            val_report = final_dataset['validation_report']
            if 'final_stats' in val_report:
                stats = val_report['final_stats']
                print(f"  • 에이전트 정확도: {stats.get('agent_performance', {}).get('accuracy', 0):.1%}")
                print(f"  • Ground Truth 정확도: {stats.get('ground_truth_quality', {}).get('accuracy', 0):.1%}")
        
        print(f"\n📁 결과 파일:")
        print(f"  • 데이터셋: {dataset_file}")
        print(f"  • 리포트: {report_file}")
        print("="*70)
        
        return 0
        
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())