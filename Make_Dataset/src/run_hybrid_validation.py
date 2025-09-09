"""
하이브리드 검증 실행 스크립트
기존 데이터셋을 에이전트와 로직으로 동시에 검증
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt

from agents.hybrid_validation_system import HybridValidationSystem, ValidationMode
from agents.hybrid_feedback_loop import HybridFeedbackLoop
from parsers.universal_parser import UniversalParser

def visualize_validation_results(validation_history: List[Dict[str, Any]]):
    """검증 결과를 시각화"""
    
    if not validation_history:
        return
    
    iterations = range(1, len(validation_history) + 1)
    agent_acc = [h['agent_performance']['accuracy'] for h in validation_history]
    gt_acc = [h['ground_truth_quality']['accuracy'] for h in validation_history]
    
    plt.figure(figsize=(10, 6))
    plt.plot(iterations, agent_acc, 'b-o', label='Agent Accuracy')
    plt.plot(iterations, gt_acc, 'g-o', label='Ground Truth Accuracy')
    plt.xlabel('Iteration')
    plt.ylabel('Accuracy')
    plt.title('Hybrid Validation Progress')
    plt.legend()
    plt.grid(True)
    plt.savefig('validation_progress.png')
    print("\n📊 그래프 저장: validation_progress.png")

def main():
    parser = argparse.ArgumentParser(description='하이브리드 검증 시스템')
    parser.add_argument('--dataset', required=True, help='검증할 데이터셋 경로')
    parser.add_argument('--xml-dir', required=True, help='XML 파일 디렉토리')
    parser.add_argument('--output', default='output/hybrid_validation', help='출력 디렉토리')
    parser.add_argument('--mode', choices=['agent', 'logic', 'hybrid'], 
                       default='hybrid', help='검증 모드')
    parser.add_argument('--sample-size', type=int, help='샘플 크기')
    parser.add_argument('--max-iter', type=int, default=3, help='최대 반복 횟수')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🚀 하이브리드 검증 시스템 시작")
    print("="*70)
    
    # 1. 데이터 로드
    print("\n1. 데이터 로딩...")
    with open(args.dataset, 'r', encoding='utf-8') as f:
        dataset = json.load(f)
    print(f"   ✓ 데이터셋: {len(dataset)}개 항목")
    
    # 2. Network Facts 파싱
    print("\n2. 네트워크 설정 파싱...")
    parser = UniversalParser()
    network_facts = parser.parse_dir(args.xml_dir)
    print(f"   ✓ 장비: {len(network_facts.get('devices', []))}개")
    
    # 3. 하이브리드 검증 시스템 초기화
    print(f"\n3. 검증 시스템 초기화 (모드: {args.mode})...")
    mode_map = {
        'agent': ValidationMode.AGENT_ONLY,
        'logic': ValidationMode.LOGIC_ONLY,
        'hybrid': ValidationMode.HYBRID
    }
    
    validator = HybridValidationSystem(
        network_facts=network_facts,
        mode=mode_map[args.mode]
    )
    feedback_loop = HybridFeedbackLoop(network_facts)
    
    # 4. 반복 검증 루프
    print("\n4. 검증 루프 시작")
    print("-"*50)
    
    iteration = 0
    validation_history = []
    
    while iteration < args.max_iter:
        print(f"\n### 반복 {iteration + 1}/{args.max_iter} ###")
        
        # 검증 수행
        validation_results, stats = validator.validate_dataset(
            dataset, 
            sample_size=args.sample_size
        )
        validation_history.append(stats)
        
        # 목표 달성 확인
        gt_accuracy = stats['ground_truth_quality']['accuracy']
        if gt_accuracy >= 0.95:
            print("\n🎉 목표 달성! Ground Truth 정확도 95% 이상")
            break
        
        # 피드백 루프
        print("\n개선 작업 중...")
        improved_dataset, improvement_report = feedback_loop.improve_dataset(
            validation_results,
            dataset
        )
        
        if improvement_report['total_improvements'] == 0:
            print("더 이상 개선할 항목이 없습니다.")
            break
        
        dataset = improved_dataset
        print(f"✓ {improvement_report['total_improvements']}개 항목 개선됨")
        
        iteration += 1
    
    # 5. 결과 저장
    print("\n5. 결과 저장...")
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # 개선된 데이터셋 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    dataset_file = output_path / f"validated_dataset_{timestamp}.json"
    with open(dataset_file, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, ensure_ascii=False, indent=2)
    print(f"   ✓ 데이터셋: {dataset_file}")
    
    # 검증 리포트 저장
    report = {
        "mode": args.mode,
        "iterations": iteration + 1,
        "validation_history": validation_history,
        "timestamp": timestamp
    }
    
    report_file = output_path / f"validation_report_{timestamp}.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"   ✓ 리포트: {report_file}")
    
    # 시각화
    visualize_validation_results(validation_history)
    
    # 최종 요약
    print("\n" + "="*70)
    print("✅ 하이브리드 검증 완료!")
    print("="*70)
    
    if validation_history:
        final_stats = validation_history[-1]
        print(f"\n최종 결과:")
        print(f"  • 에이전트 정확도: {final_stats['agent_performance']['accuracy']:.1%}")
        print(f"  • Ground Truth 정확도: {final_stats['ground_truth_quality']['accuracy']:.1%}")
        print(f"  • 총 반복: {iteration + 1}회")
    
    print(f"\n결과 저장 위치: {output_path}")
    print("="*70)

if __name__ == "__main__":
    main()