"""
네트워크 구성 파싱 데이터셋 논문용 간단 분석 도구
Network Configuration Parsing Dataset Analysis for Academic Paper (Simple Version)
"""

import json
import matplotlib.pyplot as plt
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any
import statistics

class SimpleNetworkDatasetAnalyzer:
    def __init__(self, dataset_path: str):
        """데이터셋 분석기 초기화"""
        self.dataset_path = Path(dataset_path)
        self.data = self._load_dataset()
        self.output_dir = self.dataset_path.parent / "analysis_results"
        self.output_dir.mkdir(exist_ok=True)
        
    def _load_dataset(self) -> Dict[str, Any]:
        """데이터셋 로드"""
        with open(self.dataset_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def generate_analysis(self):
        """분석 수행 및 논문용 시각화 생성"""
        print("🔍 데이터셋 분석 시작...")
        
        # 기본 통계 수집
        stats = self._collect_basic_stats()
        
        # 그래프 생성
        self._create_figures(stats)
        
        # 표 데이터 생성
        self._create_tables(stats)
        
        # 리포트 생성
        self._create_report(stats)
        
        print(f"✅ 분석 완료! 결과는 {self.output_dir}에 저장되었습니다.")
        return stats
    
    def _collect_basic_stats(self):
        """기본 통계 수집"""
        all_samples = (self.data.get('train', []) + 
                      self.data.get('validation', []) + 
                      self.data.get('test', []))
        
        # 기본 통계
        train_count = len(self.data.get('train', []))
        val_count = len(self.data.get('validation', []))
        test_count = len(self.data.get('test', []))
        total_count = len(all_samples)
        
        # 카테고리 분석
        category_counts = Counter(sample['category'] for sample in all_samples)
        
        # 복잡도 분석
        complexity_counts = Counter(sample['complexity'] for sample in all_samples)
        
        # 답변 타입 분석
        answer_type_counts = Counter(sample['answer_type'] for sample in all_samples)
        
        # 토폴로지 특화 분석
        topology_categories = {
            'Interface_Inventory', 'Routing_Inventory', 'VRF_Consistency',
            'BGP_Consistency', 'OSPF_Consistency', 'L2VPN_Consistency',
            'Basic_Info', 'System_Inventory'
        }
        
        topology_count = sum(category_counts[cat] for cat in topology_categories if cat in category_counts)
        general_count = total_count - topology_count
        
        # 질문/답변 길이 분석
        question_lengths = []
        answer_lengths = []
        
        for sample in all_samples:
            question_lengths.append(len(sample['question'].split()))
            
            gt = sample['ground_truth']
            if isinstance(gt, (list, dict)):
                gt_str = str(gt)
            else:
                gt_str = str(gt)
            answer_lengths.append(len(gt_str.split()))
        
        return {
            'total_samples': total_count,
            'train_samples': train_count,
            'val_samples': val_count,
            'test_samples': test_count,
            'category_counts': dict(category_counts),
            'complexity_counts': dict(complexity_counts),
            'answer_type_counts': dict(answer_type_counts),
            'topology_count': topology_count,
            'general_count': general_count,
            'topology_ratio': topology_count / total_count if total_count > 0 else 0,
            'avg_question_length': statistics.mean(question_lengths),
            'avg_answer_length': statistics.mean(answer_lengths),
            'question_lengths': question_lengths,
            'answer_lengths': answer_lengths,
            'device_count': self.data['metadata']['pipeline_results']['parsing']['device_count']
        }
    
    def _create_figures(self, stats):
        """논문용 Figure 생성"""
        # Figure 1: 데이터셋 구성 개요
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. Train/Val/Test 분할
        split_data = [stats['train_samples'], stats['val_samples'], stats['test_samples']]
        labels = ['Train', 'Validation', 'Test']
        colors = ['#3498db', '#e74c3c', '#2ecc71']
        
        ax1.pie(split_data, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
        ax1.set_title('Dataset Split Distribution', fontsize=14, fontweight='bold')
        
        # 2. 토폴로지 특화 vs 일반
        topo_data = [stats['topology_count'], stats['general_count']]
        topo_labels = ['Topology-Specific', 'General Network']
        topo_colors = ['#e74c3c', '#3498db']
        
        ax2.pie(topo_data, labels=topo_labels, autopct='%1.1f%%', colors=topo_colors, startangle=90)
        ax2.set_title('Question Focus Distribution', fontsize=14, fontweight='bold')
        
        # 3. 답변 타입 분포
        answer_types = list(stats['answer_type_counts'].keys())
        answer_counts = list(stats['answer_type_counts'].values())
        
        ax3.bar(answer_types, answer_counts, color=['#1abc9c', '#e67e22'])
        ax3.set_title('Answer Type Distribution', fontsize=14, fontweight='bold')
        ax3.set_ylabel('Count')
        
        # 4. 복잡도 분포
        complexity_order = ['basic', 'analytical', 'synthetic', 'diagnostic', 'scenario']
        complexity_data = [stats['complexity_counts'].get(comp, 0) for comp in complexity_order]
        
        ax4.bar(complexity_order, complexity_data, color='#34495e')
        ax4.set_title('Question Complexity Distribution', fontsize=14, fontweight='bold')
        ax4.set_ylabel('Count')
        ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figure1_dataset_overview.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Figure 2: 카테고리별 분포
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 8))
        
        # 카테고리별 분포
        categories = list(stats['category_counts'].keys())
        counts = list(stats['category_counts'].values())
        
        # 상위 10개 카테고리만 표시
        if len(categories) > 10:
            sorted_items = sorted(zip(categories, counts), key=lambda x: x[1], reverse=True)
            categories = [item[0] for item in sorted_items[:10]]
            counts = [item[1] for item in sorted_items[:10]]
        
        ax1.barh(categories, counts, color='#2c3e50')
        ax1.set_title('Top Categories by Question Count', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Number of Questions')
        
        # 질문-답변 길이 분포
        ax2.hist(stats['question_lengths'], bins=20, alpha=0.7, label='Questions', color='#3498db')
        ax2.hist(stats['answer_lengths'], bins=20, alpha=0.7, label='Answers', color='#e74c3c')
        ax2.set_title('Question vs Answer Length Distribution', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Length (words)')
        ax2.set_ylabel('Frequency')
        ax2.legend()
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'figure2_detailed_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("📊 그래프 생성 완료")
    
    def _create_tables(self, stats):
        """논문용 표 생성"""
        # Table 1: 기본 통계
        table1_content = f"""
Table 1: NetworkConfigQA Dataset Statistics

Characteristic                | Value
------------------------------|--------
Total Samples                 | {stats['total_samples']:,}
Training Samples               | {stats['train_samples']:,}
Validation Samples             | {stats['val_samples']:,}
Test Samples                   | {stats['test_samples']:,}
Categories                     | {len(stats['category_counts'])}
Complexity Levels              | {len(stats['complexity_counts'])}
Network Devices                | {stats['device_count']}
Topology-Specific Ratio        | {stats['topology_ratio']:.1%}
Avg Question Length (words)    | {stats['avg_question_length']:.1f}
Avg Answer Length (words)      | {stats['avg_answer_length']:.1f}
"""
        
        with open(self.output_dir / 'table1_basic_statistics.txt', 'w', encoding='utf-8') as f:
            f.write(table1_content)
        
        # Table 2: 카테고리별 분포
        table2_content = "Table 2: Category Distribution\\n\\n"
        table2_content += "Category | Count | Percentage\\n"
        table2_content += "---------|-------|----------\\n"
        
        sorted_categories = sorted(stats['category_counts'].items(), key=lambda x: x[1], reverse=True)
        for cat, count in sorted_categories:
            percentage = (count / stats['total_samples']) * 100
            table2_content += f"{cat} | {count} | {percentage:.1f}%\\n"
        
        with open(self.output_dir / 'table2_category_distribution.txt', 'w', encoding='utf-8') as f:
            f.write(table2_content)
        
        # Table 3: 복잡도별 분포
        table3_content = "Table 3: Complexity Distribution\\n\\n"
        table3_content += "Complexity | Count | Percentage\\n"
        table3_content += "-----------|-------|----------\\n"
        
        complexity_order = ['basic', 'analytical', 'synthetic', 'diagnostic', 'scenario']
        for comp in complexity_order:
            count = stats['complexity_counts'].get(comp, 0)
            percentage = (count / stats['total_samples']) * 100 if stats['total_samples'] > 0 else 0
            table3_content += f"{comp.title()} | {count} | {percentage:.1f}%\\n"
        
        with open(self.output_dir / 'table3_complexity_distribution.txt', 'w', encoding='utf-8') as f:
            f.write(table3_content)
        
        print("📋 표 생성 완료")
    
    def _create_report(self, stats):
        """종합 리포트 생성"""
        report = f"""
# NetworkConfigQA Dataset Analysis Report

## Executive Summary
NetworkConfigQA는 네트워크 구성 파싱에 특화된 데이터셋으로, 실제 네트워크 토폴로지 데이터를 기반으로 생성되었습니다.

## Key Statistics
- **총 샘플 수**: {stats['total_samples']:,}개
- **네트워크 장비 수**: {stats['device_count']}개
- **토폴로지 특화 비율**: {stats['topology_ratio']:.1%}
- **평균 질문 길이**: {stats['avg_question_length']:.1f} 단어
- **평균 답변 길이**: {stats['avg_answer_length']:.1f} 단어

## Dataset Composition

### Data Split
- Training: {stats['train_samples']:,} ({stats['train_samples']/stats['total_samples']*100:.1f}%)
- Validation: {stats['val_samples']:,} ({stats['val_samples']/stats['total_samples']*100:.1f}%)
- Test: {stats['test_samples']:,} ({stats['test_samples']/stats['total_samples']*100:.1f}%)

### Question Focus
- Topology-Specific: {stats['topology_count']:,} ({stats['topology_ratio']:.1%})
- General Network: {stats['general_count']:,} ({(1-stats['topology_ratio']):.1%})

### Answer Types
"""
        
        for answer_type, count in stats['answer_type_counts'].items():
            percentage = (count / stats['total_samples']) * 100
            report += f"- {answer_type.title()}: {count:,} ({percentage:.1f}%)\\n"
        
        report += f"""

## Dataset Strengths for Network Configuration Parsing

1. **Real Topology Foundation**: 실제 네트워크 장비 설정 파일 기반
2. **High Topology Focus**: 전체 질문의 {stats['topology_ratio']:.1%}가 토폴로지 특화
3. **Multi-Level Complexity**: {len(stats['complexity_counts'])}단계 복잡도 지원
4. **Balanced Generation**: Rule-based + LLM 하이브리드 생성

## Research Applications

### Primary Use Cases
1. **LLM Fine-tuning**: 네트워크 구성 이해 능력 향상
2. **Topology Parsing**: XML/설정 파일 파싱 성능 평가
3. **Network Analysis**: 자동화된 네트워크 분석 도구 개발
4. **Educational**: 네트워크 엔지니어 교육용 평가

### Evaluation Metrics
- **Exact Match**: 정확한 답변 일치도
- **F1 Score**: 부분 정답 인정 점수
- **Topology Accuracy**: 토폴로지 특화 정확도
- **Complexity-wise Performance**: 복잡도별 성능 분석

## Comparison with Existing Benchmarks

NetworkConfigQA의 차별점:
- **Domain Specificity**: 네트워크 구성 파싱에 특화
- **Real Data**: 실제 생산 환경 네트워크 설정 기반
- **Topology Focus**: 일반적인 네트워크 지식이 아닌 특정 토폴로지 이해 중심
- **Multi-modal**: 설정 파일 + 자연어 질의응답

## Files Generated
- `figure1_dataset_overview.png`: 데이터셋 구성 개요
- `figure2_detailed_analysis.png`: 상세 분석 그래프
- `table1_basic_statistics.txt`: 기본 통계표
- `table2_category_distribution.txt`: 카테고리별 분포
- `table3_complexity_distribution.txt`: 복잡도별 분포

## Recommended Paper Sections

### Abstract
"We present NetworkConfigQA, a specialized dataset for evaluating large language models on network configuration parsing tasks. The dataset contains {stats['total_samples']:,} question-answer pairs derived from real network topologies, with {stats['topology_ratio']:.1%} focusing on topology-specific understanding rather than general networking knowledge."

### Dataset Description
"NetworkConfigQA comprises {stats['total_samples']:,} samples across {len(stats['category_counts'])} categories and {len(stats['complexity_counts'])} complexity levels, generated from {stats['device_count']} real network devices..."

### Evaluation Setup  
"We evaluate models on exact match accuracy, F1 score, and topology-specific accuracy. The dataset is split into {stats['train_samples']:,}/{stats['val_samples']:,}/{stats['test_samples']:,} for train/validation/test..."
"""
        
        with open(self.output_dir / 'comprehensive_analysis_report.md', 'w', encoding='utf-8') as f:
            f.write(report)
        
        print("📝 리포트 생성 완료")


def main():
    """메인 실행 함수"""
    import sys
    
    dataset_path = "output/no_feedback/network_config_qa_dataset.json"
    
    if len(sys.argv) > 1:
        dataset_path = sys.argv[1]
    
    if not Path(dataset_path).exists():
        print(f"❌ 데이터셋 파일을 찾을 수 없습니다: {dataset_path}")
        return
    
    analyzer = SimpleNetworkDatasetAnalyzer(dataset_path)
    stats = analyzer.generate_analysis()
    
    print("\\n" + "="*50)
    print("📊 주요 통계 요약")
    print("="*50)
    print(f"총 샘플 수: {stats['total_samples']:,}")
    print(f"토폴로지 특화 비율: {stats['topology_ratio']:.1%}")
    print(f"평균 질문 길이: {stats['avg_question_length']:.1f} 단어")
    print(f"카테고리 수: {len(stats['category_counts'])}")
    print(f"복잡도 레벨: {len(stats['complexity_counts'])}")

if __name__ == "__main__":
    main()
