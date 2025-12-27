"""
NetConfigQA Evaluation Visualizer

reanalyze_results.py가 생성한 analyzed JSON 파일을 입력받아
논문용 고품질 Figure를 생성합니다.

Usage:
    python Figure.py results_analyzed_*.json
    python Figure.py results_analyzed_*.json --output ./figures
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd

# Visualization imports
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print("Error: matplotlib not found. Please install it using `pip install matplotlib`.")
    exit(1)


class AcademicFigureGenerator:
    """
    논문용 고품질 Figure 생성기.
    각 Figure는 개별 PNG 파일로 저장됩니다.
    """
    
    # 색상 팔레트 (학술 논문용)
    COLORS = {
        'primary': '#2E86AB',
        'secondary': '#A23B72', 
        'accent': '#F18F01',
        'neutral': '#6C757D',
        'success': '#28A745',
        'danger': '#DC3545',
        'levels': ['#1a9850', '#91cf60', '#fee08b', '#fc8d59', '#d73027'],  # L1-L5 (green to red)
    }
    
    # 레벨 설명
    LEVEL_DESC = {
        'L1': 'Single Device\nExtraction',
        'L2': 'Multi-Device\nAggregation', 
        'L3': 'Cross-Device\nComparison',
        'L4': 'Reachability\nAnalysis',
        'L5': 'What-If\nAnalysis'
    }
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 논문용 스타일 설정
        plt.style.use('seaborn-v0_8-whitegrid')
        plt.rcParams.update({
            'font.family': 'sans-serif',
            'font.size': 11,
            'axes.titlesize': 14,
            'axes.labelsize': 12,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10,
            'legend.fontsize': 10,
            'figure.dpi': 150,
            'savefig.dpi': 300,
            'savefig.bbox': 'tight',
            'savefig.facecolor': 'white',
            'axes.facecolor': 'white',
            'figure.facecolor': 'white',
        })
    
    def generate_all(self, json_path: str):
        """모든 Figure 생성"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        stats = data.get('stats', {})
        results = data.get('results', [])
        model_name = data.get('meta', {}).get('model', 'Unknown')
        
        print(f"\n[Generating Figures for: {model_name}]")
        print(f"Output directory: {self.output_dir}\n")
        
        # Figure 1: Level별 정확도
        self.fig1_accuracy_by_level(stats, model_name)
        
        # Figure 2: Answer Type별 정확도
        self.fig2_accuracy_by_type(stats, model_name)
        
        # Figure 3: Positive/Negative Testing 비교
        self.fig3_positive_negative(stats, model_name)
        
        # Figure 4: Level x Category Heatmap
        self.fig4_heatmap(results, model_name)
        
        print(f"\n[OK] All figures saved to: {self.output_dir}")
        return self.output_dir
    
    def fig1_accuracy_by_level(self, stats: dict, model_name: str):
        """Figure 1: 난이도 레벨별 정확도 막대 그래프"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        levels = ['L1', 'L2', 'L3', 'L4', 'L5']
        accuracies = [stats['by_level'].get(l, 0) * 100 for l in levels]
        
        # 막대 그래프
        bars = ax.bar(levels, accuracies, 
                      color=self.COLORS['levels'], 
                      edgecolor='black', 
                      linewidth=0.8,
                      width=0.7)
        
        # 값 표시
        for bar, acc in zip(bars, accuracies):
            height = bar.get_height()
            ax.annotate(f'{acc:.1f}%',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 5), textcoords="offset points",
                        ha='center', va='bottom', 
                        fontsize=11, fontweight='bold')
        
        # 스타일링
        ax.set_xlabel('Difficulty Level', fontweight='bold', fontsize=12)
        ax.set_ylabel('Accuracy (%)', fontweight='bold', fontsize=12)
        ax.set_title(f'Accuracy by Question Difficulty Level\n({model_name})', 
                     fontweight='bold', fontsize=14, pad=15)
        ax.set_ylim(0, 110)
        
        # X축 레이블에 설명 추가
        ax.set_xticks(range(len(levels)))
        ax.set_xticklabels([f'{l}\n{self.LEVEL_DESC[l]}' for l in levels], fontsize=9)
        
        # 평균선
        avg_acc = np.mean(accuracies)
        ax.axhline(y=avg_acc, color=self.COLORS['neutral'], linestyle='--', linewidth=2, 
                   label=f'Average: {avg_acc:.1f}%')
        ax.legend(loc='upper right', fontsize=10)
        
        # 스파인 제거
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        # 저장
        output_path = self.output_dir / "fig1_accuracy_by_level.png"
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        print(f"  ✓ Saved: {output_path.name}")
    
    def fig2_accuracy_by_type(self, stats: dict, model_name: str):
        """Figure 2: 답변 타입별 정확도 (수평 막대)"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # 데이터 정렬
        types = list(stats['by_type'].keys())
        accuracies = [stats['by_type'][t] * 100 for t in types]
        sorted_data = sorted(zip(types, accuracies), key=lambda x: x[1], reverse=True)
        types, accuracies = zip(*sorted_data)
        
        # 색상 (정확도 기반)
        colors = plt.cm.RdYlGn(np.array(accuracies) / 100)
        
        # 수평 막대 그래프
        bars = ax.barh(types, accuracies, 
                       color=colors, 
                       edgecolor='black', 
                       linewidth=0.8,
                       height=0.6)
        
        # 값 표시
        for bar, acc in zip(bars, accuracies):
            width = bar.get_width()
            ax.annotate(f'{acc:.1f}%',
                        xy=(width, bar.get_y() + bar.get_height() / 2),
                        xytext=(5, 0), textcoords="offset points",
                        ha='left', va='center', 
                        fontsize=10, fontweight='bold')
        
        # 스타일링
        ax.set_xlabel('Accuracy (%)', fontweight='bold', fontsize=12)
        ax.set_ylabel('Answer Type', fontweight='bold', fontsize=12)
        ax.set_title(f'Accuracy by Answer Type\n({model_name})', 
                     fontweight='bold', fontsize=14, pad=15)
        ax.set_xlim(0, 115)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        # 저장
        output_path = self.output_dir / "fig2_accuracy_by_type.png"
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        print(f"  ✓ Saved: {output_path.name}")
    
    def fig3_positive_negative(self, stats: dict, model_name: str):
        """Figure 3: Positive vs Negative Testing 비교"""
        fig, ax = plt.subplots(figsize=(8, 6))
        
        labels = ['Positive\n(OK)', 'Negative\n(NOT_CONFIGURED)']
        values = [
            stats['by_status'].get('OK', 0) * 100,
            stats['by_status'].get('NOT_CONFIGURED', 0) * 100
        ]
        
        # 막대 그래프
        colors = [self.COLORS['success'], self.COLORS['danger']]
        bars = ax.bar(labels, values, 
                      color=colors, 
                      edgecolor='black', 
                      linewidth=0.8, 
                      width=0.5)
        
        # 값 표시
        for bar, val in zip(bars, values):
            height = bar.get_height()
            ax.annotate(f'{val:.1f}%',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 5), textcoords="offset points",
                        ha='center', va='bottom', 
                        fontsize=14, fontweight='bold')
        
        # 스타일링
        ax.set_ylabel('Accuracy (%)', fontweight='bold', fontsize=12)
        ax.set_title(f'Positive vs Negative Testing\n({model_name})', 
                     fontweight='bold', fontsize=14, pad=15)
        ax.set_ylim(0, 110)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        # 저장
        output_path = self.output_dir / "fig3_positive_negative.png"
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        print(f"  ✓ Saved: {output_path.name}")
    
    def fig4_heatmap(self, results: list, model_name: str):
        """Figure 4: Level x Category Heatmap"""
        if not results:
            print("  ⚠ Skipped heatmap: No results data")
            return
        
        df = pd.DataFrame(results)
        
        # 피벗 테이블 생성
        pivot = df.pivot_table(
            values='score', 
            index='level', 
            columns='category', 
            aggfunc='mean'
        ).fillna(0) * 100
        
        # 레벨 순서 정렬
        level_order = ['L1', 'L2', 'L3', 'L4', 'L5']
        pivot = pivot.reindex([l for l in level_order if l in pivot.index])
        
        # Figure 크기 동적 조정
        n_cols = len(pivot.columns)
        fig_width = max(12, n_cols * 0.8)
        fig, ax = plt.subplots(figsize=(fig_width, 6))
        
        # Heatmap
        im = ax.imshow(pivot.values, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
        
        # 축 설정
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels([c.replace('_', '\n') for c in pivot.columns], 
                           rotation=45, ha='right', fontsize=8)
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index, fontsize=10)
        
        # 값 표시
        for i in range(len(pivot.index)):
            for j in range(len(pivot.columns)):
                val = pivot.values[i, j]
                color = 'white' if val < 50 else 'black'
                ax.text(j, i, f'{val:.0f}', 
                        ha='center', va='center', 
                        color=color, fontsize=8, fontweight='bold')
        
        # 스타일링
        ax.set_xlabel('Category', fontweight='bold', fontsize=12)
        ax.set_ylabel('Level', fontweight='bold', fontsize=12)
        ax.set_title(f'Accuracy Heatmap: Level × Category\n({model_name})', 
                     fontweight='bold', fontsize=14, pad=15)
        
        # 컬러바
        cbar = plt.colorbar(im, ax=ax, shrink=0.8, pad=0.02)
        cbar.set_label('Accuracy (%)', fontweight='bold', fontsize=10)
        
        # 저장
        output_path = self.output_dir / "fig4_heatmap.png"
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        print(f"  ✓ Saved: {output_path.name}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate academic figures from NetConfigQA evaluation results"
    )
    parser.add_argument("json_file", help="Path to analyzed results JSON (*_analyzed_*.json)")
    parser.add_argument("--output", "-o", default=None, 
                        help="Output directory (default: same dir as input/figures)")
    args = parser.parse_args()
    
    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"Error: File not found: {json_path}")
        return
    
    # 출력 디렉토리 결정
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = json_path.parent / "figures"
    
    # Figure 생성
    generator = AcademicFigureGenerator(str(output_dir))
    generator.generate_all(str(json_path))


if __name__ == "__main__":
    main()
