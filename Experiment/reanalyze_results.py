"""
NetConfigQA Result Analyzer

이 스크립트는 run_netconfigqa_eval_vllm.py의 raw 결과를 분석합니다:
- 예측 전처리 (think 태그 제거, 정규화)
- 점수 계산 (answer_type별)
- 통계 분석
- 시각화 (Figure 생성)
"""

import json
import re
import os
import argparse
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

import numpy as np
import pandas as pd

# Optional Visualization
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print("Warning: matplotlib not found. Visualization will be skipped.")


# ==================== Scorer ====================

class NetConfigQAScorer:
    """Handles scoring based on answer types."""
    
    def clean_prediction(self, pred: str) -> str:
        """
        Clean model prediction by removing thinking tags and normalizing format.
        
        Handles:
        - Complete <think>...</think> blocks
        - Incomplete <think>... (truncated output without closing tag)
        - Markdown code blocks
        - Quoted strings
        - Null values
        """
        if not pred:
            return ""
            
        # 1. Strip <think>...</think> blocks
        # Case 1: Complete tags
        pred = re.sub(r"<think>.*?</think>", "", pred, flags=re.DOTALL).strip()
        # Case 2: Incomplete/truncated <think>... (no closing tag)
        pred = re.sub(r"<think>.*$", "", pred, flags=re.DOTALL).strip()
        
        # 2. Strip standard Markdown code blocks if present
        pred = re.sub(r"```.*?```", "", pred, flags=re.DOTALL).strip()
        pred = pred.replace("```json", "").replace("```", "").strip()

        # 3. Basic normalization
        pred = pred.strip('\n\r\t ')
        
        # Unquote (double or single quotes) - only if properly balanced
        if len(pred) >= 2 and ((pred.startswith('"') and pred.endswith('"')) or \
                               (pred.startswith("'") and pred.endswith("'"))):
            pred = pred[1:-1]
            
        # Handle nulls
        if pred.lower() in ['null', 'none', 'n/a', 'not configured', 'not found', '']:
            pred = ""
            
        return pred

    def clean_gold(self, gold: str) -> str:
        """Clean gold answer with same normalization as prediction."""
        gold = str(gold).strip()
        
        # Unquote gold
        if len(gold) >= 2 and ((gold.startswith('"') and gold.endswith('"')) or \
                               (gold.startswith("'") and gold.endswith("'"))):
            gold = gold[1:-1]
        
        if gold.lower() in ['null', 'none', 'n/a', 'not configured', '']:
            gold = ""
            
        return gold

    def score(self, pred: str, gold: str, answer_type: str) -> Dict[str, float]:
        """Score prediction against gold answer based on answer type."""
        gold = self.clean_gold(gold)

        try:
            if answer_type == "boolean":
                return self._score_boolean(pred, gold)
            elif answer_type in ["numeric", "scalar_int", "number"]:
                return self._score_numeric(pred, gold)
            elif answer_type in ["set", "set_str", "list"]:
                return self._score_set(pred, gold)
            elif answer_type in ["map", "map_str_str", "dictionary", "json"]:
                return self._score_map(pred, gold)
            else:  # text
                return self._score_text(pred, gold)
        except Exception as e:
            return {"score": 0.0, "error": str(e)}

    def _clean_bool(self, val: str) -> bool:
        val = val.lower()
        if val in ['true', 'yes', 'on', 'enabled', '1']:
            return True
        return False

    def _score_boolean(self, pred: str, gold: str) -> Dict[str, float]:
        return {"score": 1.0 if self._clean_bool(pred) == self._clean_bool(gold) else 0.0}

    def _extract_number(self, val: str) -> float:
        try:
            match = re.search(r'-?\d+(\.\d+)?', val)
            return float(match.group()) if match else None
        except:
            return None

    def _score_numeric(self, pred: str, gold: str) -> Dict[str, float]:
        p_num = self._extract_number(pred)
        g_num = self._extract_number(gold)
        if p_num is None or g_num is None:
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
        return {"score": 1.0 if p_num == g_num else 0.0}

    def _parse_set(self, val: str) -> Set[str]:
        try:
            val = val.replace("'", '"')
            if val.startswith('[') and val.endswith(']'):
                items = json.loads(val)
                return set(str(i).strip().lower() for i in items)
        except:
            pass
        return set(i.strip().lower() for i in val.split(',')) if val else set()

    def _score_set(self, pred: str, gold: str) -> Dict[str, float]:
        p_set = self._parse_set(pred)
        g_set = self._parse_set(gold)
        if not g_set and not p_set:
            return {"score": 1.0, "f1": 1.0}
        
        intersection = len(p_set & g_set)
        precision = intersection / len(p_set) if p_set else 0.0
        recall = intersection / len(g_set) if g_set else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return {"score": f1, "f1": f1, "precision": precision, "recall": recall}

    def _score_map(self, pred: str, gold: str) -> Dict[str, float]:
        try:
            p_obj = json.loads(pred.replace("'", '"'))
            g_obj = json.loads(gold.replace("'", '"'))
        except:
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
        
        if not isinstance(p_obj, dict) or not isinstance(g_obj, dict):
            return {"score": 1.0 if str(p_obj) == str(g_obj) else 0.0}
             
        common = set(p_obj.keys()) & set(g_obj.keys())
        all_k = set(p_obj.keys()) | set(g_obj.keys())
        if not all_k:
            return {"score": 1.0}
        
        val_matches = sum(1 for k in common if str(p_obj[k]).lower() == str(g_obj[k]).lower())
        return {"score": (len(common)/len(all_k)*0.5) + (val_matches/len(common)*0.5 if common else 0)}

    def _score_text(self, pred: str, gold: str) -> Dict[str, float]:
        return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}


# ==================== Visualizer ====================

class ResultVisualizer:
    """Generates academic figures from evaluation results."""
    
    # 색상 팔레트 (논문용)
    COLORS = {
        'primary': '#2E86AB',
        'secondary': '#A23B72', 
        'accent': '#F18F01',
        'neutral': '#6C757D',
        'levels': ['#1a9850', '#91cf60', '#fee08b', '#fc8d59', '#d73027'],  # L1-L5
    }
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 논문용 스타일 설정
        plt.style.use('seaborn-v0_8-whitegrid')
        plt.rcParams.update({
            'font.size': 11,
            'axes.titlesize': 13,
            'axes.labelsize': 11,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10,
            'legend.fontsize': 10,
            'figure.dpi': 150,
            'savefig.dpi': 300,
            'savefig.bbox': 'tight',
        })
    
    def plot_accuracy_by_level(self, stats: dict, ax=None):
        """Figure 1: 난이도 레벨별 정확도"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(8, 5))
        
        levels = ['L1', 'L2', 'L3', 'L4', 'L5']
        level_desc = {
            'L1': 'Single Device\nExtraction',
            'L2': 'Multi-Device\nAggregation', 
            'L3': 'Cross-Device\nComparison',
            'L4': 'Reachability\nAnalysis',
            'L5': 'What-If\nAnalysis'
        }
        
        accuracies = [stats['by_level'].get(l, 0) * 100 for l in levels]
        bars = ax.bar(levels, accuracies, color=self.COLORS['levels'], edgecolor='black', linewidth=0.5)
        
        for bar, acc in zip(bars, accuracies):
            height = bar.get_height()
            ax.annotate(f'{acc:.1f}%',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        ax.set_xlabel('Difficulty Level', fontweight='bold')
        ax.set_ylabel('Accuracy (%)', fontweight='bold')
        ax.set_title('Accuracy by Question Difficulty Level', fontweight='bold', pad=10)
        ax.set_ylim(0, 100)
        ax.set_xticks(range(len(levels)))
        ax.set_xticklabels([f'{l}\n{level_desc[l]}' for l in levels], fontsize=9)
        
        avg_acc = np.mean(accuracies)
        ax.axhline(y=avg_acc, color=self.COLORS['neutral'], linestyle='--', linewidth=1.5, 
                   label=f'Average: {avg_acc:.1f}%')
        ax.legend(loc='upper right')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        return ax

    def plot_accuracy_by_type(self, stats: dict, ax=None):
        """Figure 2: 답변 타입별 정확도 (수평 막대)"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(8, 5))
        
        types = list(stats['by_type'].keys())
        accuracies = [stats['by_type'][t] * 100 for t in types]
        
        sorted_data = sorted(zip(types, accuracies), key=lambda x: x[1], reverse=True)
        types, accuracies = zip(*sorted_data)
        
        colors = plt.cm.RdYlGn(np.array(accuracies) / 100)
        bars = ax.barh(types, accuracies, color=colors, edgecolor='black', linewidth=0.5)
        
        for bar, acc in zip(bars, accuracies):
            width = bar.get_width()
            ax.annotate(f'{acc:.1f}%',
                        xy=(width, bar.get_y() + bar.get_height() / 2),
                        xytext=(3, 0), textcoords="offset points",
                        ha='left', va='center', fontsize=10, fontweight='bold')
        
        ax.set_xlabel('Accuracy (%)', fontweight='bold')
        ax.set_ylabel('Answer Type', fontweight='bold')
        ax.set_title('Accuracy by Answer Type', fontweight='bold', pad=10)
        ax.set_xlim(0, 110)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        return ax

    def plot_positive_negative(self, stats: dict, ax=None):
        """Figure 3: Positive vs Negative Testing 비교"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(6, 5))
        
        labels = ['Positive\n(OK)', 'Negative\n(NOT_CONFIGURED)']
        values = [
            stats['by_status'].get('OK', 0) * 100,
            stats['by_status'].get('NOT_CONFIGURED', 0) * 100
        ]
        
        colors = [self.COLORS['primary'], self.COLORS['secondary']]
        bars = ax.bar(labels, values, color=colors, edgecolor='black', linewidth=0.5, width=0.6)
        
        for bar, val in zip(bars, values):
            height = bar.get_height()
            ax.annotate(f'{val:.1f}%',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=12, fontweight='bold')
        
        ax.set_ylabel('Accuracy (%)', fontweight='bold')
        ax.set_title('Positive vs Negative Testing', fontweight='bold', pad=10)
        ax.set_ylim(0, 100)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        return ax

    def plot_heatmap(self, results: list, ax=None):
        """Figure 4: 레벨 x 카테고리 Heatmap"""
        if ax is None:
            fig, ax = plt.subplots(figsize=(14, 6))
        
        df = pd.DataFrame(results)
        pivot = df.pivot_table(
            values='score', 
            index='level', 
            columns='category', 
            aggfunc='mean'
        ).fillna(0) * 100
        
        level_order = ['L1', 'L2', 'L3', 'L4', 'L5']
        pivot = pivot.reindex([l for l in level_order if l in pivot.index])
        
        im = ax.imshow(pivot.values, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
        
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels([c.replace('_', '\n') for c in pivot.columns], rotation=45, ha='right', fontsize=8)
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index)
        
        for i in range(len(pivot.index)):
            for j in range(len(pivot.columns)):
                val = pivot.values[i, j]
                color = 'white' if val < 50 else 'black'
                ax.text(j, i, f'{val:.0f}', ha='center', va='center', color=color, fontsize=8, fontweight='bold')
        
        ax.set_xlabel('Category', fontweight='bold')
        ax.set_ylabel('Level', fontweight='bold')
        ax.set_title('Accuracy Heatmap: Level x Category', fontweight='bold', pad=10)
        
        cbar = plt.colorbar(im, ax=ax, shrink=0.8)
        cbar.set_label('Accuracy (%)', fontweight='bold')
        
        return ax

    def create_summary_figure(self, stats: dict, results: list, model_name: str):
        """종합 Figure 생성 (2x2 레이아웃)"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 12))
        fig.suptitle(f"NetConfigQA Evaluation Results: {model_name}", 
                     fontsize=16, fontweight='bold', y=1.02)
        
        self.plot_accuracy_by_level(stats, axes[0, 0])
        self.plot_accuracy_by_type(stats, axes[0, 1])
        self.plot_positive_negative(stats, axes[1, 0])
        
        # 4번째 칸에 통계 요약 텍스트
        ax = axes[1, 1]
        ax.axis('off')
        summary_text = f"""
Overall Accuracy: {stats['accuracy']*100:.2f}%
Total Samples: {stats['total_samples']}

By Level:
{chr(10).join(f"  {k}: {v*100:.1f}%" for k, v in sorted(stats['by_level'].items()))}

By Status:
{chr(10).join(f"  {k}: {v*100:.1f}%" for k, v in sorted(stats['by_status'].items()))}
"""
        ax.text(0.1, 0.9, summary_text, transform=ax.transAxes, fontsize=11,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        
        output_path = self.output_dir / "summary.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.savefig(str(output_path).replace('.png', '.pdf'), facecolor='white')
        plt.close()
        
        print(f"   Saved: {output_path}")

    def create_heatmap_figure(self, results: list):
        """Heatmap Figure 별도 생성"""
        fig, ax = plt.subplots(figsize=(14, 6))
        self.plot_heatmap(results, ax)
        
        plt.tight_layout()
        output_path = self.output_dir / "heatmap.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        plt.savefig(str(output_path).replace('.png', '.pdf'), facecolor='white')
        plt.close()
        
        print(f"   Saved: {output_path}")


# ==================== Main Analyzer ====================

def analyze_results(json_file: str, verbose: bool = False, visualize: bool = True):
    """메인 분석 함수"""
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    scorer = NetConfigQAScorer()
    results = []
    
    # 통계 수집용
    grouped_by_type = defaultdict(list)
    grouped_by_level = defaultdict(list)
    grouped_by_category = defaultdict(list)
    grouped_by_status = defaultdict(list)
    error_samples = []
    
    print(f"Analyzing {len(data['results'])} results...")

    for row in data['results']:
        # 필드명 호환성 처리 (raw_pred vs pred, answer_type vs type, answer_status vs status)
        raw_pred = row.get('raw_pred', row.get('pred', ''))
        answer_type = row.get('answer_type', row.get('type', 'text'))
        status = row.get('answer_status', row.get('status', 'OK'))
        level = row.get('level', 'L1')
        category = row.get('category', 'General')
        
        # 전처리
        clean_pred = scorer.clean_prediction(raw_pred)
        clean_gold = scorer.clean_gold(row['gold'])
        
        # 점수 계산
        metrics = scorer.score(clean_pred, row['gold'], answer_type)
        score = metrics['score']
        
        # 결과 저장
        result = {
            "question_id": row.get('question_id', ''),
            "question": row['question'],
            "gold": row['gold'],
            "gold_cleaned": clean_gold,
            "raw_pred": raw_pred,
            "pred": clean_pred,
            "score": score,
            "level": level,
            "category": category,
            "type": answer_type,
            "status": status,
        }
        result.update(metrics)  # 추가 메트릭 (f1, precision, recall 등)
        results.append(result)
        
        # 그룹별 통계
        grouped_by_type[answer_type].append(score)
        grouped_by_level[level].append(score)
        grouped_by_category[category].append(score)
        grouped_by_status[status].append(score)
        
        # 오류 샘플 수집
        if score < 0.99 and len(error_samples) < 20:
            error_samples.append({
                "id": row.get('question_id', '?'),
                "question": row['question'][:60] + "..." if len(row['question']) > 60 else row['question'],
                "gold": clean_gold[:40] if clean_gold else "(empty)",
                "pred": clean_pred[:40] if clean_pred else "(empty)",
                "type": answer_type,
                "score": score
            })

    n = len(results)
    total_score = sum(r['score'] for r in results)
    avg_acc = total_score / n if n > 0 else 0
    
    # 통계 빌드
    stats = {
        "accuracy": avg_acc,
        "total_samples": n,
        "by_type": {t: sum(s)/len(s) for t, s in grouped_by_type.items()},
        "by_level": {l: sum(s)/len(s) for l, s in grouped_by_level.items()},
        "by_category": {c: sum(s)/len(s) for c, s in grouped_by_category.items()},
        "by_status": {s: sum(sc)/len(sc) for s, sc in grouped_by_status.items()},
    }
    
    # 결과 출력
    print("\n" + "="*60)
    print("              ANALYSIS RESULTS")
    print("="*60)
    print(f"\n[Overall Accuracy]: {avg_acc:.2%}")
    
    print(f"\n[By Answer Type]")
    for t in sorted(grouped_by_type.keys()):
        scores = grouped_by_type[t]
        print(f"   {t:12s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    
    print(f"\n[By Level]")
    for lvl in sorted(grouped_by_level.keys()):
        scores = grouped_by_level[lvl]
        print(f"   {lvl:5s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    
    print(f"\n[By Status]")
    for status in sorted(grouped_by_status.keys()):
        scores = grouped_by_status[status]
        print(f"   {status:15s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    
    if verbose and error_samples:
        print(f"\n[Sample Errors (first {len(error_samples)})]")
        for i, e in enumerate(error_samples[:10], 1):
            print(f"\n   [{i}] ID: {e['id']} | Type: {e['type']} | Score: {e['score']:.2f}")
            print(f"       Q: {e['question']}")
            print(f"       Gold: {e['gold']}")
            print(f"       Pred: {e['pred']}")

    # 결과 저장
    output_file = json_file.replace(".json", "_analyzed.json")
    if "_raw_" in json_file:
        output_file = json_file.replace("_raw_", "_analyzed_")
    
    output_data = {
        "meta": data.get("meta", {}),
        "stats": stats,
        "results": results
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Saved analyzed results to: {output_file}")
    
    # 시각화
    if visualize and VISUALIZATION_AVAILABLE:
        print("\n[Generating Figures...]")
        model_name = data.get("meta", {}).get("model", "Unknown")
        output_dir = Path(output_file).parent / "figures"
        
        visualizer = ResultVisualizer(str(output_dir))
        visualizer.create_summary_figure(stats, results, model_name)
        visualizer.create_heatmap_figure(results)
        
        print(f"\n[OK] Figures saved to: {output_dir}")
    
    return stats, results


def main():
    parser = argparse.ArgumentParser(description="Analyze NetConfigQA evaluation results")
    parser.add_argument("json_file", help="Path to results json (raw or already analyzed)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed error analysis")
    parser.add_argument("--no-visualize", action="store_true", help="Skip figure generation")
    args = parser.parse_args()

    analyze_results(args.json_file, args.verbose, not args.no_visualize)


if __name__ == "__main__":
    main()
