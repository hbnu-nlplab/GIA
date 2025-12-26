"""
NetConfigQA Result Analyzer (Scoring Only)

이 스크립트는 run_netconfigqa_eval_vllm.py의 raw 결과를 분석합니다:
- 예측 전처리 (think 태그 제거, 정규화)
- 점수 계산 (answer_type별)
- 통계 분석
- Markdown/JSON 채점표 생성

시각화는 별도로 Figure.py에서 수행합니다.
"""

import json
import re
import os
import argparse
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict
from datetime import datetime


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


# ==================== Markdown Report Generator ====================

class ScorecardGenerator:
    """Generates Markdown scorecard from analysis results."""
    
    def generate(self, stats: dict, meta: dict, error_samples: list = None) -> str:
        """Generate a comprehensive Markdown scorecard."""
        lines = []
        
        # Header
        model_name = meta.get("model", "Unknown Model")
        lines.append(f"# NetConfigQA Evaluation Scorecard\n")
        lines.append(f"> **Model**: `{model_name}`  ")
        lines.append(f"> **Date**: {meta.get('date', datetime.now().isoformat())}  ")
        lines.append(f"> **Dataset**: `{meta.get('dataset', 'Unknown')}`\n")
        
        # Overall Score
        lines.append("## 📊 Overall Performance\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Overall Accuracy** | **{stats['accuracy']*100:.2f}%** |")
        lines.append(f"| Total Samples | {stats['total_samples']} |")
        lines.append(f"| Inference Time | {meta.get('duration', 0):.1f}s |")
        lines.append("")
        
        # By Level
        lines.append("## 📈 Accuracy by Difficulty Level\n")
        lines.append("| Level | Description | Accuracy | Status |")
        lines.append("|-------|-------------|----------|--------|")
        level_desc = {
            'L1': 'Single Device Extraction',
            'L2': 'Multi-Device Aggregation',
            'L3': 'Cross-Device Comparison',
            'L4': 'Reachability Analysis',
            'L5': 'What-If Analysis'
        }
        for level in ['L1', 'L2', 'L3', 'L4', 'L5']:
            acc = stats['by_level'].get(level, 0) * 100
            desc = level_desc.get(level, '')
            status = "✅" if acc >= 70 else "⚠️" if acc >= 40 else "❌"
            lines.append(f"| {level} | {desc} | {acc:.1f}% | {status} |")
        lines.append("")
        
        # By Answer Type
        lines.append("## 📝 Accuracy by Answer Type\n")
        lines.append("| Type | Accuracy |")
        lines.append("|------|----------|")
        for atype, acc in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {atype} | {acc*100:.1f}% |")
        lines.append("")
        
        # By Status (Positive/Negative Testing)
        lines.append("## 🔬 Positive vs Negative Testing\n")
        lines.append("| Test Type | Accuracy |")
        lines.append("|-----------|----------|")
        for status, acc in sorted(stats['by_status'].items()):
            label = "Positive (OK)" if status == "OK" else "Negative (NOT_CONFIGURED)"
            lines.append(f"| {label} | {acc*100:.1f}% |")
        lines.append("")
        
        # Error Analysis (if provided)
        if error_samples:
            lines.append("## ❌ Sample Errors\n")
            lines.append("| ID | Type | Gold | Pred | Score |")
            lines.append("|----|------|------|------|-------|")
            for e in error_samples[:15]:
                gold_short = e['gold'][:25] + "..." if len(e['gold']) > 25 else e['gold']
                pred_short = e['pred'][:25] + "..." if len(e['pred']) > 25 else e['pred']
                lines.append(f"| {e['id']} | {e['type']} | `{gold_short}` | `{pred_short}` | {e['score']:.2f} |")
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Generated by NetConfigQA Analyzer on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(lines)


# ==================== Main Analyzer ====================

def analyze_results(json_file: str, verbose: bool = False):
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

    # 결과 저장 (JSON)
    output_file = json_file.replace(".json", "_analyzed.json")
    if "_raw_" in json_file:
        output_file = json_file.replace("_raw_", "_analyzed_")
    
    meta = data.get("meta", {})
    output_data = {
        "meta": meta,
        "stats": stats,
        "results": results
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Saved analyzed results to: {output_file}")
    
    # Markdown 채점표 저장
    scorecard_file = output_file.replace(".json", "_scorecard.md")
    scorecard_gen = ScorecardGenerator()
    scorecard_md = scorecard_gen.generate(stats, meta, error_samples)
    
    with open(scorecard_file, 'w', encoding='utf-8') as f:
        f.write(scorecard_md)
    
    print(f"[OK] Saved scorecard to: {scorecard_file}")
    print(f"\n[TIP] Run 'python Figure.py \"{output_file}\"' to generate visualizations.")
    
    return stats, results


def main():
    parser = argparse.ArgumentParser(description="Analyze NetConfigQA evaluation results")
    parser.add_argument("json_file", help="Path to results json (raw or already analyzed)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed error analysis")
    args = parser.parse_args()

    analyze_results(args.json_file, args.verbose)


if __name__ == "__main__":
    main()
