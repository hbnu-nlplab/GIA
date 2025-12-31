"""
NetConfigQA 데이터셋 통계 분석 스크립트

데이터셋 CSV 파일의 통계 정보를 Markdown 문서로 생성합니다:
- 총 문제 수
- 레벨별 문제 수
- 카테고리(메트릭)별 문제 수
- 답변 타입별 문제 수
- OK/NOT_CONFIGURED 비율
"""

import csv
import argparse
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime


def load_dataset(csv_path: str) -> list:
    """데이터셋 CSV 로드"""
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)


def analyze_dataset(data: list) -> dict:
    """데이터셋 통계 분석"""
    stats = {
        "total": len(data),
        "by_level": Counter(),
        "by_category": Counter(),
        "by_type": Counter(),
        "by_status": Counter(),
        "level_category": defaultdict(Counter),
        "level_type": defaultdict(Counter),
    }
    
    for row in data:
        level = row.get('level', 'Unknown')
        category = row.get('category', 'Unknown')
        answer_type = row.get('answer_type', 'Unknown')
        status = row.get('answer_status', 'OK')
        
        stats["by_level"][level] += 1
        stats["by_category"][category] += 1
        stats["by_type"][answer_type] += 1
        stats["by_status"][status] += 1
        stats["level_category"][level][category] += 1
        stats["level_type"][level][answer_type] += 1
    
    return stats


def generate_markdown(stats: dict, dataset_name: str = "") -> str:
    """Markdown 문서 생성"""
    
    md = []
    md.append("# NetConfigQA Dataset Statistics\n")
    md.append(f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    if dataset_name:
        md.append(f"> Dataset: `{dataset_name}`\n")
    md.append("")
    
    # 1. Overview
    md.append("## 1. Overview\n")
    md.append(f"| Metric | Value |")
    md.append(f"|--------|-------|")
    md.append(f"| Total Questions | **{stats['total']}** |")
    md.append(f"| Difficulty Levels | {len(stats['by_level'])} |")
    md.append(f"| Categories | {len(stats['by_category'])} |")
    md.append(f"| Answer Types | {len(stats['by_type'])} |")
    md.append(f"| Positive Testing (OK) | {stats['by_status'].get('OK', 0)} ({stats['by_status'].get('OK', 0)/stats['total']*100:.1f}%) |")
    md.append(f"| Negative Testing (NOT_CONFIGURED) | {stats['by_status'].get('NOT_CONFIGURED', 0)} ({stats['by_status'].get('NOT_CONFIGURED', 0)/stats['total']*100:.1f}%) |")
    md.append("")
    
    # 2. By Level
    md.append("## 2. Distribution by Difficulty Level\n")
    md.append("| Level | Description | Count | Percentage |")
    md.append("|-------|-------------|------:|------------|")
    level_desc = {
        'L1': 'Single Device Extraction',
        'L2': 'Multi-Device Aggregation',
        'L3': 'Cross-Device Comparison',
        'L4': 'Reachability Analysis',
        'L5': 'What-If Analysis'
    }
    for level in sorted(stats["by_level"].keys()):
        count = stats["by_level"][level]
        pct = count / stats["total"] * 100
        desc = level_desc.get(level, '')
        md.append(f"| {level} | {desc} | {count} | {pct:.1f}% |")
    md.append(f"| **Total** | | **{stats['total']}** | **100%** |")
    md.append("")
    
    # 3. By Category
    md.append("## 3. Distribution by Category (Metric)\n")
    md.append("| Category | Count | Percentage |")
    md.append("|----------|------:|------------|")
    for category in sorted(stats["by_category"].keys()):
        count = stats["by_category"][category]
        pct = count / stats["total"] * 100
        md.append(f"| {category} | {count} | {pct:.1f}% |")
    md.append(f"| **Total** | **{stats['total']}** | **100%** |")
    md.append("")
    
    # 4. By Answer Type
    md.append("## 4. Distribution by Answer Type\n")
    md.append("| Answer Type | Count | Percentage |")
    md.append("|-------------|------:|------------|")
    for atype in sorted(stats["by_type"].keys()):
        count = stats["by_type"][atype]
        pct = count / stats["total"] * 100
        md.append(f"| {atype} | {count} | {pct:.1f}% |")
    md.append(f"| **Total** | **{stats['total']}** | **100%** |")
    md.append("")
    
    # 5. Level x Category Matrix
    md.append("## 5. Level × Category Distribution\n")
    categories = sorted(stats["by_category"].keys())
    
    # Header
    header = "| Level |"
    for cat in categories:
        short_cat = cat.replace('_', ' ')
        header += f" {short_cat} |"
    header += " Total |"
    md.append(header)
    
    # Separator
    sep = "|-------|"
    for _ in categories:
        sep += "---:|"
    sep += "---:|"
    md.append(sep)
    
    # Data rows
    for level in sorted(stats["level_category"].keys()):
        row = f"| {level} |"
        level_total = 0
        for cat in categories:
            count = stats["level_category"][level].get(cat, 0)
            level_total += count
            row += f" {count if count > 0 else '-'} |"
        row += f" {level_total} |"
        md.append(row)
    md.append("")
    
    # 6. Level x Type Matrix
    md.append("## 6. Level × Answer Type Distribution\n")
    types = sorted(stats["by_type"].keys())
    
    # Header
    header = "| Level |"
    for t in types:
        header += f" {t} |"
    header += " Total |"
    md.append(header)
    
    # Separator
    sep = "|-------|"
    for _ in types:
        sep += "---:|"
    sep += "---:|"
    md.append(sep)
    
    # Data rows
    for level in sorted(stats["level_type"].keys()):
        row = f"| {level} |"
        level_total = 0
        for t in types:
            count = stats["level_type"][level].get(t, 0)
            level_total += count
            row += f" {count if count > 0 else '-'} |"
        row += f" {level_total} |"
        md.append(row)
    md.append("")
    
    # 7. Summary for Paper (LaTeX-friendly)
    md.append("## 7. Summary for Paper\n")
    md.append("```")
    md.append(f"Total Questions: {stats['total']}")
    md.append(f"Difficulty Levels: {len(stats['by_level'])} (L1-L5)")
    md.append(f"Categories: {len(stats['by_category'])}")
    md.append(f"Answer Types: {len(stats['by_type'])}")
    md.append(f"Positive Testing: {stats['by_status'].get('OK', 0)} ({stats['by_status'].get('OK', 0)/stats['total']*100:.1f}%)")
    md.append(f"Negative Testing: {stats['by_status'].get('NOT_CONFIGURED', 0)} ({stats['by_status'].get('NOT_CONFIGURED', 0)/stats['total']*100:.1f}%)")
    md.append("```")
    md.append("")
    
    # Level stats
    md.append("### Level Distribution\n")
    md.append("```")
    for level in sorted(stats["by_level"].keys()):
        count = stats["by_level"][level]
        pct = count / stats["total"] * 100
        md.append(f"{level}: {count} ({pct:.1f}%)")
    md.append("```")
    md.append("")
    
    # Type stats
    md.append("### Answer Type Distribution\n")
    md.append("```")
    for atype in sorted(stats["by_type"].keys()):
        count = stats["by_type"][atype]
        pct = count / stats["total"] * 100
        md.append(f"{atype}: {count} ({pct:.1f}%)")
    md.append("```")
    
    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="NetConfigQA Dataset Statistics")
    parser.add_argument("csv_file", help="Path to dataset CSV file")
    parser.add_argument("--output", "-o", help="Output markdown file path (default: same dir as input)")
    args = parser.parse_args()
    
    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"Error: File not found: {csv_path}")
        return
    
    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = csv_path.parent / f"{csv_path.stem}_statistics.md"
    
    print(f"Loading dataset from: {csv_path}")
    data = load_dataset(str(csv_path))
    
    stats = analyze_dataset(data)
    markdown = generate_markdown(stats, csv_path.name)
    
    # Save markdown
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)
    
    print(f"Statistics saved to: {output_path}")
    
    # Also print summary
    print(f"\n=== Quick Summary ===")
    print(f"Total Questions: {stats['total']}")
    print(f"Levels: {dict(sorted(stats['by_level'].items()))}")
    print(f"Categories: {len(stats['by_category'])}")
    print(f"Answer Types: {len(stats['by_type'])}")


if __name__ == "__main__":
    main()