#!/usr/bin/env python3
"""Generate markdown summary/statistics for NetConfigQA dataset outputs.

Supported input:
- dataset CSV
- dataset JSON (with "questions" list)
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def pct(part: int, total: int) -> float:
    return (part / total * 100.0) if total > 0 else 0.0


def load_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    suffix = dataset_path.suffix.lower()
    if suffix == ".csv":
        with dataset_path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))

    if suffix == ".json":
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            rows = payload.get("questions", payload.get("results", []))
            return list(rows) if isinstance(rows, list) else []
        if isinstance(payload, list):
            return payload
        return []

    raise ValueError(f"Unsupported dataset format: {dataset_path.suffix}")


def load_quality_report(dataset_path: Path) -> Dict[str, Any]:
    report_path = dataset_path.with_name(f"{dataset_path.stem}_quality_report.json")
    if not report_path.exists():
        return {}
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def analyze_dataset(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    stats: Dict[str, Any] = {
        "total": len(rows),
        "by_level": Counter(),
        "by_category": Counter(),
        "by_type": Counter(),
        "by_status": Counter(),
        "level_category": defaultdict(Counter),
        "level_type": defaultdict(Counter),
    }

    for row in rows:
        level = str(row.get("level", "Unknown"))
        category = str(row.get("category", "Unknown"))
        answer_type = str(row.get("answer_type", "Unknown"))
        status = str(row.get("answer_status", row.get("status", "OK")))

        stats["by_level"][level] += 1
        stats["by_category"][category] += 1
        stats["by_type"][answer_type] += 1
        stats["by_status"][status] += 1
        stats["level_category"][level][category] += 1
        stats["level_type"][level][answer_type] += 1

    return stats


def generate_markdown(
    stats: Dict[str, Any],
    dataset_name: str,
    quality: Dict[str, Any],
) -> str:
    lines: List[str] = []
    total = stats["total"]

    lines.append("# NetConfigQA Dataset Statistics")
    lines.append("")
    lines.append(f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"> Dataset: `{dataset_name}`")
    lines.append("")

    lines.append("## 1. Overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total Questions | **{total}** |")
    lines.append(f"| Difficulty Levels | {len(stats['by_level'])} |")
    lines.append(f"| Categories | {len(stats['by_category'])} |")
    lines.append(f"| Answer Types | {len(stats['by_type'])} |")
    ok_count = stats["by_status"].get("OK", 0)
    neg_count = stats["by_status"].get("NOT_CONFIGURED", 0)
    lines.append(f"| Positive Testing (OK) | {ok_count} ({pct(ok_count, total):.1f}%) |")
    lines.append(f"| Negative Testing (NOT_CONFIGURED) | {neg_count} ({pct(neg_count, total):.1f}%) |")
    lines.append("")

    if quality:
        checks = quality.get("checks", {}) if isinstance(quality.get("checks"), dict) else {}
        lines.append("## 2. Quality Gate")
        lines.append("")
        lines.append("| Check | Value |")
        lines.append("|---|---:|")
        lines.append(f"| quality_gate_passed | **{quality.get('quality_gate_passed', False)}** |")
        lines.append(f"| duplicate_id_count | {checks.get('duplicate_id_count', 'N/A')} |")
        lines.append(f"| evidence_placeholder_count | {checks.get('evidence_placeholder_count', 'N/A')} |")
        lines.append(f"| unsupported_answer_type_count | {checks.get('unsupported_answer_type_count', 'N/A')} |")
        lines.append(
            "| structured_schema_pass_rate | "
            f"{checks.get('structured_schema_pass_rate', 'N/A')} |"
        )
        lines.append("")

    lines.append("## 3. Distribution by Difficulty Level")
    lines.append("")
    lines.append("| Level | Count | Percentage |")
    lines.append("|---|---:|---:|")
    for level in sorted(stats["by_level"].keys()):
        count = stats["by_level"][level]
        lines.append(f"| {level} | {count} | {pct(count, total):.1f}% |")
    lines.append(f"| **Total** | **{total}** | **100.0%** |")
    lines.append("")

    lines.append("## 4. Distribution by Category")
    lines.append("")
    lines.append("| Category | Count | Percentage |")
    lines.append("|---|---:|---:|")
    for category in sorted(stats["by_category"].keys()):
        count = stats["by_category"][category]
        lines.append(f"| {category} | {count} | {pct(count, total):.1f}% |")
    lines.append(f"| **Total** | **{total}** | **100.0%** |")
    lines.append("")

    lines.append("## 5. Distribution by Answer Type")
    lines.append("")
    lines.append("| Answer Type | Count | Percentage |")
    lines.append("|---|---:|---:|")
    for answer_type in sorted(stats["by_type"].keys()):
        count = stats["by_type"][answer_type]
        lines.append(f"| {answer_type} | {count} | {pct(count, total):.1f}% |")
    lines.append(f"| **Total** | **{total}** | **100.0%** |")
    lines.append("")

    lines.append("## 6. Quick Copy Block")
    lines.append("")
    lines.append("```")
    lines.append(f"Total Questions: {total}")
    lines.append(f"Levels: {dict(sorted(stats['by_level'].items()))}")
    lines.append(f"Categories: {len(stats['by_category'])}")
    lines.append(f"Answer Types: {len(stats['by_type'])}")
    lines.append(f"Positive Testing (OK): {ok_count} ({pct(ok_count, total):.1f}%)")
    lines.append(f"Negative Testing (NOT_CONFIGURED): {neg_count} ({pct(neg_count, total):.1f}%)")
    if quality:
        lines.append(f"Quality Gate Passed: {quality.get('quality_gate_passed', False)}")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate dataset statistics markdown")
    parser.add_argument(
        "dataset_file",
        help="Path to dataset CSV/JSON (e.g., *_dataset_batfish_*.csv or .json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output markdown path (default: <dataset_stem>_statistics.md)",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset_file)
    if not dataset_path.exists():
        raise SystemExit(f"Error: file not found: {dataset_path}")

    rows = load_dataset(dataset_path)
    stats = analyze_dataset(rows)
    quality = load_quality_report(dataset_path)

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = dataset_path.with_name(f"{dataset_path.stem}_statistics.md")

    markdown = generate_markdown(stats, dataset_path.name, quality)
    output_path.write_text(markdown, encoding="utf-8")

    print(f"Statistics saved to: {output_path}")
    print("=== Quick Summary ===")
    print(f"Total Questions: {stats['total']}")
    print(f"Levels: {dict(sorted(stats['by_level'].items()))}")
    print(f"Categories: {len(stats['by_category'])}")
    print(f"Answer Types: {len(stats['by_type'])}")
    if quality:
        print(f"Quality Gate Passed: {quality.get('quality_gate_passed', False)}")


if __name__ == "__main__":
    main()
