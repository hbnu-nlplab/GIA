#!/usr/bin/env python3
"""Dataset quality validator for NetConfigQA generation outputs."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

SUPPORTED_TYPES = {
    "text",
    "number",
    "numeric",
    "set",
    "map",
    "boolean",
    "bool",
    "set_str",
    "map_str_str",
    "map_str_int",
    "scalar_int",
    "scalar_str",
    "enum",
    "json",
    "path",
    "edge_set",
    "list",
}

STRUCTURED_METRICS = {
    "compare_bgp_neighbor_count",
    "compare_interface_count",
    "compare_vrf_count",
}

RE_STRUCT_PLACEHOLDER = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")


def _load_rows(dataset_path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if dataset_path.suffix.lower() == ".json":
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            rows = payload.get("questions", [])
            meta = payload.get("meta", {}) if isinstance(payload.get("meta"), dict) else {}
            return list(rows), meta
        if isinstance(payload, list):
            return payload, {}
        raise ValueError("Unsupported JSON structure")

    if dataset_path.suffix.lower() == ".csv":
        with dataset_path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f)), {}

    raise ValueError(f"Unsupported dataset extension: {dataset_path.suffix}")


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return bool(RE_STRUCT_PLACEHOLDER.search(value))
    if isinstance(value, dict):
        return any(_contains_placeholder(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_placeholder(v) for v in value)
    return False


def _metric_name_from_row(row: Dict[str, Any]) -> str:
    evidence_raw = row.get("evidence")
    if isinstance(evidence_raw, str) and evidence_raw:
        try:
            evidence = json.loads(evidence_raw)
            if isinstance(evidence, dict) and evidence.get("metric"):
                return str(evidence["metric"]).strip().lower()
        except Exception:
            pass

    metric = row.get("metric")
    if metric:
        return str(metric).strip().lower()

    rid = str(row.get("id", row.get("question_id", ""))).lower()
    for target in STRUCTURED_METRICS:
        if rid.startswith(target) or target in rid:
            return target
    return ""


def _parse_answer_value(row: Dict[str, Any]) -> Any:
    answer = row.get("answer")
    if answer is None:
        return None
    if not isinstance(answer, str):
        return answer
    answer = answer.strip()
    if not answer:
        return None
    try:
        return json.loads(answer)
    except Exception:
        return answer


def _is_supported_answer_type(answer_type: str) -> bool:
    return str(answer_type).strip().lower() in SUPPORTED_TYPES


def _structured_schema_ok(metric: str, value: Any) -> bool:
    if metric not in STRUCTURED_METRICS:
        return True
    if not isinstance(value, dict):
        return False
    required_keys = {"host1_count", "host2_count", "difference"}
    if set(value.keys()) != required_keys:
        return False
    return all(isinstance(value[k], int) for k in required_keys)


def _markdown_report(report: Dict[str, Any]) -> str:
    checks = report["checks"]
    lines = [
        "# Dataset Quality Report",
        "",
        f"- dataset: `{report['dataset']}`",
        f"- total_rows: {report['total_rows']}",
        f"- quality_gate_passed: **{report['quality_gate_passed']}**",
        "",
        "## Checks",
        "",
        "| check | value | pass |",
        "|---|---:|:---:|",
        f"| duplicate_id_count | {checks['duplicate_id_count']} | {'✅' if checks['duplicate_id_count'] == 0 else '❌'} |",
        f"| evidence_placeholder_count | {checks['evidence_placeholder_count']} | {'✅' if checks['evidence_placeholder_count'] == 0 else '❌'} |",
        f"| unsupported_answer_type_count | {checks['unsupported_answer_type_count']} | {'✅' if checks['unsupported_answer_type_count'] == 0 else '❌'} |",
        (
            f"| structured_schema_pass_rate | {checks['structured_schema_pass_rate']:.3f} "
            f"({checks['structured_schema_valid']}/{checks['structured_schema_total']}) | "
            f"{'✅' if checks['structured_schema_pass_rate'] == 1.0 else '❌'} |"
        ),
    ]
    if checks["duplicate_id_examples"]:
        lines.extend([
            "",
            "## Duplicate ID Examples",
            "",
            ", ".join(f"`{x}`" for x in checks["duplicate_id_examples"]),
        ])
    return "\n".join(lines) + "\n"


def validate_dataset_quality(dataset_path: Path) -> Dict[str, Any]:
    rows, meta = _load_rows(dataset_path)

    ids = [str(r.get("id", "")).strip() for r in rows if str(r.get("id", "")).strip()]
    id_counts = Counter(ids)
    duplicate_ids = sorted([k for k, v in id_counts.items() if v > 1])

    placeholder_count = 0
    unsupported_type_count = 0
    structured_total = 0
    structured_valid = 0

    for row in rows:
        answer_type = str(row.get("answer_type", "")).strip().lower()
        if answer_type and not _is_supported_answer_type(answer_type):
            unsupported_type_count += 1

        evidence_raw = row.get("evidence")
        evidence_obj: Any = evidence_raw
        if isinstance(evidence_raw, str) and evidence_raw:
            try:
                evidence_obj = json.loads(evidence_raw)
            except Exception:
                evidence_obj = evidence_raw
        if _contains_placeholder(evidence_obj):
            placeholder_count += 1

        metric = _metric_name_from_row(row)
        if metric in STRUCTURED_METRICS:
            structured_total += 1
            if _structured_schema_ok(metric, _parse_answer_value(row)):
                structured_valid += 1

    structured_rate = 1.0 if structured_total == 0 else structured_valid / structured_total

    checks = {
        "duplicate_id_count": len(duplicate_ids),
        "duplicate_id_examples": duplicate_ids[:20],
        "evidence_placeholder_count": placeholder_count,
        "unsupported_answer_type_count": unsupported_type_count,
        "structured_schema_total": structured_total,
        "structured_schema_valid": structured_valid,
        "structured_schema_pass_rate": structured_rate,
    }

    passed = (
        checks["duplicate_id_count"] == 0
        and checks["evidence_placeholder_count"] == 0
        and checks["unsupported_answer_type_count"] == 0
        and checks["structured_schema_pass_rate"] == 1.0
    )

    return {
        "dataset": str(dataset_path),
        "total_rows": len(rows),
        "meta": meta,
        "checks": checks,
        "quality_gate_passed": passed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate NetConfigQA dataset quality gates")
    parser.add_argument("--dataset", required=True, help="Dataset path (.json or .csv)")
    parser.add_argument("--out-json", default=None, help="Output JSON report path")
    parser.add_argument("--out-md", default=None, help="Output Markdown report path")
    args = parser.parse_args()

    dataset_path = Path(args.dataset).resolve()
    report = validate_dataset_quality(dataset_path)

    out_json = Path(args.out_json).resolve() if args.out_json else dataset_path.with_name(dataset_path.stem + "_quality_report.json")
    out_md = Path(args.out_md).resolve() if args.out_md else dataset_path.with_name(dataset_path.stem + "_quality_report.md")

    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(_markdown_report(report), encoding="utf-8")

    print(f"[OK] JSON report: {out_json}")
    print(f"[OK] Markdown report: {out_md}")

    if not report["quality_gate_passed"]:
        print("[FAIL] dataset quality gate failed")
        raise SystemExit(1)

    print("[OK] dataset quality gate passed")


if __name__ == "__main__":
    main()
