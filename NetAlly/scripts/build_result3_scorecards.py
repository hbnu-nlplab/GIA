#!/usr/bin/env python3
"""Build normalized result3 scorecards from official raw evaluation outputs.

The script keeps raw JSON files in their original locations and writes only
derived scoring artifacts under NetAlly/result3.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


LABS = ("LabA", "LabB", "LabC", "LabD")
METHODS = ("singleLLM_cfg", "singleLLM_mcp", "masLLM_cfg", "masLLM_mcp")
DEFAULT_MCP_MODEL = "Mistral3-8B"
TYPE_COLUMNS = ("map", "number", "set", "text", "boolean", "path")


@dataclass(frozen=True)
class RawRun:
    family: str
    method: str
    model: str
    lab: str
    raw_path: Path


def load_analyzer(root: Path):
    analyzer_path = root / "Experiment/code/NetConfigQA2_2/analyze_results.py"
    spec = importlib.util.spec_from_file_location("netconfigqa_analyzer", analyzer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load analyzer from {analyzer_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def latest_json(paths: list[Path]) -> Path | None:
    valid = [
        path
        for path in paths
        if path.is_file()
        and path.suffix == ".json"
        and "_analyzed" not in path.name
        and "_errors" not in path.name
        and "_token_estimate" not in path.name
        and "status_fixed" not in str(path)
    ]
    if not valid:
        return None
    return sorted(valid, key=lambda p: p.name)[-1]


def discover_single_cfg(root: Path) -> list[RawRun]:
    base = root / "Experiment/code/NetConfigQA2_2/result_final"
    runs: list[RawRun] = []
    for model_dir in sorted(path for path in base.iterdir() if path.is_dir()):
        for lab in LABS:
            lab_dir = model_dir / lab
            raw = latest_json(list(lab_dir.glob("results_raw_vllm_en_*.json")))
            if raw:
                runs.append(
                    RawRun(
                        family="cfg_only",
                        method="singleLLM_cfg",
                        model=model_dir.name,
                        lab=lab,
                        raw_path=raw,
                    )
                )
    return runs


def discover_single_mcp(root: Path) -> list[RawRun]:
    base = root / "NetAlly/result2/singleLLM_mcp/mistral3-8b"
    lab_dirs = {
        "LabA": base / "LabA",
        "LabB": base / "LabB/current",
        "LabC": base / "LabC",
        "LabD": base / "LabD",
    }
    runs: list[RawRun] = []
    for lab, lab_dir in lab_dirs.items():
        raw = latest_json(list(lab_dir.glob("netally_eval_direct_singleLLM_mcp_*.json")))
        if raw:
            runs.append(
                RawRun(
                    family="tool_augmented",
                    method="singleLLM_mcp",
                    model=DEFAULT_MCP_MODEL,
                    lab=lab,
                    raw_path=raw,
                )
            )
    return runs


def discover_mas_cfg(root: Path) -> list[RawRun]:
    base = root / "NetAlly/result2/masLLM_cfg/mistral3_8b"
    runs: list[RawRun] = []
    for lab in LABS:
        lab_dir = base / f"lab{lab[-1]}"
        raw = latest_json(list(lab_dir.glob("results_raw_mistral3_8b_*.json")))
        if raw:
            runs.append(
                RawRun(
                    family="cfg_only",
                    method="masLLM_cfg",
                    model=DEFAULT_MCP_MODEL,
                    lab=lab,
                    raw_path=raw,
                )
            )
    return runs


def discover_mas_mcp(root: Path) -> list[RawRun]:
    base = root / "NetAlly/result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp"
    runs: list[RawRun] = []
    for lab in LABS:
        lab_dir = base / lab
        raw = latest_json(list(lab_dir.glob("*.json")))
        if raw:
            runs.append(
                RawRun(
                    family="tool_augmented",
                    method="masLLM_mcp",
                    model=DEFAULT_MCP_MODEL,
                    lab=lab,
                    raw_path=raw,
                )
            )
    return runs


def discover_runs(root: Path) -> list[RawRun]:
    runs = []
    runs.extend(discover_single_cfg(root))
    runs.extend(discover_single_mcp(root))
    runs.extend(discover_mas_cfg(root))
    runs.extend(discover_mas_mcp(root))
    return sorted(runs, key=lambda r: (r.method, r.model, r.lab))


def load_rows(raw_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    with raw_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        rows = payload.get("results", [])
        meta = payload.get("meta", {})
    elif isinstance(payload, list):
        rows = payload
        meta = {}
    else:
        raise ValueError(f"Unsupported JSON structure: {raw_path}")
    return rows, meta if isinstance(meta, dict) else {}


def resolve_dataset_path(root: Path, raw_path: Path, meta: dict[str, Any]) -> Path | None:
    dataset_path = meta.get("dataset_path")
    if not dataset_path:
        return None
    candidate = Path(str(dataset_path))
    candidates = []
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        candidates.extend(
            [
                root / candidate,
                root / "NetAlly" / candidate,
                raw_path.parent / candidate,
            ]
        )
    for path in candidates:
        resolved = path.resolve()
        if resolved.exists():
            return resolved
    return None


def load_dataset_rows(root: Path, raw_path: Path, meta: dict[str, Any]) -> dict[str, dict[str, Any]]:
    dataset_path = resolve_dataset_path(root, raw_path, meta)
    if dataset_path is None:
        return {}
    with dataset_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        rows = payload.get("results", payload.get("questions", payload.get("data", [])))
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []

    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("question_id", "id", "id_v2"):
            value = row.get(key)
            if value:
                indexed[str(value)] = row
    return indexed


def pct(value: float | None, digits: int = 2) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.{digits}f}%"


def avg(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def infer_prediction(row: dict[str, Any]) -> Any:
    return row.get(
        "pred",
        row.get("raw_pred", row.get("debate2_answer", row.get("candidate_answer", ""))),
    )


def infer_raw_prediction(row: dict[str, Any]) -> Any:
    return row.get(
        "raw_pred",
        row.get("debate2_answer", row.get("candidate_answer", row.get("pred", ""))),
    )


def score_run(raw: RawRun, mode: str, analyzer: Any, root: Path) -> dict[str, Any]:
    rows, meta = load_rows(raw.raw_path)
    dataset_rows = load_dataset_rows(root, raw.raw_path, meta)
    rows = [
        row
        for row in rows
        if str(row.get("level", "L1")).strip().upper() != "L6"
    ]

    scorer = analyzer.NetConfigQAScorer()
    trad_calc = analyzer.TraditionalMetricsCalculator()

    scored_rows: list[dict[str, Any]] = []
    grouped_by_type: dict[str, list[float]] = defaultdict(list)
    grouped_by_level: dict[str, list[float]] = defaultdict(list)
    grouped_by_status: dict[str, list[float]] = defaultdict(list)
    grouped_by_category: dict[str, list[float]] = defaultdict(list)
    trad_values: dict[str, list[float]] = defaultdict(list)
    trad_by_type: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

    negative_total = 0
    semantic_negative_correct = 0
    explicit_abstention_correct = 0
    blank_negative_predictions = 0
    status_overlay_count = 0
    errors: list[dict[str, Any]] = []

    for idx, row in enumerate(rows):
        question_id = str(row.get("question_id", row.get("id", idx)))
        dataset_row = dataset_rows.get(question_id)
        raw_answer_type = row.get("answer_type", row.get("type", "text"))
        if dataset_row and not raw_answer_type:
            raw_answer_type = dataset_row.get("answer_type", "text")
        answer_type = analyzer.canonical_answer_type(raw_answer_type)
        report_type = analyzer.display_answer_type(raw_answer_type)
        level = str(row.get("level", "L1")).strip().upper()
        category = str(row.get("category", "General"))
        status = str(row.get("answer_status", row.get("status", "OK"))).strip().upper()
        if dataset_row and dataset_row.get("answer_status"):
            dataset_status = str(dataset_row.get("answer_status")).strip().upper()
            if dataset_status != status:
                status_overlay_count += 1
            status = dataset_status
        gold_raw = str(row.get("gold", row.get("gold_answer", "")))

        clean_pred = scorer.clean_prediction(str(infer_prediction(row)), answer_type)
        clean_gold = scorer.clean_gold(gold_raw, status=status)
        strict_metrics = scorer.score(
            clean_pred,
            gold_raw,
            answer_type,
            status=status,
            question_id=question_id,
        )
        strict_score = float(strict_metrics.get("score", 0.0))

        negative_metrics = None
        if status == "NOT_CONFIGURED":
            negative_metrics = scorer.evaluate_negative_prediction(clean_pred, gold_raw, answer_type)
            negative_total += 1
            semantic_negative_correct += int(negative_metrics["semantic_negative_correct"])
            explicit_abstention_correct += int(negative_metrics["explicit_abstention_correct"])
            blank_negative_predictions += int(negative_metrics["blank_prediction"])
            if mode == "relaxed":
                type_aware_score = 1.0 if negative_metrics["semantic_negative_correct"] else 0.0
            else:
                type_aware_score = strict_score
        else:
            type_aware_score = strict_score

        trad_metrics = trad_calc.calculate_all(clean_pred, clean_gold)
        for metric_name, metric_value in trad_metrics.items():
            if metric_value is not None:
                trad_values[metric_name].append(float(metric_value))
                trad_by_type[report_type][metric_name].append(float(metric_value))

        scored = {
            "question_id": question_id,
            "level": level,
            "category": category,
            "status": status,
            "type": report_type,
            "canonical_type": answer_type,
            "gold": gold_raw,
            "gold_cleaned": clean_gold,
            "raw_pred": infer_raw_prediction(row),
            "pred": clean_pred,
            "strict_type_aware_score": strict_score,
            "type_aware_score": type_aware_score,
            "negative_semantic_correct": None
            if negative_metrics is None
            else negative_metrics["semantic_negative_correct"],
            "negative_explicit_abstention": None
            if negative_metrics is None
            else negative_metrics["explicit_abstention_correct"],
            "negative_contract_compliant": None
            if negative_metrics is None
            else negative_metrics["contract_compliant"],
            "negative_blank_prediction": None
            if negative_metrics is None
            else negative_metrics["blank_prediction"],
            "negative_eval_detail": None if negative_metrics is None else negative_metrics["detail"],
            **trad_metrics,
        }
        scored_rows.append(scored)

        grouped_by_type[report_type].append(type_aware_score)
        grouped_by_level[level].append(type_aware_score)
        grouped_by_status[status].append(type_aware_score)
        grouped_by_category[category].append(type_aware_score)

        if type_aware_score < 0.99 and len(errors) < 15:
            errors.append(
                {
                    "question_id": question_id,
                    "level": level,
                    "status": status,
                    "type": report_type,
                    "gold": gold_raw,
                    "pred": clean_pred,
                    "score": type_aware_score,
                }
            )

    total = len(scored_rows)
    accuracy = avg([row["type_aware_score"] for row in scored_rows]) or 0.0
    strict_accuracy = avg([row["strict_type_aware_score"] for row in scored_rows]) or 0.0

    stats = {
        "mode": mode,
        "accuracy": accuracy,
        "strict_accuracy": strict_accuracy,
        "total_samples": total,
        "by_type": {key: avg(vals) for key, vals in sorted(grouped_by_type.items())},
        "by_level": {key: avg(vals) for key, vals in sorted(grouped_by_level.items())},
        "by_status": {key: avg(vals) for key, vals in sorted(grouped_by_status.items())},
        "by_category": {key: avg(vals) for key, vals in sorted(grouped_by_category.items())},
        "traditional_metrics": {key: avg(vals) for key, vals in sorted(trad_values.items())},
        "trad_by_type": {
            key: {metric: avg(values) for metric, values in sorted(metrics.items())}
            for key, metrics in sorted(trad_by_type.items())
        },
        "negative_eval": {
            "total_negative_samples": negative_total,
            "semantic_negative_correct": semantic_negative_correct,
            "explicit_abstention_correct": explicit_abstention_correct,
            "blank_negative_predictions": blank_negative_predictions,
            "semantic_negative_accuracy": semantic_negative_correct / negative_total
            if negative_total
            else None,
            "explicit_abstention_accuracy": explicit_abstention_correct / negative_total
            if negative_total
            else None,
            "contract_compliance": explicit_abstention_correct / semantic_negative_correct
            if semantic_negative_correct
            else None,
        },
    }

    return {
        "family": raw.family,
        "method": raw.method,
        "model": raw.model,
        "lab": raw.lab,
        "mode": mode,
        "raw_path": str(raw.raw_path),
        "meta": meta,
        "stats": stats,
        "status_overlay_count": status_overlay_count,
        "dataset_status_available": bool(dataset_rows),
        "sample_errors": errors,
    }


def safe_cell(value: float | None) -> str:
    return "" if value is None else f"{value * 100:.2f}"


def summary_row(record: dict[str, Any]) -> dict[str, Any]:
    stats = record["stats"]
    levels = stats.get("by_level", {})
    status = stats.get("by_status", {})
    neg = stats.get("negative_eval", {})
    by_type = stats.get("by_type", {})
    return {
        "mode": record["mode"],
        "family": record["family"],
        "method": record["method"],
        "model": record["model"],
        "lab": record["lab"],
        "total": stats.get("total_samples", 0),
        "ta_acc": safe_cell(stats.get("accuracy")),
        "strict_ta_acc": safe_cell(stats.get("strict_accuracy")),
        "l1": safe_cell(levels.get("L1")),
        "l2": safe_cell(levels.get("L2")),
        "l3": safe_cell(levels.get("L3")),
        "l4": safe_cell(levels.get("L4")),
        "l5": safe_cell(levels.get("L5")),
        "ok_acc": safe_cell(status.get("OK")),
        "strict_not_configured": safe_cell(neg.get("explicit_abstention_accuracy")),
        "semantic_not_configured": safe_cell(neg.get("semantic_negative_accuracy")),
        "compliance": safe_cell(neg.get("contract_compliance")),
        "negative_total": neg.get("total_negative_samples", 0),
        "negative_explicit_correct": neg.get("explicit_abstention_correct", 0),
        "negative_semantic_correct": neg.get("semantic_negative_correct", 0),
        "negative_blank": neg.get("blank_negative_predictions", 0),
        **{f"type_{answer_type}": safe_cell(by_type.get(answer_type)) for answer_type in TYPE_COLUMNS},
        "raw_path": record["raw_path"],
    }


def render_scorecard(record: dict[str, Any]) -> str:
    stats = record["stats"]
    neg = stats.get("negative_eval", {})
    lines = [
        "# NetConfigQA Result3 Scorecard",
        "",
        f"- Mode: `{record['mode']}`",
        f"- Method: `{record['method']}`",
        f"- Model: `{record['model']}`",
        f"- Lab: `{record['lab']}`",
        f"- Raw: `{record['raw_path']}`",
        f"- Dataset status overlay: {record.get('status_overlay_count', 0)} rows",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Overall",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Type-Aware Accuracy | {pct(stats.get('accuracy'))} |",
        f"| Strict TA-Acc | {pct(stats.get('strict_accuracy'))} |",
        f"| Total Samples | {stats.get('total_samples', 0)} |",
        "",
        "## Level Breakdown",
        "",
        "| Level | TA-Acc |",
        "|---|---:|",
    ]
    for level in ("L1", "L2", "L3", "L4", "L5"):
        lines.append(f"| {level} | {pct(stats.get('by_level', {}).get(level))} |")

    lines.extend(
        [
            "",
            "## Type Breakdown",
            "",
            "| Type | TA-Acc |",
            "|---|---:|",
        ]
    )
    for answer_type, value in stats.get("by_type", {}).items():
        lines.append(f"| {answer_type} | {pct(value)} |")

    lines.extend(
        [
            "",
            "## Positive vs Negative",
            "",
            "| Slice | Accuracy |",
            "|---|---:|",
            f"| OK | {pct(stats.get('by_status', {}).get('OK'))} |",
            f"| Explicit NOT_CONFIGURED | {pct(neg.get('explicit_abstention_accuracy'))} |",
            f"| Semantic Negative | {pct(neg.get('semantic_negative_accuracy'))} |",
            f"| Contract Compliance | {pct(neg.get('contract_compliance'))} |",
            "",
            "## Sample Errors",
            "",
            "| ID | Level | Status | Type | Gold | Pred | Score |",
            "|---|---|---|---|---|---|---:|",
        ]
    )
    for err in record.get("sample_errors", []):
        gold = str(err["gold"]).replace("|", "\\|")[:80]
        pred = str(err["pred"]).replace("|", "\\|")[:80]
        lines.append(
            f"| {err['question_id']} | {err['level']} | {err['status']} | "
            f"{err['type']} | `{gold}` | `{pred}` | {err['score']:.2f} |"
        )
    return "\n".join(lines) + "\n"


def write_record(result3: Path, record: dict[str, Any]) -> None:
    target_dir = (
        result3
        / "scorecards"
        / record["mode"]
        / record["method"]
        / record["model"]
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    lab = record["lab"]
    summary_path = target_dir / f"{lab}_summary.json"
    scorecard_path = target_dir / f"{lab}_scorecard.md"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    scorecard_path.write_text(render_scorecard(record), encoding="utf-8")


def write_raw_index(result3: Path, runs: list[RawRun], root: Path) -> None:
    lines = [
        "# Result3 Raw Index",
        "",
        "Official raw JSON inputs used to generate `NetAlly/result3` scorecards.",
        "",
        "| Method | Model | Lab | Family | Raw Path |",
        "|---|---|---|---|---|",
    ]
    for run in runs:
        rel = run.raw_path.relative_to(root)
        lines.append(
            f"| {run.method} | {run.model} | {run.lab} | {run.family} | `{rel}` |"
        )
    (result3 / "raw_index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    rows = [summary_row(record) for record in records]
    fieldnames = [
        "mode",
        "family",
        "method",
        "model",
        "lab",
        "total",
        "ta_acc",
        "strict_ta_acc",
        "l1",
        "l2",
        "l3",
        "l4",
        "l5",
        "ok_acc",
        "strict_not_configured",
        "semantic_not_configured",
        "compliance",
        "negative_total",
        "negative_explicit_correct",
        "negative_semantic_correct",
        "negative_blank",
        *[f"type_{answer_type}" for answer_type in TYPE_COLUMNS],
        "raw_path",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def group_average(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[
            (record["mode"], record["family"], record["method"], record["model"])
        ].append(record)

    rows = []
    for (mode, family, method, model), items in sorted(grouped.items()):
        total_samples = sum(item["stats"]["total_samples"] for item in items)
        weighted_acc = (
            sum(item["stats"]["accuracy"] * item["stats"]["total_samples"] for item in items)
            / total_samples
            if total_samples
            else 0.0
        )
        macro_acc = avg([item["stats"]["accuracy"] for item in items]) or 0.0
        rows.append(
            {
                "mode": mode,
                "family": family,
                "method": method,
                "model": model,
                "labs": len(items),
                "total": total_samples,
                "weighted_ta_acc": weighted_acc,
                "macro_ta_acc": macro_acc,
            }
        )
    return rows


def markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


def write_combined_md(path: Path, records: list[dict[str, Any]]) -> None:
    lines = [
        "# Result3 Combined Summary",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Method Averages",
        "",
    ]
    avg_rows = group_average(records)
    lines.extend(
        markdown_table(
            ["Mode", "Method", "Model", "Labs", "Total", "Weighted TA", "Macro TA"],
            [
                [
                    row["mode"],
                    row["method"],
                    row["model"],
                    str(row["labs"]),
                    str(row["total"]),
                    pct(row["weighted_ta_acc"]),
                    pct(row["macro_ta_acc"]),
                ]
                for row in avg_rows
            ],
        )
    )

    for mode in ("strict", "relaxed"):
        mode_records = [record for record in records if record["mode"] == mode]
        lines.extend(["", f"## {mode.title()} Lab Results", ""])
        lines.extend(
            markdown_table(
                [
                    "Method",
                    "Model",
                    "Lab",
                    "Total",
                    "TA",
                    "L1",
                    "L2",
                    "L3",
                    "L4",
                    "L5",
                    "OK",
                    "Strict NOT_CONFIGURED",
                    "Semantic NOT_CONFIGURED",
                ],
                [
                    [
                        row["method"],
                        row["model"],
                        row["lab"],
                        str(row["total"]),
                        row["ta_acc"],
                        row["l1"],
                        row["l2"],
                        row["l3"],
                        row["l4"],
                        row["l5"],
                        row["ok_acc"],
                        row["strict_not_configured"],
                        row["semantic_not_configured"],
                    ]
                    for row in [summary_row(record) for record in mode_records]
                ],
            )
        )

        lines.extend(["", f"## {mode.title()} Type Breakdown", ""])
        lines.extend(
            markdown_table(
                [
                    "Method",
                    "Model",
                    "Lab",
                    "TA",
                    "Map",
                    "Number",
                    "Set",
                    "Text",
                    "Boolean",
                    "Path",
                ],
                [
                    [
                        row["method"],
                        row["model"],
                        row["lab"],
                        row["ta_acc"],
                        row["type_map"],
                        row["type_number"],
                        row["type_set"],
                        row["type_text"],
                        row["type_boolean"],
                        row["type_path"],
                    ]
                    for row in [summary_row(record) for record in mode_records]
                ],
            )
        )

        lines.extend(["", f"## {mode.title()} NOT_CONFIGURED Breakdown", ""])
        lines.extend(
            markdown_table(
                [
                    "Method",
                    "Model",
                    "Lab",
                    "Negative Total",
                    "Strict NOT_CONFIGURED",
                    "Strict Correct",
                    "Semantic NOT_CONFIGURED",
                    "Semantic Correct",
                    "Compliance",
                    "Blank",
                ],
                [
                    [
                        row["method"],
                        row["model"],
                        row["lab"],
                        str(row["negative_total"]),
                        row["strict_not_configured"],
                        str(row["negative_explicit_correct"]),
                        row["semantic_not_configured"],
                        str(row["negative_semantic_correct"]),
                        row["compliance"],
                        str(row["negative_blank"]),
                    ]
                    for row in [summary_row(record) for record in mode_records]
                ],
            )
        )

    strict_by_key = {
        (r["method"], r["model"], r["lab"]): r for r in records if r["mode"] == "strict"
    }
    relaxed_by_key = {
        (r["method"], r["model"], r["lab"]): r for r in records if r["mode"] == "relaxed"
    }
    gap_rows = []
    for key in sorted(strict_by_key):
        if key not in relaxed_by_key:
            continue
        strict_acc = strict_by_key[key]["stats"]["accuracy"]
        relaxed_acc = relaxed_by_key[key]["stats"]["accuracy"]
        gap_rows.append(
            [
                key[0],
                key[1],
                key[2],
                pct(strict_acc),
                pct(relaxed_acc),
                f"{(relaxed_acc - strict_acc) * 100:.2f}",
            ]
        )
    lines.extend(["", "## Strict vs Relaxed Gap", ""])
    lines.extend(
        markdown_table(
            ["Method", "Model", "Lab", "Strict TA", "Relaxed TA", "Gap pp"],
            gap_rows,
        )
    )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_tables(result3: Path, records: list[dict[str, Any]]) -> None:
    tables = result3 / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    write_csv(tables / "combined_summary.csv", records)
    write_csv(tables / "strict_summary.csv", [r for r in records if r["mode"] == "strict"])
    write_csv(tables / "relaxed_summary.csv", [r for r in records if r["mode"] == "relaxed"])
    write_combined_md(tables / "combined_summary.md", records)


def main() -> None:
    default_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Build normalized result3 scorecards")
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    result3 = (args.output_dir or (root / "NetAlly/result3")).resolve()
    analyzer = load_analyzer(root)
    runs = discover_runs(root)

    expected_min = 20 + 12
    if len(runs) < expected_min:
        raise SystemExit(f"Discovered only {len(runs)} raw runs; expected at least {expected_min}")

    print(f"Discovered {len(runs)} raw runs")
    for run in runs:
        print(f"  {run.method:14s} {run.model:14s} {run.lab:4s} {run.raw_path}")

    if args.dry_run:
        return

    result3.mkdir(parents=True, exist_ok=True)
    write_raw_index(result3, runs, root)

    records: list[dict[str, Any]] = []
    for run in runs:
        for mode in ("strict", "relaxed"):
            record = score_run(run, mode, analyzer, root)
            write_record(result3, record)
            records.append(record)
            print(
                f"[OK] {mode:7s} {run.method:14s} {run.model:14s} "
                f"{run.lab}: {record['stats']['accuracy']:.2%}"
            )

    write_tables(result3, records)
    print(f"[DONE] Wrote result3 artifacts to {result3}")


if __name__ == "__main__":
    main()
