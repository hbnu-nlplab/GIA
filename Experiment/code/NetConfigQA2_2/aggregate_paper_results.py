#!/usr/bin/env python3
"""Aggregate NetConfigQA results across models and labs for paper-ready tables."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from analyze_results import analyze_results


TIMESTAMP_RE = re.compile(r"(\d{8}_\d{6})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate NetConfigQA model results across labs into paper-ready tables."
    )
    parser.add_argument(
        "--results-dir",
        default=str(Path(__file__).resolve().parent / "results_2"),
        help="Root directory containing model/Lab*/results_*.json files.",
    )
    parser.add_argument(
        "--labs",
        nargs="+",
        default=["LabA", "LabB", "LabC", "LabD"],
        help="Lab folders to aggregate (default: LabA LabB LabC LabD).",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=None,
        help="Optional subset of model folder names to include.",
    )
    parser.add_argument(
        "--output-md",
        default=None,
        help="Markdown output path. Defaults under results-dir.",
    )
    parser.add_argument(
        "--output-csv",
        default=None,
        help="Long-form CSV output path. Defaults under results-dir.",
    )
    parser.add_argument(
        "--output-rank-csv",
        default=None,
        help="Ranking CSV output path. Defaults under results-dir.",
    )
    parser.add_argument(
        "--include-levels",
        nargs="+",
        default=None,
        help="Levels to include when auto-analyzing raw results.",
    )
    parser.add_argument(
        "--exclude-levels",
        nargs="+",
        default=["L6"],
        help="Levels to exclude when auto-analyzing raw results.",
    )
    parser.add_argument(
        "--reanalyze",
        action="store_true",
        help="Force re-analysis from the latest raw result even if analyzed JSON already exists.",
    )
    parser.add_argument(
        "--language",
        choices=["all", "en", "ko"],
        default="all",
        help="Filter artifacts by language tag in filename (default: all).",
    )
    parser.add_argument(
        "--decoding-mode",
        choices=["all", "legacy", "strict"],
        default="all",
        help="Filter artifacts by meta.decoding_mode (default: all).",
    )
    return parser.parse_args()


def extract_timestamp(path: Path) -> str:
    match = TIMESTAMP_RE.search(path.name)
    return match.group(1) if match else ""


def timestamp_key(path: Path) -> Tuple[str, float]:
    return (extract_timestamp(path), path.stat().st_mtime)


def fmt_pct(value: Optional[float]) -> str:
    return "미보고" if value is None else f"{value * 100:.2f}%"


def fmt_num(value: Optional[float]) -> str:
    return "미보고" if value is None else f"{value:.2f}"


def mean(values: Iterable[Optional[float]]) -> Optional[float]:
    cleaned = [v for v in values if v is not None]
    if not cleaned:
        return None
    return sum(cleaned) / len(cleaned)


def discover_models(results_dir: Path, requested_models: Optional[Sequence[str]]) -> List[Path]:
    model_dirs = []
    requested = set(requested_models) if requested_models else None
    for path in sorted(results_dir.iterdir()):
        if not path.is_dir():
            continue
        if requested and path.name not in requested:
            continue
        if any(child.is_dir() and child.name.startswith("Lab") for child in path.iterdir()):
            model_dirs.append(path)
    return model_dirs


def matches_language(path: Path, language: str) -> bool:
    if language == "all":
        return True
    return f"_{language}_" in path.name


def read_meta_quick(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    meta = payload.get("meta")
    return meta if isinstance(meta, dict) else {}


def matches_decoding_mode(path: Path, decoding_mode: str) -> bool:
    if decoding_mode == "all":
        return True
    meta = read_meta_quick(path)
    return str(meta.get("decoding_mode", "")).strip().lower() == decoding_mode


def list_analyzed_files(
    lab_dir: Path,
    language: str = "all",
    decoding_mode: str = "all",
) -> List[Path]:
    files = []
    for path in lab_dir.glob("results_analyzed_*.json"):
        if path.name.endswith("_errors.json"):
            continue
        if not matches_language(path, language):
            continue
        if not matches_decoding_mode(path, decoding_mode):
            continue
        files.append(path)
    return sorted(files, key=timestamp_key)


def list_raw_files(
    lab_dir: Path,
    language: str = "all",
    decoding_mode: str = "all",
) -> List[Path]:
    return sorted(
        [
            p
            for p in lab_dir.glob("results_raw_*.json")
            if matches_language(p, language) and matches_decoding_mode(p, decoding_mode)
        ],
        key=timestamp_key,
    )


def analyzed_path_for_raw(raw_path: Path) -> Path:
    return raw_path.with_name(raw_path.name.replace("results_raw_", "results_analyzed_"))


def choose_artifact(
    lab_dir: Path,
    reanalyze: bool,
    language: str = "all",
    decoding_mode: str = "all",
) -> Tuple[Optional[Path], Optional[Path], str]:
    analyzed_files = list_analyzed_files(lab_dir, language=language, decoding_mode=decoding_mode)
    raw_files = list_raw_files(lab_dir, language=language, decoding_mode=decoding_mode)
    latest_analyzed = analyzed_files[-1] if analyzed_files else None
    latest_raw = raw_files[-1] if raw_files else None

    if reanalyze and latest_raw:
        return latest_raw, analyzed_path_for_raw(latest_raw), "raw"

    if latest_raw:
        matched_analyzed = analyzed_path_for_raw(latest_raw)
        if matched_analyzed.exists():
            return matched_analyzed, matched_analyzed, "analyzed"
        return latest_raw, matched_analyzed, "raw"

    if latest_analyzed:
        return latest_analyzed, latest_analyzed, "analyzed"

    return None, None, "missing"


def load_analyzed(path: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["stats"], payload["meta"]


def ensure_analyzed(
    selected_path: Path,
    kind: str,
    include_levels: Optional[Sequence[str]],
    exclude_levels: Optional[Sequence[str]],
) -> Tuple[Dict[str, Any], Dict[str, Any], Path]:
    if kind == "analyzed":
        stats, meta = load_analyzed(selected_path)
        return stats, meta, selected_path

    stats, _, meta = analyze_results(
        str(selected_path),
        verbose=False,
        include_levels=include_levels,
        exclude_levels=exclude_levels,
    )
    analyzed_path = analyzed_path_for_raw(selected_path)
    return stats, meta, analyzed_path


def safe_get(dct: Dict[str, Any], *keys: str) -> Optional[float]:
    current: Any = dct
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if current is None:
        return None
    return float(current)


def build_record(
    model: str,
    lab: str,
    stats: Dict[str, Any],
    meta: Dict[str, Any],
    source_path: Path,
    analyzed_path: Path,
) -> Dict[str, Any]:
    trad = stats.get("traditional_metrics", {})
    negative_eval = stats.get("negative_eval", {})
    return {
        "model": model,
        "lab": lab,
        "lab_label": meta.get("lab", lab),
        "samples": meta.get("total_samples", stats.get("total_samples")),
        "type_aware_accuracy": safe_get(stats, "accuracy"),
        "exact_match": safe_get(trad, "exact_match"),
        "token_f1": safe_get(trad, "token_f1"),
        "bleu": safe_get(trad, "bleu"),
        "bertscore_f1": safe_get(trad, "bertscore_f1"),
        "rouge1": safe_get(trad, "rouge1"),
        "rouge2": safe_get(trad, "rouge2"),
        "rougeL": safe_get(trad, "rougeL"),
        "L1": safe_get(stats, "by_level", "L1"),
        "L2": safe_get(stats, "by_level", "L2"),
        "L3": safe_get(stats, "by_level", "L3"),
        "L4": safe_get(stats, "by_level", "L4"),
        "L5": safe_get(stats, "by_level", "L5"),
        "map": safe_get(stats, "by_type", "map"),
        "numeric": safe_get(stats, "by_type", "numeric"),
        "number": safe_get(stats, "by_type", "number"),
        "set": safe_get(stats, "by_type", "set"),
        "text": safe_get(stats, "by_type", "text"),
        "ok_accuracy": safe_get(stats, "by_status", "OK"),
        "strict_negative_accuracy": safe_get(negative_eval, "explicit_abstention_accuracy"),
        "semantic_negative_accuracy": safe_get(negative_eval, "semantic_negative_accuracy"),
        "contract_compliance": safe_get(negative_eval, "contract_compliance"),
        "negative_gap": safe_get(negative_eval, "semantic_vs_explicit_gap"),
        "duration_sec": meta.get("duration_sec"),
        "throughput": meta.get("throughput"),
        "language": meta.get("language"),
        "decoding_mode": meta.get("decoding_mode"),
        "source_path": str(source_path),
        "analyzed_path": str(analyzed_path),
    }


def compute_ranks(records: List[Dict[str, Any]], labs: Sequence[str]) -> Dict[str, Dict[str, int]]:
    ranks: Dict[str, Dict[str, int]] = defaultdict(dict)
    for lab in labs:
        lab_records = [r for r in records if r["lab"] == lab and r["type_aware_accuracy"] is not None]
        sorted_records = sorted(
            lab_records,
            key=lambda r: (r["type_aware_accuracy"], r["token_f1"] or -1.0, r["exact_match"] or -1.0),
            reverse=True,
        )
        prev_score: Optional[Tuple[Optional[float], Optional[float], Optional[float]]] = None
        prev_rank = 0
        for idx, record in enumerate(sorted_records, start=1):
            score = (
                record["type_aware_accuracy"],
                record["token_f1"],
                record["exact_match"],
            )
            if score != prev_score:
                prev_rank = idx
                prev_score = score
            ranks[record["model"]][lab] = prev_rank
    return ranks


def aggregate_model_rows(
    records: List[Dict[str, Any]],
    labs: Sequence[str],
    ranks: Dict[str, Dict[str, int]],
) -> List[Dict[str, Any]]:
    by_model: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_model[record["model"]].append(record)

    rows = []
    for model, model_records in by_model.items():
        record_by_lab = {record["lab"]: record for record in model_records}
        avg_rank = mean(ranks.get(model, {}).get(lab) for lab in labs)
        row = {
            "model": model,
            "labs_covered": sum(1 for lab in labs if lab in record_by_lab),
            "avg_type_aware_accuracy": mean(record_by_lab.get(lab, {}).get("type_aware_accuracy") for lab in labs),
            "avg_exact_match": mean(record_by_lab.get(lab, {}).get("exact_match") for lab in labs),
            "avg_token_f1": mean(record_by_lab.get(lab, {}).get("token_f1") for lab in labs),
            "avg_bleu": mean(record_by_lab.get(lab, {}).get("bleu") for lab in labs),
            "avg_bertscore_f1": mean(record_by_lab.get(lab, {}).get("bertscore_f1") for lab in labs),
            "avg_rougeL": mean(record_by_lab.get(lab, {}).get("rougeL") for lab in labs),
            "avg_L4": mean(record_by_lab.get(lab, {}).get("L4") for lab in labs),
            "avg_L5": mean(record_by_lab.get(lab, {}).get("L5") for lab in labs),
            "avg_ok_accuracy": mean(record_by_lab.get(lab, {}).get("ok_accuracy") for lab in labs),
            "avg_strict_negative_accuracy": mean(record_by_lab.get(lab, {}).get("strict_negative_accuracy") for lab in labs),
            "avg_semantic_negative_accuracy": mean(record_by_lab.get(lab, {}).get("semantic_negative_accuracy") for lab in labs),
            "avg_contract_compliance": mean(record_by_lab.get(lab, {}).get("contract_compliance") for lab in labs),
            "avg_negative_gap": mean(record_by_lab.get(lab, {}).get("negative_gap") for lab in labs),
            "avg_rank": avg_rank,
        }
        for lab in labs:
            row[f"{lab}_ta"] = record_by_lab.get(lab, {}).get("type_aware_accuracy")
            row[f"{lab}_rank"] = ranks.get(model, {}).get(lab)
            row[f"{lab}_strict_nc"] = record_by_lab.get(lab, {}).get("strict_negative_accuracy")
            row[f"{lab}_semantic_nc"] = record_by_lab.get(lab, {}).get("semantic_negative_accuracy")
            row[f"{lab}_compliance"] = record_by_lab.get(lab, {}).get("contract_compliance")
        rows.append(row)

    rows.sort(
        key=lambda row: (
            row["avg_type_aware_accuracy"] is None,
            -(row["avg_type_aware_accuracy"] or -1.0),
            row["avg_rank"] or 999.0,
        )
    )
    return rows


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    header_line = "| " + " | ".join(headers) + " |"
    sep_line = "| " + " | ".join([":---"] + [":---:" for _ in headers[1:]]) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header_line, sep_line] + body)


def generate_markdown(
    model_rows: List[Dict[str, Any]],
    records: List[Dict[str, Any]],
    labs: Sequence[str],
    missing: List[Tuple[str, str]],
) -> str:
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = ["# NetConfigQA 전체 결과 요약", "", f"> 생성 시각: {generated}", ""]
    lines.append("> 읽는 법")
    lines.append("> - 모든 비율 값은 % 단위입니다.")
    lines.append("> - `TA-Acc`는 이 벤치마크의 핵심 점수입니다.")
    lines.append("> - `미보고`는 해당 모델-랩 조합의 실험 결과가 없다는 뜻입니다.")
    lines.append("")

    total_labs = len(labs)
    full_rows = [row for row in model_rows if row["labs_covered"] == total_labs]
    partial_rows = [row for row in model_rows if row["labs_covered"] < total_labs]

    all_models = sorted({record["model"] for record in records})
    common_labs = [
        lab
        for lab in labs
        if all(any(record["model"] == model and record["lab"] == lab for record in records) for model in all_models)
    ]
    common_ranks = compute_ranks(records, common_labs) if common_labs else {}
    common_rows = aggregate_model_rows(records, common_labs, common_ranks) if common_labs else []

    lines.append("## 1. 한눈에 보는 결론")
    lines.append("")
    if full_rows:
        best_full = full_rows[0]
        lines.append(
            f"- 4개 랩을 모두 끝낸 모델만 놓고 보면, 전체 1위는 `{best_full['model']}`이고 평균 TA-Acc는 {fmt_pct(best_full['avg_type_aware_accuracy'])}입니다."
        )
    if partial_rows:
        partial_desc = ", ".join(
            f"`{row['model']}` ({row['labs_covered']}/{total_labs}개 랩만 완료)"
            for row in partial_rows
        )
        lines.append(
            f"- 다음 모델은 일부 랩만 결과가 있어서 전체 순위와 따로 봐야 합니다: {partial_desc}."
        )
    if common_labs and len(common_labs) < total_labs:
        lines.append(
            f"- 모든 모델에 결과가 있는 공통 랩은 `{', '.join(common_labs)}`입니다. 일부 랩이 비어 있는 모델은 이 공통 랩 기준 표로 비교하는 것이 더 공정합니다."
        )
    if missing:
        lines.append(
            "- 특히 `Qwen3-8B / LabD`처럼 어려운 랩이 빠지면 평균 점수가 실제보다 좋아 보일 수 있습니다. 그래서 이런 모델은 메인 종합 순위에 바로 넣지 않는 편이 안전합니다."
        )
    lines.append("")

    full_headers = [
        "순위",
        "모델",
        "완료 랩 수",
        "평균 TA-Acc",
        "평균 순위",
        "평균 EM",
        "평균 Token F1",
        "평균 ROUGE-L",
        "평균 BLEU",
        "평균 BERTScore",
        "평균 L4",
        "평균 L5",
    ]
    full_table_rows = []
    for idx, row in enumerate(full_rows, start=1):
        full_table_rows.append(
            [
                str(idx),
                row["model"],
                f"{row['labs_covered']}/{total_labs}",
                fmt_pct(row["avg_type_aware_accuracy"]),
                fmt_num(row["avg_rank"]),
                fmt_pct(row["avg_exact_match"]),
                fmt_pct(row["avg_token_f1"]),
                fmt_pct(row["avg_rougeL"]),
                fmt_pct(row["avg_bleu"]),
                fmt_pct(row["avg_bertscore_f1"]),
                fmt_pct(row["avg_L4"]),
                fmt_pct(row["avg_L5"]),
            ]
        )
    lines.extend(["## 2. 전체 랩을 모두 끝낸 모델 순위", ""])
    if full_table_rows:
        lines.append(markdown_table(full_headers, full_table_rows))
    else:
        lines.append("4개 랩을 모두 끝낸 모델이 없습니다.")
    lines.append("")

    partial_headers = [
        "모델",
        "완료한 랩 수",
        "완료한 랩 기준 평균 TA-Acc",
        "완료한 랩 기준 평균 순위",
        "비고",
    ]
    partial_table_rows = []
    for row in partial_rows:
        missing_labs = [lab for lab in labs if row.get(f"{lab}_ta") is None]
        partial_table_rows.append(
            [
                row["model"],
                f"{row['labs_covered']}/{total_labs}",
                fmt_pct(row["avg_type_aware_accuracy"]),
                fmt_num(row["avg_rank"]),
                f"전체 순위에서는 제외, 빠진 랩: {', '.join(missing_labs) if missing_labs else '없음'}",
            ]
        )
    lines.extend(["## 3. 일부 랩만 완료한 모델", ""])
    if partial_table_rows:
        lines.append(markdown_table(partial_headers, partial_table_rows))
    else:
        lines.append("일부 랩만 완료한 모델은 없습니다.")
    lines.append("")

    if common_rows:
        common_headers = [
            "순위",
            "모델",
            "공통 랩 수",
            "공통 랩 평균 TA-Acc",
            "공통 랩 평균 순위",
            "공통 랩 평균 EM",
            "공통 랩 평균 Token F1",
        ]
        common_table_rows = []
        for idx, row in enumerate(common_rows, start=1):
            common_table_rows.append(
                [
                    str(idx),
                    row["model"],
                    f"{row['labs_covered']}/{len(common_labs)}",
                    fmt_pct(row["avg_type_aware_accuracy"]),
                    fmt_num(row["avg_rank"]),
                    fmt_pct(row["avg_exact_match"]),
                    fmt_pct(row["avg_token_f1"]),
                ]
            )
        lines.extend([f"## 4. 모든 모델이 공통으로 완료한 랩만 따로 비교 ({', '.join(common_labs)})", "", markdown_table(common_headers, common_table_rows), ""])

    matrix_headers = ["모델", *labs, "평균"]
    matrix_rows = []
    for row in model_rows:
        matrix_rows.append(
            [
                row["model"],
                *[fmt_pct(row.get(f"{lab}_ta")) for lab in labs],
                fmt_pct(row["avg_type_aware_accuracy"]),
            ]
        )
    lines.extend(["## 5. 랩별 핵심 점수(TA-Acc)", "", markdown_table(matrix_headers, matrix_rows), ""])

    best_by_lab_headers = ["랩", "최고 모델", "TA-Acc", "EM", "Token F1", "ROUGE-L"]
    best_by_lab_rows = []
    for lab in labs:
        lab_records = [r for r in records if r["lab"] == lab and r["type_aware_accuracy"] is not None]
        if not lab_records:
            best_by_lab_rows.append([lab, "미보고", "미보고", "미보고", "미보고", "미보고"])
            continue
        best = sorted(
            lab_records,
            key=lambda r: (r["type_aware_accuracy"], r["token_f1"] or -1.0, r["exact_match"] or -1.0),
            reverse=True,
        )[0]
        best_by_lab_rows.append(
            [
                lab,
                best["model"],
                fmt_pct(best["type_aware_accuracy"]),
                fmt_pct(best["exact_match"]),
                fmt_pct(best["token_f1"]),
                fmt_pct(best["rougeL"]),
            ]
        )
    lines.extend(["## 6. 각 랩에서 가장 잘한 모델", "", markdown_table(best_by_lab_headers, best_by_lab_rows), ""])

    negative_headers = [
        "모델",
        "보고 랩 수",
        "평균 OK",
        "평균 Explicit NC",
        "평균 Semantic NC",
        "평균 Compliance",
        "평균 Gap",
    ]
    negative_rows = []
    negative_sorted = sorted(
        model_rows,
        key=lambda row: (
            row["avg_strict_negative_accuracy"] is None,
            -(row["avg_strict_negative_accuracy"] or -1.0),
            -(row["avg_semantic_negative_accuracy"] or -1.0),
            -(row["avg_contract_compliance"] or -1.0),
        ),
    )
    for row in negative_sorted:
        negative_rows.append(
            [
                row["model"],
                f"{row['labs_covered']}/{total_labs}",
                fmt_pct(row["avg_ok_accuracy"]),
                fmt_pct(row["avg_strict_negative_accuracy"]),
                fmt_pct(row["avg_semantic_negative_accuracy"]),
                fmt_pct(row["avg_contract_compliance"]),
                fmt_pct(row["avg_negative_gap"]),
            ]
        )
    lines.extend(["## 7. 설정이 없을 때 제대로 '없음'이라고 답했는지", "", markdown_table(negative_headers, negative_rows), ""])
    lines.append(
        "> `Explicit NC`: 모델이 정답을 정확히 `NOT_CONFIGURED`라고 쓴 비율"
    )
    lines.append(
        "> `Semantic NC`: 표현은 달라도 의미상 '설정이 없음'을 맞힌 비율"
    )
    lines.append(
        "> `Compliance`: 의미상 맞춘 답 중에서, 실제로 `NOT_CONFIGURED` 규약까지 지킨 비율"
    )
    lines.append("")

    if missing:
        lines.append("## 8. 빠진 결과는 어떻게 해석해야 하나?")
        lines.append("")
        for model, lab in missing:
            lines.append(f"- `{model} / {lab}`: 결과가 없어서 `미보고`로 표시했습니다.")
        lines.append("- 결과가 빠진 모델은 전체 순위에 바로 넣지 않는 것이 좋습니다.")
        lines.append("- 대신 모든 모델이 공통으로 완료한 랩만 따로 모아 비교하면 더 공정합니다.")
        lines.append("- 특히 어려운 랩이 빠진 경우 평균 점수는 실제보다 높게 보일 수 있습니다.")
        lines.append("")

    lines.append("---")
    lines.append("*aggregate_paper_results.py 로 생성됨*")
    return "\n".join(lines)


def write_long_csv(path: Path, records: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "model",
        "lab",
        "lab_label",
        "samples",
        "type_aware_accuracy",
        "exact_match",
        "token_f1",
        "bleu",
        "bertscore_f1",
        "rouge1",
        "rouge2",
        "rougeL",
        "L1",
        "L2",
        "L3",
        "L4",
        "L5",
        "map",
        "numeric",
        "number",
        "set",
        "text",
        "ok_accuracy",
        "strict_negative_accuracy",
        "semantic_negative_accuracy",
        "contract_compliance",
        "negative_gap",
        "duration_sec",
        "throughput",
        "language",
        "decoding_mode",
        "source_path",
        "analyzed_path",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for record in sorted(records, key=lambda r: (r["model"], r["lab"])):
            writer.writerow(record)


def write_rank_csv(path: Path, model_rows: List[Dict[str, Any]], labs: Sequence[str]) -> None:
    fieldnames = [
        "model",
        "labs_covered",
        "avg_type_aware_accuracy",
        "avg_rank",
        "avg_exact_match",
        "avg_token_f1",
        "avg_rougeL",
        "avg_bleu",
        "avg_bertscore_f1",
        "avg_L4",
        "avg_L5",
        "avg_ok_accuracy",
        "avg_strict_negative_accuracy",
        "avg_semantic_negative_accuracy",
        "avg_contract_compliance",
        "avg_negative_gap",
        *[f"{lab}_ta" for lab in labs],
        *[f"{lab}_strict_nc" for lab in labs],
        *[f"{lab}_semantic_nc" for lab in labs],
        *[f"{lab}_compliance" for lab in labs],
        *[f"{lab}_rank" for lab in labs],
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for row in model_rows:
            writer.writerow(row)


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir).resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_md = Path(args.output_md) if args.output_md else results_dir / f"paper_summary_{stamp}.md"
    output_csv = Path(args.output_csv) if args.output_csv else results_dir / f"paper_summary_{stamp}.csv"
    output_rank_csv = (
        Path(args.output_rank_csv)
        if args.output_rank_csv
        else results_dir / f"paper_summary_{stamp}_ranking.csv"
    )

    model_dirs = discover_models(results_dir, args.models)
    if not model_dirs:
        raise SystemExit(f"No model directories found in {results_dir}")

    records: List[Dict[str, Any]] = []
    missing: List[Tuple[str, str]] = []

    for model_dir in model_dirs:
        for lab in args.labs:
            lab_dir = model_dir / lab
            if not lab_dir.exists():
                missing.append((model_dir.name, lab))
                continue

            selected_path, analyzed_path, kind = choose_artifact(
                lab_dir,
                args.reanalyze,
                language=args.language,
                decoding_mode=args.decoding_mode,
            )
            if not selected_path or not analyzed_path:
                missing.append((model_dir.name, lab))
                continue

            print(f"[INFO] {model_dir.name} / {lab}: using {kind} -> {selected_path.name}")
            stats, meta, ensured_analyzed_path = ensure_analyzed(
                selected_path,
                kind,
                include_levels=args.include_levels,
                exclude_levels=args.exclude_levels,
            )
            records.append(
                build_record(
                    model=model_dir.name,
                    lab=lab,
                    stats=stats,
                    meta=meta,
                    source_path=selected_path,
                    analyzed_path=ensured_analyzed_path,
                )
            )

    if not records:
        raise SystemExit("No results could be aggregated.")

    ranks = compute_ranks(records, args.labs)
    model_rows = aggregate_model_rows(records, args.labs, ranks)
    markdown = generate_markdown(model_rows, records, args.labs, missing)

    output_md.write_text(markdown, encoding="utf-8")
    write_long_csv(output_csv, records)
    write_rank_csv(output_rank_csv, model_rows, args.labs)

    print("\n" + "=" * 80)
    print(f"[OK] Markdown summary : {output_md}")
    print(f"[OK] Long-form CSV    : {output_csv}")
    print(f"[OK] Ranking CSV      : {output_rank_csv}")
    print("=" * 80)


if __name__ == "__main__":
    main()
