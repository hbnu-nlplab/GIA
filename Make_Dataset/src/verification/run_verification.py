#!/usr/bin/env python3
"""Run Independent Parser verification against NetConfigQA dataset.

Usage:
    python Make_Dataset/src/verification/run_verification.py \
      --configs Data/Pnetlab/Research_Institute_Internal_DC/configs/ \
      --dataset Data/Pnetlab/Research_Institute_Internal_DC/Dataset/20260213_155502/...json \
      --output Data/Pnetlab/Research_Institute_Internal_DC/Dataset/verification/method1/
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure project root importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.verification.independent_parser import CfgParser, TopologyFacts
from src.verification.compare import compare_answers, canonical_answer_type


# ── Dataset Loading ─────────────────────────────────────────────────

def load_configs(cfg_dir: Path) -> Dict[str, str]:
    """Load all .cfg files from a directory. Returns {filename: text}."""
    configs = {}
    for f in sorted(cfg_dir.glob("*.cfg")):
        configs[f.name] = f.read_text(encoding="utf-8", errors="replace")
    return configs


def load_dataset(dataset_path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Load dataset (JSON or CSV). Returns (rows, meta)."""
    if dataset_path.suffix.lower() == ".json":
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            rows = payload.get("questions", [])
            meta = payload.get("meta", {})
            return list(rows), meta
        if isinstance(payload, list):
            return payload, {}
        raise ValueError(f"Unsupported JSON structure in {dataset_path}")

    if dataset_path.suffix.lower() == ".csv":
        with dataset_path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f)), {}

    raise ValueError(f"Unsupported file extension: {dataset_path.suffix}")


def parse_evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    """Extract metric name and scope from evidence field."""
    evidence_raw = row.get("evidence")
    if isinstance(evidence_raw, str) and evidence_raw.strip():
        try:
            return json.loads(evidence_raw)
        except Exception:
            pass
    if isinstance(evidence_raw, dict):
        return evidence_raw
    return {}


# ── Verification Runner ────────────────────────────────────────────

def run_verification(
    topo: TopologyFacts,
    rows: List[Dict[str, Any]],
    levels: set[str] = frozenset({"L1", "L2", "L3"}),
) -> List[Dict[str, Any]]:
    """Run independent parser verification on all rows in target levels."""
    results: List[Dict[str, Any]] = []

    for row in rows:
        level = str(row.get("level", "")).upper()
        if level not in levels:
            continue

        evidence = parse_evidence(row)
        metric = evidence.get("metric", "")
        scope = evidence.get("scope", {})
        answer_type = str(row.get("answer_type", "text"))
        dataset_answer = row.get("answer")

        if not metric:
            results.append({
                "id": row.get("id", ""),
                "id_v2": row.get("id_v2", ""),
                "level": level,
                "metric": metric,
                "answer_type": answer_type,
                "status": "SKIP",
                "reason": "no_metric_in_evidence",
                "parser_answer": None,
                "dataset_answer": dataset_answer,
                "match": False,
                "score": 0.0,
                "detail": "",
            })
            continue

        # Compute answer independently
        try:
            _atype, parser_answer = topo.compute_metric(metric, scope)
        except Exception as e:
            results.append({
                "id": row.get("id", ""),
                "id_v2": row.get("id_v2", ""),
                "level": level,
                "metric": metric,
                "answer_type": answer_type,
                "status": "ERROR",
                "reason": f"parser_exception: {e}",
                "parser_answer": None,
                "dataset_answer": dataset_answer,
                "match": False,
                "score": 0.0,
                "detail": str(e),
            })
            continue

        if parser_answer is None:
            results.append({
                "id": row.get("id", ""),
                "id_v2": row.get("id_v2", ""),
                "level": level,
                "metric": metric,
                "answer_type": answer_type,
                "status": "UNSUPPORTED",
                "reason": "metric_not_implemented",
                "parser_answer": None,
                "dataset_answer": dataset_answer,
                "match": False,
                "score": 0.0,
                "detail": "",
            })
            continue

        # Compare
        comparison = compare_answers(parser_answer, dataset_answer, answer_type)
        results.append({
            "id": row.get("id", ""),
            "id_v2": row.get("id_v2", ""),
            "level": level,
            "metric": metric,
            "answer_type": answer_type,
            "status": "MATCH" if comparison["match"] else "MISMATCH",
            "reason": "",
            "parser_answer": _serialize(parser_answer),
            "dataset_answer": _serialize(dataset_answer),
            "match": comparison["match"],
            "score": comparison["score"],
            "detail": comparison.get("detail", ""),
        })

    return results


def _serialize(val: Any) -> str:
    """Serialize a value for CSV output."""
    if isinstance(val, (dict, list, set, tuple)):
        return json.dumps(val, ensure_ascii=False, sort_keys=True)
    return str(val) if val is not None else ""


# ── Report Generation ──────────────────────────────────────────────

def save_csv(results: List[Dict[str, Any]], path: Path) -> None:
    if not results:
        return
    fieldnames = list(results[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def generate_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate verification summary statistics."""
    total = len(results)
    match_count = sum(1 for r in results if r["match"])
    mismatch_count = sum(1 for r in results if r["status"] == "MISMATCH")
    skip_count = sum(1 for r in results if r["status"] == "SKIP")
    error_count = sum(1 for r in results if r["status"] == "ERROR")
    unsupported_count = sum(1 for r in results if r["status"] == "UNSUPPORTED")
    verifiable = total - skip_count - error_count - unsupported_count

    # By level
    level_stats = defaultdict(lambda: {"total": 0, "match": 0, "mismatch": 0})
    for r in results:
        lvl = r["level"]
        level_stats[lvl]["total"] += 1
        if r["match"]:
            level_stats[lvl]["match"] += 1
        elif r["status"] == "MISMATCH":
            level_stats[lvl]["mismatch"] += 1

    # By metric
    metric_stats = defaultdict(lambda: {"total": 0, "match": 0, "mismatch": 0})
    for r in results:
        m = r["metric"]
        metric_stats[m]["total"] += 1
        if r["match"]:
            metric_stats[m]["match"] += 1
        elif r["status"] == "MISMATCH":
            metric_stats[m]["mismatch"] += 1

    # By answer_type
    type_stats = defaultdict(lambda: {"total": 0, "match": 0})
    for r in results:
        at = canonical_answer_type(r["answer_type"])
        type_stats[at]["total"] += 1
        if r["match"]:
            type_stats[at]["match"] += 1

    # Mismatch examples
    mismatches = [r for r in results if r["status"] == "MISMATCH"]

    return {
        "total_rows": total,
        "verifiable": verifiable,
        "match": match_count,
        "mismatch": mismatch_count,
        "skip": skip_count,
        "error": error_count,
        "unsupported": unsupported_count,
        "agreement_rate": match_count / verifiable if verifiable > 0 else 0.0,
        "by_level": dict(level_stats),
        "by_metric": dict(metric_stats),
        "by_answer_type": dict(type_stats),
        "mismatch_examples": mismatches[:30],
    }


def save_summary_json(summary: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def save_mismatch_report(results: List[Dict[str, Any]], path: Path) -> None:
    """Generate a markdown mismatch report."""
    mismatches = [r for r in results if r["status"] == "MISMATCH"]
    lines = [
        "# Independent Parser — Mismatch Report",
        "",
        f"Total mismatches: {len(mismatches)}",
        "",
    ]

    # Group by metric
    by_metric: Dict[str, List[Dict]] = defaultdict(list)
    for r in mismatches:
        by_metric[r["metric"]].append(r)

    for metric, rows in sorted(by_metric.items(), key=lambda x: -len(x[1])):
        lines.append(f"## {metric} ({len(rows)} mismatches)")
        lines.append("")
        lines.append("| ID | Level | Parser Answer | Dataset Answer | Score | Detail |")
        lines.append("|---|---|---|---|---|---|")
        for r in rows[:10]:
            pa = str(r["parser_answer"])[:60]
            da = str(r["dataset_answer"])[:60]
            lines.append(f"| {r['id']} | {r['level']} | `{pa}` | `{da}` | {r['score']:.2f} | {r['detail'][:40]} |")
        if len(rows) > 10:
            lines.append(f"| ... | ... | ... | ... | ... | ({len(rows) - 10} more) |")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def print_summary(summary: Dict[str, Any]) -> None:
    """Print a concise summary to stdout."""
    print("\n" + "=" * 60)
    print("  Independent Parser Verification Summary")
    print("=" * 60)
    print(f"  Total rows verified: {summary['verifiable']} / {summary['total_rows']}")
    print(f"  Agreement rate:      {summary['agreement_rate']:.1%}")
    print(f"  Match:    {summary['match']}")
    print(f"  Mismatch: {summary['mismatch']}")
    print(f"  Skip:     {summary['skip']}")
    print(f"  Error:    {summary['error']}")
    print(f"  Unsupported: {summary['unsupported']}")
    print()
    print("  By Level:")
    for lvl in sorted(summary["by_level"]):
        s = summary["by_level"][lvl]
        rate = s["match"] / s["total"] if s["total"] > 0 else 0
        print(f"    {lvl}: {s['match']}/{s['total']} ({rate:.1%})")
    print()
    print("  By Answer Type:")
    for at in sorted(summary["by_answer_type"]):
        s = summary["by_answer_type"][at]
        rate = s["match"] / s["total"] if s["total"] > 0 else 0
        print(f"    {at}: {s['match']}/{s['total']} ({rate:.1%})")
    print("=" * 60)


# ── Main ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Run Independent Parser verification (Method 1)")
    parser.add_argument("--configs", required=True, help="Directory containing .cfg files")
    parser.add_argument("--dataset", required=True, help="Dataset path (.json or .csv)")
    parser.add_argument("--output", default=None, help="Output directory for results")
    args = parser.parse_args()

    cfg_dir = Path(args.configs).resolve()
    dataset_path = Path(args.dataset).resolve()
    output_dir = Path(args.output).resolve() if args.output else dataset_path.parent / "verification" / "method1_independent_parser"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/4] Loading configs from {cfg_dir} ...")
    configs = load_configs(cfg_dir)
    print(f"       Found {len(configs)} config files")

    print("[2/4] Parsing configs with CfgParser ...")
    t0 = time.time()
    device_facts: Dict[str, Dict[str, Any]] = {}
    for filename, text in configs.items():
        p = CfgParser(text, filename)
        facts = p.parse()
        hostname = facts["system"]["hostname"]
        device_facts[hostname] = facts
    topo = TopologyFacts(device_facts)
    print(f"       Parsed {len(device_facts)} devices in {time.time() - t0:.2f}s")
    print(f"       Hostnames: {sorted(device_facts.keys())}")

    # Save parser facts for debugging
    facts_out = output_dir / "independent_parser_facts.json"
    # Clean internal flags before saving
    clean_facts = {}
    for hostname, facts in device_facts.items():
        clean = json.loads(json.dumps(facts, default=str))
        # Remove internal flags from interfaces
        for iface in clean.get("interfaces", []):
            for k in list(iface.keys()):
                if k.startswith("_"):
                    del iface[k]
        clean_facts[hostname] = clean
    facts_out.write_text(json.dumps({"devices": clean_facts}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"       Saved parser facts → {facts_out.name}")

    print(f"[3/4] Loading dataset from {dataset_path.name} ...")
    rows, meta = load_dataset(dataset_path)
    l1l3_count = sum(1 for r in rows if str(r.get("level", "")).upper() in ("L1", "L2", "L3"))
    print(f"       Total rows: {len(rows)}, L1-L3: {l1l3_count}")

    print("[4/4] Running verification ...")
    t0 = time.time()
    results = run_verification(topo, rows)
    elapsed = time.time() - t0
    print(f"       Verified {len(results)} rows in {elapsed:.2f}s")

    # Save results
    csv_path = output_dir / "independent_parser_results.csv"
    save_csv(results, csv_path)

    summary = generate_summary(results)
    summary_path = output_dir / "independent_parser_summary.json"
    save_summary_json(summary, summary_path)

    mismatch_path = output_dir / "independent_parser_mismatch.md"
    save_mismatch_report(results, mismatch_path)

    print(f"\n[OK] Results saved to {output_dir}/")
    print(f"     - {csv_path.name}")
    print(f"     - {summary_path.name}")
    print(f"     - {mismatch_path.name}")

    print_summary(summary)

    # Exit code
    if summary["agreement_rate"] < 0.90:
        print(f"\n[WARN] Agreement rate {summary['agreement_rate']:.1%} is below 90% threshold")
        sys.exit(1)
    print(f"\n[OK] Agreement rate {summary['agreement_rate']:.1%} meets threshold")


if __name__ == "__main__":
    main()
