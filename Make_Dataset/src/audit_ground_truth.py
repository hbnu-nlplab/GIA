#!/usr/bin/env python3
"""Audit metric contracts and coverage across generation/verification code."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Set

from ground_truth_contracts import build_metric_contracts, serialize_contracts


def _metric_branches(path: Path) -> Set[str]:
    text = path.read_text(encoding="utf-8")
    matches = set(re.findall(r'if metric == "([^"]+)"', text))
    matches |= set(re.findall(r'elif metric == "([^"]+)"', text))
    return matches


def _coverage_summary(
    policy_metrics: Set[str],
    implemented_metrics: Set[str],
) -> Dict[str, object]:
    missing = sorted(policy_metrics - implemented_metrics)
    extra = sorted(implemented_metrics - policy_metrics)
    return {
        "implemented_count": len(implemented_metrics),
        "missing_count": len(missing),
        "missing_metrics": missing,
        "extra_count": len(extra),
        "extra_metrics": extra,
    }


def _group_missing_by_level(missing_metrics: Iterable[str], contracts: Dict[str, object]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for metric in missing_metrics:
        level = contracts[metric]["level"]
        counts[level] = counts.get(level, 0) + 1
    return counts


def audit(repo_root: Path, out_json: Path | None = None, out_md: Path | None = None) -> Dict[str, object]:
    make_dataset = repo_root / "Make_Dataset"
    policies_path = make_dataset / "policies.json"
    payload = json.loads(policies_path.read_text(encoding="utf-8"))
    metrics_metadata = payload["metrics_metadata"]
    contracts = serialize_contracts(build_metric_contracts(metrics_metadata).values())
    policy_metrics = set(metrics_metadata)

    builder_path = make_dataset / "src" / "core_batfish" / "builder_core.py"
    verifier_path = make_dataset / "src" / "verification" / "independent_parser.py"

    builder_metrics = _metric_branches(builder_path)
    verifier_metrics = _metric_branches(verifier_path)

    builder = _coverage_summary(policy_metrics, builder_metrics)
    verifier = _coverage_summary(policy_metrics, verifier_metrics)
    builder["missing_by_level"] = _group_missing_by_level(builder["missing_metrics"], contracts)
    verifier["missing_by_level"] = _group_missing_by_level(verifier["missing_metrics"], contracts)

    report = {
        "repo_root": str(repo_root),
        "policy_metrics": len(policy_metrics),
        "contracts": contracts,
        "builder_core": builder,
        "independent_parser": verifier,
    }

    if out_json:
        out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    if out_md:
        lines: List[str] = [
            "# Ground Truth Audit",
            "",
            f"- repo_root: `{repo_root}`",
            f"- policy_metrics: {len(policy_metrics)}",
            "",
            "## Coverage",
            "",
            "| component | implemented | missing | extra |",
            "|---|---:|---:|---:|",
            f"| builder_core | {builder['implemented_count']} | {builder['missing_count']} | {builder['extra_count']} |",
            f"| independent_parser | {verifier['implemented_count']} | {verifier['missing_count']} | {verifier['extra_count']} |",
            "",
            "## Missing By Level",
            "",
            "| component | levels |",
            "|---|---|",
            f"| builder_core | {builder['missing_by_level']} |",
            f"| independent_parser | {verifier['missing_by_level']} |",
            "",
            "## High-Risk Missing Metrics",
            "",
            f"- builder_core: {', '.join(builder['missing_metrics'][:20])}",
            f"- independent_parser: {', '.join(verifier['missing_metrics'][:20])}",
            "",
        ]
        out_md.write_text("\n".join(lines), encoding="utf-8")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Make_Dataset ground-truth metric coverage")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="Repository root containing Make_Dataset/",
    )
    parser.add_argument("--out-json", default=None, help="Write JSON report to this path")
    parser.add_argument("--out-md", default=None, help="Write Markdown report to this path")
    args = parser.parse_args()

    out_json = Path(args.out_json).resolve() if args.out_json else None
    out_md = Path(args.out_md).resolve() if args.out_md else None
    report = audit(Path(args.repo_root).resolve(), out_json=out_json, out_md=out_md)
    print(
        f"[OK] audited {report['policy_metrics']} policy metrics "
        f"(builder missing={report['builder_core']['missing_count']}, "
        f"verifier missing={report['independent_parser']['missing_count']})"
    )


if __name__ == "__main__":
    main()
