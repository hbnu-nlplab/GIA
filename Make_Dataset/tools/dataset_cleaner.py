"""
Dataset Cleaner: auto re-grade and correct QA datasets using AnswerAgent.

Scans simplified_enhanced_dataset.json and network_qa_dataset.csv (also checks tools/ path),
recomputes ground truth and explanation via AnswerAgent.execute_plan, validates outputs,
and writes *_clean.json / *_clean.csv.
"""

from __future__ import annotations
import os
import sys
import json
import csv
from typing import Any, Dict, List


# Ensure we can import from src/
HERE = os.path.abspath(os.path.dirname(__file__))
SRC_PATH = os.path.join(HERE, "src")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from agents.answer_agent import AnswerAgent


def _first_existing(paths: List[str]) -> str | None:
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def load_facts(path: str | None = None) -> Dict[str, Any]:
    """Load parsed facts JSON from common output locations or provided path."""
    if path and os.path.exists(path):
        chosen = path
    else:
        candidates = [
            os.path.join(HERE, "parsed_facts.json"),
            os.path.join(HERE, "output", "network_qa", "parsed_facts.json"),
            os.path.join(HERE, "output", "network_qqa", "parsed_facts.json"),
            os.path.join(HERE, "output", "aa", "parsed_facts.json"),
            os.path.join(HERE, "data", "raw", "XML_Data", "parsed_facts.json"),
        ]
        chosen = _first_existing(candidates)
    if not chosen:
        raise FileNotFoundError("parsed_facts.json not found in default locations; provide --facts path.")
    with open(chosen, "r", encoding="utf-8") as f:
        return json.load(f)


def clean_json(in_path: str, facts: Dict[str, Any]) -> str:
    data = json.load(open(in_path, "r", encoding="utf-8"))
    out: List[Dict[str, Any]] = []
    ag = AnswerAgent(facts)
    for row in data:
        if not isinstance(row, dict):
            continue
        q = row.get("question") or row.get("query") or ""
        if not q:
            continue
        plan = row.get("reasoning_plan") or row.get("plan") or "auto"
        atype = (row.get("answer_type") or "short").lower()
        res = ag.execute_plan(q, plan, answer_type=atype)
        gt = res.get("ground_truth")
        ex = res.get("explanation", "")
        sf = res.get("source_files") or []
        # Drop invalid entries
        if gt in (None, "insufficient_evidence", ""):
            continue
        row.update({
            "ground_truth": gt,
            "explanation": ex,
            "source_files": ",".join(sf) if isinstance(sf, list) else str(sf),
        })
        out.append(row)
    out_path = in_path.replace('.json', '_clean.json')
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return out_path


def clean_csv(in_path: str, facts: Dict[str, Any]) -> str:
    rows = list(csv.DictReader(open(in_path, "r", encoding="utf-8")))
    out_rows: List[Dict[str, Any]] = []
    ag = AnswerAgent(facts)
    for row in rows:
        if not isinstance(row, dict):
            continue
        q = row.get("question") or row.get("query") or ""
        if not q:
            continue
        plan = row.get("reasoning_plan") or row.get("plan") or "auto"
        atype = (row.get("answer_type") or "short").lower()
        res = ag.execute_plan(q, plan, answer_type=atype)
        gt = res.get("ground_truth")
        ex = res.get("explanation", "")
        sf = res.get("source_files") or []
        if gt in (None, "insufficient_evidence", ""):
            continue
        row.update({
            "ground_truth": gt,
            "explanation": ex,
            "source_files": ",".join(sf) if isinstance(sf, list) else str(sf),
        })
        out_rows.append(row)

    if not out_rows:
        out_rows = rows[:0]  # keep header only if none valid

    out_path = in_path.replace('.csv', '_clean.csv')
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        # Use header from first row if present, else union of keys
        fieldnames = list(out_rows[0].keys()) if out_rows else list(rows[0].keys()) if rows else []
        if "ground_truth" not in fieldnames:
            fieldnames.append("ground_truth")
        if "explanation" not in fieldnames:
            fieldnames.append("explanation")
        if "source_files" not in fieldnames:
            fieldnames.append("source_files")
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in out_rows:
            w.writerow({k: r.get(k) for k in fieldnames})
    return out_path


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Auto clean QA datasets using AnswerAgent.")
    ap.add_argument("--facts", default=None, help="Path to parsed_facts.json (optional)")
    ap.add_argument("--json", default=None, help="Path to simplified_enhanced_dataset.json (optional)")
    ap.add_argument("--csv", default=None, help="Path to network_qa_dataset.csv (optional)")
    args = ap.parse_args()

    facts = load_facts(args.facts)

    # Locate datasets
    json_in = args.json or _first_existing([
        os.path.join(HERE, "simplified_enhanced_dataset.json"),
        os.path.join(HERE, "tools", "simplified_enhanced_dataset.json"),
        os.path.join(HERE, "output", "network_qa", "enhanced_dataset.json"),
        os.path.join(HERE, "output", "network_qqa", "enhanced_dataset.json"),
        os.path.join(HERE, "output", "aa", "enhanced_dataset.json"),
    ])
    csv_in = args.csv or _first_existing([
        os.path.join(HERE, "network_qa_dataset.csv"),
        os.path.join(HERE, "tools", "network_qa_dataset.csv"),
        os.path.join(HERE, "dataset_for_evaluation.csv"),
        os.path.join(HERE, "Network-Management-System-main", "dataset", "dataset_for_evaluation_filtered.csv"),
    ])

    if json_in and os.path.exists(json_in):
        out_json = clean_json(json_in, facts)
        print(f"✔ JSON cleaned → {out_json}")
    else:
        print("ℹ No JSON dataset found to clean.")

    if csv_in and os.path.exists(csv_in):
        out_csv = clean_csv(csv_in, facts)
        print(f"✔ CSV cleaned → {out_csv}")
    else:
        print("ℹ No CSV dataset found to clean.")

    print("✔ cleaning done.")


if __name__ == "__main__":
    main()

