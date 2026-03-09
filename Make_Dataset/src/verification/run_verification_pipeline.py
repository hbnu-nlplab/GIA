#!/usr/bin/env python3
"""Unified Ground Truth Verification Pipeline.

Runs all 3 verification methods and generates human-readable guides/checklists
for any lab, from a single CLI command.

Usage:
    python Make_Dataset/src/verification/run_verification_pipeline.py \
      --lab-path Data/Pnetlab/Research_Institute_Internal_DC/

    # Skip already-completed methods
    python Make_Dataset/src/verification/run_verification_pipeline.py \
      --lab-path Data/Pnetlab/Lab_B_20nodes/ \
      --skip-method1

Outputs:
    <lab>/Dataset/verification/
    ├── method1_independent_parser/   (자동 검증 결과)
    │   ├── independent_parser_results.csv
    │   ├── independent_parser_summary.json
    │   ├── independent_parser_mismatch.md
    │   └── independent_parser_facts.json
    ├── method2_manual_check/         (사람 검토용 가이드 + 자동 보조 결과)
    │   ├── human_reviewer_guide.md
    │   ├── blank_checklist.csv
    │   ├── manual_sample_selection.md
    │   ├── manual_verification_protocol.md
    │   ├── manual_checklist.csv      (자동 보조)
    │   ├── manual_disagreement_log.md
    │   └── manual_verification_summary.json
    ├── method3_pnetlab/              (PNETLab 실환경 검증 가이드)
    │   ├── pnetlab_verification_guide.md
    │   ├── blank_checklist.csv
    │   └── sample_selection.md
    ├── method4_l45_replay/           (L4-L5 Batfish replay 자동 검증)
    │   ├── l45_replay_results.csv
    │   ├── l45_replay_summary.json
    │   ├── l45_replay_mismatch.md
    │   └── paper_ready_dataset.json
    └── verification_summary.json     (통합 요약)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import textwrap
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure Make_Dataset/ is on sys.path for src.* imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# ════════════════════════════════════════════════════════════════
#  Auto-Discovery
# ════════════════════════════════════════════════════════════════

def discover_lab(lab_path: Path) -> Dict[str, Path]:
    """Auto-discover configs dir and latest dataset JSON for a lab."""
    configs_dir = lab_path / "configs"
    if not configs_dir.is_dir():
        raise FileNotFoundError(f"configs/ 디렉토리를 찾을 수 없습니다: {configs_dir}")

    dataset_dir = lab_path / "Dataset"
    if not dataset_dir.is_dir():
        raise FileNotFoundError(f"Dataset/ 디렉토리를 찾을 수 없습니다: {dataset_dir}")

    # Find the latest dataset_batfish_*.json (search recursively, pick newest)
    candidates: List[Path] = []
    for p in dataset_dir.rglob("*_dataset_batfish_*.json"):
        # Exclude quality reports and verification outputs
        if "quality_report" in p.name or "verification" in str(p):
            continue
        candidates.append(p)

    if not candidates:
        raise FileNotFoundError(f"dataset_batfish_*.json을 찾을 수 없습니다: {dataset_dir}")

    # Sort by modification time, take newest
    dataset_path = max(candidates, key=lambda p: p.stat().st_mtime)

    return {
        "lab_path": lab_path,
        "lab_name": lab_path.name,
        "configs_dir": configs_dir,
        "dataset_path": dataset_path,
        "dataset_dir": dataset_dir,
        "verification_dir": dataset_dir / "verification",
    }


def discover_policies() -> Path:
    """Find policies.json relative to this script."""
    # Make_Dataset/src/verification/ → Make_Dataset/policies.json
    script_dir = Path(__file__).resolve().parent
    policies = script_dir.parents[1] / "policies.json"
    if policies.exists():
        return policies
    raise FileNotFoundError(f"policies.json을 찾을 수 없습니다: {policies}")


# ════════════════════════════════════════════════════════════════
#  Helper: Parse evidence field
# ════════════════════════════════════════════════════════════════

def _parse_evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    ev = row.get("evidence", {})
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            ev = {}
    return ev if isinstance(ev, dict) else {}


def _serialize(val: Any) -> str:
    if isinstance(val, (dict, list, set, tuple)):
        return json.dumps(val, ensure_ascii=False, sort_keys=True)
    return str(val) if val is not None else ""


def _load_existing_unified_summary(verification_dir: Path) -> Dict[str, Any]:
    path = verification_dir / "verification_summary.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("verification_methods", {})
    except Exception:
        return {}


def _safe_load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ════════════════════════════════════════════════════════════════
#  Method 1 Runner (delegates to existing script)
# ════════════════════════════════════════════════════════════════

def run_method1(
    configs_dir: Path,
    dataset_path: Path,
    output_dir: Path,
) -> Dict[str, Any]:
    """Run Method 1 independent parser verification."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Import and run directly (avoids subprocess overhead)
    from src.verification.run_verification import (
        load_configs, load_dataset, run_verification,
        save_csv, generate_summary, save_summary_json,
        save_mismatch_report, print_summary,
    )
    from src.verification.independent_parser import CfgParser, TopologyFacts

    print(f"  [1/4] Loading configs from {configs_dir.name}/ ...")
    configs = load_configs(configs_dir)
    print(f"         Found {len(configs)} config files")

    print("  [2/4] Parsing configs with CfgParser ...")
    t0 = time.time()
    device_facts: Dict[str, Dict[str, Any]] = {}
    for filename, text in configs.items():
        p = CfgParser(text, filename)
        facts = p.parse()
        hostname = facts["system"]["hostname"]
        device_facts[hostname] = facts
    topo = TopologyFacts(device_facts)
    print(f"         Parsed {len(device_facts)} devices in {time.time() - t0:.2f}s")

    # Save facts
    facts_out = output_dir / "independent_parser_facts.json"
    clean_facts = {}
    for hostname, facts in device_facts.items():
        clean = json.loads(json.dumps(facts, default=str))
        for iface in clean.get("interfaces", []):
            for k in list(iface.keys()):
                if k.startswith("_"):
                    del iface[k]
        clean_facts[hostname] = clean
    facts_out.write_text(
        json.dumps({"devices": clean_facts}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"  [3/4] Loading dataset from {dataset_path.name} ...")
    rows, meta = load_dataset(dataset_path)

    print("  [4/4] Running verification ...")
    t0 = time.time()
    results = run_verification(topo, rows)
    print(f"         Verified {len(results)} rows in {time.time() - t0:.2f}s")

    save_csv(results, output_dir / "independent_parser_results.csv")
    summary = generate_summary(results)
    save_summary_json(summary, output_dir / "independent_parser_summary.json")
    save_mismatch_report(results, output_dir / "independent_parser_mismatch.md")
    print_summary(summary)

    return summary


# ════════════════════════════════════════════════════════════════
#  Method 2 Runner + Human Guide Generation
# ════════════════════════════════════════════════════════════════

def run_method2(
    configs_dir: Path,
    dataset_path: Path,
    policies_path: Path,
    method1_dir: Path,
    output_dir: Path,
) -> Dict[str, Any]:
    """Run Method 2: automated crossref + generate human reviewer guide."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run the automated part via existing module
    from src.verification.run_manual_verification import (
        select_samples, ManualVerifier, _parse_evidence as m2_parse_evidence,
        save_checklist_csv, save_disagreement_log, save_summary_json as m2_save_summary,
        save_sample_selection_doc, save_protocol_doc,
    )

    # Load inputs
    configs = {}
    for f in sorted(configs_dir.glob("*.cfg")):
        configs[f.stem.lower()] = f.read_text(encoding="utf-8", errors="replace")

    ds = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows = ds.get("questions", ds) if isinstance(ds, dict) else ds

    policies_data = json.loads(policies_path.read_text(encoding="utf-8"))
    policies = policies_data.get("metrics_metadata", {})

    method1_summary = json.loads(
        (method1_dir / "independent_parser_summary.json").read_text(encoding="utf-8")
    )
    method1_mismatches = method1_summary.get("mismatch_examples", [])
    method1_facts = {}
    mf_path = method1_dir / "independent_parser_facts.json"
    if mf_path.exists():
        mf = json.loads(mf_path.read_text(encoding="utf-8"))
        method1_facts = mf.get("devices", mf)

    # Select samples
    l1_l3_rows = [r for r in rows if r.get("level") in ("L1", "L2", "L3")]
    samples = select_samples(l1_l3_rows, method1_mismatches)
    print(f"  Selected {len(samples)} stratified samples")

    # Save selection docs
    save_sample_selection_doc(samples, output_dir)
    save_protocol_doc(output_dir)

    # Run automated verification
    verifier = ManualVerifier(configs, policies, method1_facts)
    results = []
    for s in samples:
        results.append(verifier.verify(s))

    save_checklist_csv(results, output_dir)
    save_disagreement_log(results, output_dir)
    m2_save_summary(results, output_dir)

    # Generate human reviewer guide
    _generate_human_reviewer_guide(samples, policies, configs_dir, output_dir)
    _generate_blank_checklist(samples, policies, output_dir)

    agree = sum(1 for r in results if r["verdict"] == "AGREE")
    print(f"  Method 2: {agree}/{len(results)} AGREE ({agree/len(results)*100:.1f}%)")

    return {
        "total": len(results),
        "agree": agree,
        "disagree": len(results) - agree,
        "rate": agree / len(results) if results else 0,
        "samples": samples,
        "results": results,
    }


def _generate_human_reviewer_guide(
    samples: List[Dict],
    policies: Dict,
    configs_dir: Path,
    output_dir: Path,
) -> None:
    """Generate human-readable verification guide for Method 2 reviewers."""
    cfg_files = sorted(f.name for f in configs_dir.glob("*.cfg"))
    cfg_tree = "  ".join(cfg_files)

    lines = [
        "# Method 2 — Human Reviewer Guide",
        "",
        "> **목적**: 데이터셋 정답(Ground Truth)의 신뢰성을 사람이 직접 검증",
        f"> **대상**: L1-L3 계층화 표본 {len(samples)}개 QA",
        "> **소요 시간**: 약 2-3시간 (QA당 3-5분)",
        "> **필요 도구**: 텍스트 에디터 (VS Code 권장)",
        "",
        "---",
        "",
        "## 사전 준비",
        "",
        "### 1. Config 파일 위치",
        "```",
        f"{configs_dir.relative_to(configs_dir.parents[2])}/",
        f"  {cfg_tree}",
        "```",
        "",
        "### 2. 검증 순서",
        "1. 아래 체크리스트의 각 QA를 순서대로 진행",
        "2. 해당 .cfg 파일을 열고 **검증 절차**를 따라 직접 답을 도출",
        "3. 도출한 답과 **데이터셋 정답**을 비교",
        "4. `blank_checklist.csv`에 결과 기입",
        "",
        "### 3. 판정 기준",
        "| 판정 | 조건 |",
        "|------|------|",
        "| **AGREE** | 내가 구한 답 = 데이터셋 정답 |",
        "| **DISAGREE** | 내가 구한 답 ≠ 데이터셋 정답 |",
        "",
        "DISAGREE인 경우 분류:",
        "| 분류 | 의미 |",
        "|------|------|",
        "| DATA_ERROR | 데이터셋 정답이 틀림 |",
        "| REVIEWER_ERROR | 내 검증이 틀림 (재확인 필요) |",
        "| AMBIGUITY | 질문이나 답 정의가 모호함 |",
        "| FORMAT_MISMATCH | 값은 같은데 표기가 다름 |",
        "",
        "### 4. 비교 규칙 (answer_type별)",
        '| Type | 비교 방법 | 예시 |',
        '|------|-----------|------|',
        '| text | 대소문자 무시, 앞뒤 공백 제거 후 일치 | "PE1" = "pe1" |',
        '| number | 숫자 변환 후 값 비교 | "3" = "3.0" |',
        '| set | 순서 무관, 원소 일치 | ["a","b"] = ["b","a"] |',
        '| map | 키-값 쌍 완전 일치 | {"a":1} = {"a":1} |',
        "",
        "---",
        "",
        f"## 검증 체크리스트 ({len(samples)}개 QA)",
        "",
    ]

    for i, s in enumerate(samples, 1):
        ev = _parse_evidence(s)
        metric = ev.get("metric", "")
        scope = ev.get("scope", {})
        qa_id = s.get("id", "")
        level = s.get("level", "")
        answer_type = s.get("answer_type", "")
        question = s.get("question", "")
        answer = s.get("answer", "")

        # Get verification procedure from policies
        verification = ""
        for pkey, pval in policies.items():
            if pval.get("_metric_key", pkey) == metric or pkey == metric:
                verification = pval.get("verification", "")
                break
        # Fallback: search by metric substring
        if not verification:
            for pkey, pval in policies.items():
                if metric in pkey or pkey in metric:
                    verification = pval.get("verification", "")
                    break

        # Determine which .cfg files to check
        files_to_check = _determine_cfg_files(metric, scope, cfg_files)

        lines.extend([
            f"### {i}. {qa_id}",
            f"- **Level**: {level} | **Type**: {answer_type}",
            f"- **질문**: {question}",
            f"- **데이터셋 정답**: `{_serialize(answer)}`",
            f"- **확인할 파일**: {', '.join(files_to_check)}",
            f"- **검증 절차**:",
            f"  > {verification}" if verification else "  > (policies.json에 검증 절차 없음)",
            "- **내 답**: ________________",
            "- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________",
            "- **메모**: ",
            "",
        ])

    (output_dir / "human_reviewer_guide.md").write_text("\n".join(lines), encoding="utf-8")


def _determine_cfg_files(metric: str, scope: Dict, all_cfg_files: List[str]) -> List[str]:
    """Determine which .cfg files are relevant for a given metric/scope."""
    # L1: single device → scope["host"]
    host = scope.get("host", "")
    if host:
        fname = f"{host.lower()}.cfg"
        if fname in all_cfg_files:
            return [fname]

    # L3 compare: two devices
    hosts = []
    for key in ("host_a", "host_b", "host1", "host2", "src", "dst"):
        h = scope.get(key, "")
        if h:
            fname = f"{h.lower()}.cfg"
            if fname in all_cfg_files:
                hosts.append(fname)
    if hosts:
        return list(dict.fromkeys(hosts))  # deduplicate, preserve order

    # L2/L3 cross-device: all configs
    return ["전체 configs/*.cfg"]


def _generate_blank_checklist(
    samples: List[Dict],
    policies: Dict,
    output_dir: Path,
) -> None:
    """Generate blank CSV checklist for human reviewers."""
    fieldnames = [
        "#", "qa_id", "level", "metric", "answer_type",
        "question", "dataset_answer", "files_to_check",
        "my_answer", "verdict", "disagree_type", "memo",
    ]
    path = output_dir / "blank_checklist.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, s in enumerate(samples, 1):
            ev = _parse_evidence(s)
            writer.writerow({
                "#": i,
                "qa_id": s.get("id", ""),
                "level": s.get("level", ""),
                "metric": ev.get("metric", ""),
                "answer_type": s.get("answer_type", ""),
                "question": s.get("question", ""),
                "dataset_answer": _serialize(s.get("answer", "")),
                "files_to_check": "",
                "my_answer": "",
                "verdict": "",
                "disagree_type": "",
                "memo": "",
            })


# ════════════════════════════════════════════════════════════════
#  Method 3: PNETLab Guide Generation
# ════════════════════════════════════════════════════════════════

def run_method3_generation(
    configs_dir: Path,
    dataset_path: Path,
    policies_path: Path,
    output_dir: Path,
    lab_name: str,
) -> Dict[str, Any]:
    """Generate Method 3 PNETLab verification guide and checklists."""
    output_dir.mkdir(parents=True, exist_ok=True)

    ds = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows = ds.get("questions", ds) if isinstance(ds, dict) else ds

    policies_data = json.loads(policies_path.read_text(encoding="utf-8"))
    policies = policies_data.get("metrics_metadata", {})

    # Filter L4-L5 rows
    l4_l5_rows = [r for r in rows if r.get("level") in ("L4", "L5")]
    if not l4_l5_rows:
        print("  [Method 3] L4-L5 QA 없음 — 스킵")
        return {"total": 0, "l4": 0, "l5": 0, "samples": []}

    # Stratified sampling for L4-L5
    samples = _select_l4_l5_samples(l4_l5_rows)

    # Extract topology link map from configs
    link_map = _extract_link_map(configs_dir)

    # Generate guide
    _generate_pnetlab_guide(samples, policies, link_map, lab_name, configs_dir, output_dir)
    _generate_method3_blank_checklist(samples, output_dir)
    _generate_method3_sample_selection(samples, output_dir)
    _generate_method3_manifest(samples, output_dir)
    _generate_method3_review_protocol(output_dir)

    l4_count = sum(1 for s in samples if s.get("level") == "L4")
    l5_count = sum(1 for s in samples if s.get("level") == "L5")
    print(f"  Method 3: {len(samples)} samples selected (L4: {l4_count}, L5: {l5_count})")

    return {"total": len(samples), "l4": l4_count, "l5": l5_count, "samples": samples}


def _normalize_method3_verdict(raw: str) -> str:
    value = str(raw or "").strip().lower()
    if value in {"agree", "match", "ok", "pass", "passed", "yes", "y", "일치", "정답"}:
        return "AGREE"
    if value in {"disagree", "mismatch", "fail", "failed", "no", "n", "불일치", "오답"}:
        return "DISAGREE"
    if value in {"skip", "skipped", "n/a", "na", "not_sure", "uncertain", "보류"}:
        return "SKIP"
    return ""


def summarize_method3_review(checklist_path: Path, output_dir: Path) -> Optional[Dict[str, Any]]:
    """Parse a human-completed Method 3 checklist and persist a summary."""
    if not checklist_path.exists():
        return None

    with checklist_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    reviewed = 0
    agree = 0
    disagree = 0
    skipped = 0
    by_level: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "agree": 0, "disagree": 0, "skip": 0})
    by_metric: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "agree": 0, "disagree": 0, "skip": 0})

    for row in rows:
        verdict = _normalize_method3_verdict(row.get("verdict", ""))
        if not verdict:
            continue
        reviewed += 1
        level = str(row.get("level", "")).strip() or "UNKNOWN"
        metric = str(row.get("metric", "")).strip() or "UNKNOWN"
        by_level[level]["total"] += 1
        by_metric[metric]["total"] += 1
        if verdict == "AGREE":
            agree += 1
            by_level[level]["agree"] += 1
            by_metric[metric]["agree"] += 1
        elif verdict == "DISAGREE":
            disagree += 1
            by_level[level]["disagree"] += 1
            by_metric[metric]["disagree"] += 1
        else:
            skipped += 1
            by_level[level]["skip"] += 1
            by_metric[metric]["skip"] += 1

    if reviewed == 0:
        return None

    summary = {
        "status": "REVIEWED",
        "checklist_path": str(checklist_path),
        "total_reviewed": reviewed,
        "agree": agree,
        "disagree": disagree,
        "skip": skipped,
        "agreement_rate_raw": (agree / reviewed) if reviewed else 0.0,
        "by_level": dict(by_level),
        "by_metric": dict(by_metric),
    }
    (output_dir / "method3_verification_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return summary


def run_method4_replay(
    lab_path: Path,
    dataset_path: Path,
    policies_path: Path,
    output_dir: Path,
    batfish_host: str = "localhost",
) -> Dict[str, Any]:
    """Run Method 4: automatic L4-L5 Batfish replay verification."""
    output_dir.mkdir(parents=True, exist_ok=True)

    from src.verification.run_l45_replay_verification import (
        run_l45_replay_verification,
        save_csv as m4_save_csv,
        generate_summary as m4_generate_summary,
        save_summary_json as m4_save_summary_json,
        save_mismatch_report as m4_save_mismatch_report,
        save_paper_dataset,
    )

    results = run_l45_replay_verification(lab_path, dataset_path, policies_path, batfish_host=batfish_host)
    m4_save_csv(results, output_dir / "l45_replay_results.csv")
    summary = m4_generate_summary(results)
    m4_save_summary_json(summary, output_dir / "l45_replay_summary.json")
    m4_save_mismatch_report(results, output_dir / "l45_replay_mismatch.md")
    retained = save_paper_dataset(dataset_path, results, output_dir / "paper_ready_dataset.json")
    summary["paper_ready"] = retained
    m4_save_summary_json(summary, output_dir / "l45_replay_summary.json")
    print(
        f"  Method 4: {summary.get('match', 0)}/{summary.get('total', 0)} MATCH "
        f"({summary.get('agreement_rate', 0):.1%}), quarantined={summary.get('quarantined', 0)}"
    )
    return summary


def _select_l4_l5_samples(rows: List[Dict]) -> List[Dict]:
    """Stratified sampling: 2-3 per metric for L4-L5, max ~36 total."""
    by_metric: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        ev = _parse_evidence(r)
        metric = ev.get("metric", "")
        if metric:
            by_metric[metric].append(r)

    selected: Dict[str, Dict] = {}
    for metric, rlist in sorted(by_metric.items()):
        # Pick up to 3 per metric
        count = min(3, len(rlist))
        if len(rlist) <= 3:
            for r in rlist:
                selected[r["id"]] = r
        else:
            # Pick boundary + normal
            picked = 0
            # First: pick one with interesting answer (empty, 0, failure)
            for r in rlist:
                if picked >= count:
                    break
                ans = str(r.get("answer", ""))
                if any(kw in ans.lower() for kw in ("unreachable", "no ", "blocked", "fail", "0", "[]")):
                    if r["id"] not in selected:
                        selected[r["id"]] = r
                        picked += 1
            # Fill remaining
            for r in rlist:
                if picked >= count:
                    break
                if r["id"] not in selected:
                    selected[r["id"]] = r
                    picked += 1

    return sorted(selected.values(), key=lambda r: (r.get("level", ""), r.get("id", "")))


def _extract_link_map(configs_dir: Path) -> Dict[str, Dict[str, str]]:
    """Extract physical link topology from configs.
    Returns: {hostname: {peer_hostname: local_interface}}
    """
    link_map: Dict[str, Dict[str, str]] = defaultdict(dict)

    for f in sorted(configs_dir.glob("*.cfg")):
        hostname = f.stem.lower()
        text = f.read_text(encoding="utf-8", errors="replace")

        current_iface = None
        current_desc = None

        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("interface "):
                current_iface = stripped.split(None, 1)[1]
                current_desc = None
            elif stripped.startswith("description ") and current_iface:
                current_desc = stripped.split(None, 1)[1].lower()
                # Try to extract peer from description like "to p1" or "link to PE1"
                m = re.search(r"(?:to|link\s+to|connect(?:ed)?\s+to)\s+(\S+)", current_desc, re.IGNORECASE)
                if m:
                    peer = m.group(1).strip(".,;:").lower()
                    link_map[hostname][peer] = current_iface
            elif stripped == "!" or (not stripped.startswith(" ") and not stripped.startswith("!")):
                current_iface = None
                current_desc = None

    return dict(link_map)


def _generate_pnetlab_guide(
    samples: List[Dict],
    policies: Dict,
    link_map: Dict,
    lab_name: str,
    configs_dir: Path,
    output_dir: Path,
) -> None:
    """Generate PNETLab verification guide markdown."""
    # Collect device hostnames
    cfg_files = sorted(f.stem.lower() for f in configs_dir.glob("*.cfg"))
    num_nodes = len(cfg_files)

    # Count L4/L5
    l4_samples = [s for s in samples if s.get("level") == "L4"]
    l5_samples = [s for s in samples if s.get("level") == "L5"]

    lines = [
        f"# Method 3 — PNETLab 실환경 검증 가이드",
        "",
        f"> **목적**: Batfish 시뮬레이션 결과를 실제 Cisco IOS 라우터에서 검증",
        f"> **대상**: L4-L5 계층화 표본 {len(samples)}개 QA",
        f"> **소요 시간**: 약 4-6시간 (환경 구축 1h + L4 1.5h + L5 2.5h)",
        "> **필요**: PNETLab 서버 + Cisco IOSv 15.7 이미지",
        "",
        "---",
        "",
        "## 전체 검증 흐름 (3가지 Method)",
        "",
        "```",
        "┌─────────────────────────────────────────────────────────────────────┐",
        "│               NetConfigQA2.0 Ground Truth Verification              │",
        "├─────────────────────┬──────────────────┬────────────────────────────┤",
        "│  Method 1           │  Method 2        │  Method 3                  │",
        "│  독립 파서 (자동)   │  사람 검토 (수동)│  PNETLab 실환경 (수동)     │",
        "│                     │                  │                            │",
        "│  L1-L3 전수         │  L1-L3 표본      │  L4-L5 표본                │",
        "│  Python+Regex       │  눈+.cfg+체크리스트│  CLI: traceroute/ping     │",
        "└─────────────────────┴──────────────────┴────────────────────────────┘",
        "```",
        "",
        "---",
        "## Phase 0: PNETLab 환경 준비",
        "",
        f"### 토폴로지: {lab_name} ({num_nodes} nodes)",
        "",
        f"장비 목록: {', '.join(cfg_files)}",
        "",
        "### Config 적용 방법",
        "1. PNETLab 웹 UI에서 토폴로지 시작",
        f"2. 각 노드 콘솔 접속 → `configs/*.cfg` 내용 copy/paste",
        "3. 프로토콜 수렴 대기 (약 2분)",
        "",
        "### 수렴 확인 명령",
        "```",
        "# show ip ospf neighbor           ! 모두 FULL 상태여야 함",
        "# show ip bgp vpnv4 all summary   ! Established 확인",
        "# show mpls ldp neighbor           ! LDP 세션 확인",
        "```",
        "",
    ]

    # Link shutdown reference (for L5)
    if link_map:
        lines.extend([
            "### 링크→인터페이스 매핑 (L5 shutdown용)",
            "",
            "| 장비 | 피어 | 인터페이스 (shutdown 대상) |",
            "|------|------|---------------------------|",
        ])
        for host in sorted(link_map):
            for peer in sorted(link_map[host]):
                iface = link_map[host][peer]
                lines.append(f"| {host} | {peer} | {iface} |")
        lines.append("")

    # Phase 1: L4
    if l4_samples:
        lines.extend([
            "---",
            f"## Phase 1: L4 검증 ({len(l4_samples)}개)",
            "",
        ])
        for i, s in enumerate(l4_samples, 1):
            _write_pnetlab_test_case(lines, f"L4-{i}", s, policies, link_map)

    # Phase 2: L5
    if l5_samples:
        lines.extend([
            "---",
            f"## Phase 2: L5 검증 ({len(l5_samples)}개)",
            "",
            "> **주의**: L5는 failure injection 후 반드시 **원복(no shutdown)**해야 합니다!",
            "",
        ])
        for i, s in enumerate(l5_samples, 1):
            _write_pnetlab_test_case(lines, f"L5-{i}", s, policies, link_map)

    (output_dir / "pnetlab_verification_guide.md").write_text("\n".join(lines), encoding="utf-8")


def _extract_hosts_from_qa_id(qa_id: str) -> Tuple[str, str]:
    """Try to extract source/destination hosts from QA ID patterns.
    Examples:
      ACL_BLOCKING_leaf4_leaf3 → (leaf4, leaf3)
      TRACEROUTE_PATH_pe1_p1 → (pe1, p1)
      NODE_FAILURE_IMPACT_p2 → (p2, "")
      MULTI_LINK_FAILURE_p1_p2_pe1_pe2 → (p1, "")
    """
    known_hosts = {"leaf1", "leaf2", "leaf3", "leaf4", "p1", "p2", "p3", "p4", "pe1", "pe2"}
    parts = qa_id.lower().split("_")

    found = []
    for part in parts:
        if part in known_hosts:
            found.append(part)

    if len(found) >= 2:
        return found[0], found[1]
    elif len(found) == 1:
        return found[0], ""
    return "", ""


def _write_pnetlab_test_case(
    lines: List[str],
    label: str,
    sample: Dict,
    policies: Dict,
    link_map: Dict,
) -> None:
    """Write a single test case section for PNETLab guide."""
    ev = _parse_evidence(sample)
    metric = ev.get("metric", "")
    scope = ev.get("scope", {})
    qa_id = sample.get("id", "")
    question = sample.get("question", "")
    answer = sample.get("answer", "")
    level = sample.get("level", "")

    # Fill missing src/dst from QA ID if scope doesn't have them
    if not scope.get("src") and not scope.get("host"):
        id_src, id_dst = _extract_hosts_from_qa_id(qa_id)
        if id_src:
            scope = dict(scope)  # Don't mutate original
            scope.setdefault("src", id_src)
            if id_dst:
                scope.setdefault("dst", id_dst)

    lines.extend([
        f"### {label}. {qa_id}",
        f"- **메트릭**: `{metric}`",
        f"- **질문**: {question}",
        f"- **데이터셋 정답**: `{_serialize(answer)}`",
        "",
    ])

    # Generate CLI commands based on metric type
    cli_commands = _generate_cli_commands(metric, scope, link_map, level)
    lines.append("```")
    for cmd in cli_commands:
        lines.append(cmd)
    lines.append("```")
    lines.extend([
        "- **내 결과**: ________________",
        "- **판정**: [ ] AGREE  [ ] DISAGREE",
        "",
    ])


def _generate_cli_commands(
    metric: str,
    scope: Dict,
    link_map: Dict,
    level: str,
) -> List[str]:
    """Generate Cisco CLI commands for a given metric."""
    src = scope.get("src", scope.get("host", "")).upper()
    dst = scope.get("dst", "").upper()
    src_ip = scope.get("src_ip", "")
    dst_ip = scope.get("dst_ip", "")

    commands = []

    # L4 metrics
    if metric == "traceroute_path":
        host = src or "?"
        target = dst_ip or dst or "?"
        commands.append(f"! {host}에서 {target}으로 경로 추적:")
        commands.append(f"{host}# traceroute {target}")

    elif metric == "reachability_status":
        host = src or "?"
        target = dst_ip or dst or "?"
        commands.append(f"! {host}에서 {target} 도달성 확인:")
        commands.append(f"{host}# ping {target}")
        commands.append(f"{host}# traceroute {target}")

    elif metric == "bounded_path_length":
        host = src or "?"
        target = dst_ip or dst or "?"
        commands.append(f"! {host}에서 {target}까지 홉 수 확인:")
        commands.append(f"{host}# traceroute {target}")
        commands.append("! 홉 수를 세어 max_hops와 비교")

    elif metric == "asymmetric_path_comparison":
        host_a = src or scope.get("host_a", "?").upper()
        host_b = dst or scope.get("host_b", "?").upper()
        commands.append("! 양방향 경로 확인:")
        commands.append(f"{host_a}# traceroute <{host_b} loopback IP>")
        commands.append(f"{host_b}# traceroute <{host_a} loopback IP>")

    elif metric == "acl_blocking_point":
        host = src or "?"
        target = dst_ip or dst or "?"
        commands.append("! ACL 차단 지점 확인:")
        commands.append(f"{host}# traceroute {target}")
        commands.append(f"{host}# show ip access-lists")
        if dst:
            commands.append(f"! {dst} 장비도 확인: {dst.upper()}# show ip access-lists")

    elif metric == "waypoint_traversal_path":
        host = src or "?"
        target = dst_ip or dst or "?"
        commands.append("! Waypoint 경유 확인:")
        commands.append(f"{host}# traceroute {target}")
        commands.append("! 경로에 waypoint가 포함되는지 확인")

    elif metric in ("blackhole_destination_list", "blackhole_check"):
        commands.append("! Blackhole 목적지 확인:")
        commands.append("! 각 장비에서 목적지로 ping/traceroute:")
        commands.append("# ping <target_ip>")
        commands.append("# traceroute <target_ip>")

    elif metric == "loop_detection":
        commands.append("! 루프 탐지:")
        commands.append("# traceroute <target_ip>")
        commands.append("! 동일 홉이 반복되면 루프 존재")

    elif metric in ("leaked_prefixes_list", "leaked_prefix_count"):
        commands.append("! VRF 간 경로 누출 확인:")
        commands.append("# show ip route vrf <vrf_name>")
        commands.append("# show ip bgp vpnv4 vrf <vrf_name>")

    elif metric in ("redundant_paths_list", "redundant_path_count"):
        host = src or "?"
        target = dst_ip or "?"
        commands.append("! 이중화 경로 확인:")
        commands.append(f"{host}# show ip route {target}")
        commands.append(f"{host}# traceroute {target}")

    elif metric == "ospf_area0_routers":
        commands.append("! OSPF Area 0 라우터 확인:")
        commands.append("# show ip ospf neighbor")
        commands.append("# show ip ospf interface brief")

    elif metric == "non_existent_node_check":
        commands.append("! 존재하지 않는 노드 확인:")
        commands.append("# show ip ospf neighbor")
        commands.append("# show ip bgp summary")

    # L5 metrics (failure injection)
    elif metric == "multi_link_failure_reachability":
        links = scope.get("failed_links", [])
        commands.append("! 다중 링크 장애 시뮬레이션:")
        for link in links[:3]:
            if isinstance(link, list) and len(link) == 2:
                a, b = link[0].lower(), link[1].lower()
                iface = link_map.get(a, {}).get(b, "<interface>")
                commands.append(f"{a.upper()}# conf t")
                commands.append(f"{a.upper()}(config)# interface {iface}")
                commands.append(f"{a.upper()}(config-if)# shutdown")
        if src and dst_ip:
            commands.append(f"! 장애 적용 후 도달성 확인:")
            commands.append(f"{src}# ping {dst_ip}")
        commands.append("! === 원복 ===")
        for link in links[:3]:
            if isinstance(link, list) and len(link) == 2:
                a, b = link[0].lower(), link[1].lower()
                iface = link_map.get(a, {}).get(b, "<interface>")
                commands.append(f"{a.upper()}(config-if)# no shutdown")

    elif metric == "node_failure_impact":
        failed_node = scope.get("failed_node", "?").upper()
        commands.append(f"! 노드 장애 시뮬레이션 ({failed_node}):")
        commands.append(f"! {failed_node}의 모든 인터페이스 shutdown")
        if failed_node.lower() in link_map:
            for peer, iface in link_map[failed_node.lower()].items():
                commands.append(f"{failed_node}(config)# interface {iface}")
                commands.append(f"{failed_node}(config-if)# shutdown")
        commands.append("! 다른 장비에서 도달성 확인:")
        commands.append("# ping <target_ip>")
        commands.append("! === 원복: 모든 인터페이스 no shutdown ===")

    elif metric == "root_cause_analysis":
        commands.append("! 장애 원인 분석:")
        failed = scope.get("failed_links", scope.get("failed_nodes", []))
        if failed:
            commands.append(f"! 장애 요소: {json.dumps(failed)}")
        commands.append("# show ip ospf neighbor")
        commands.append("# show ip bgp summary")
        commands.append("# show ip route")
        commands.append("! 장애 적용 후 위 명령으로 영향 범위 확인")

    elif metric == "redundancy_verification":
        commands.append("! 이중화 검증:")
        failed = scope.get("failed_links", scope.get("failed_nodes", []))
        if failed:
            commands.append(f"! 장애 요소: {json.dumps(failed)}")
        commands.append("! 1) 장애 적용 전 ping 확인")
        commands.append("! 2) 장애 적용 (shutdown)")
        commands.append("! 3) 수렴 대기 후 ping 재확인")
        commands.append("! 4) 원복 (no shutdown)")

    elif metric == "spof_detection":
        commands.append("! Single Point of Failure 탐지:")
        commands.append("! 각 링크/노드를 하나씩 다운시키며 전체 도달성 확인")
        commands.append("! 1개 장애로 전체 통신 불가 → SPOF")

    elif metric in ("dual_node_failure_impact", "triple_node_failure"):
        nodes = scope.get("failed_nodes", [])
        commands.append(f"! 다중 노드 장애: {nodes}")
        for node in nodes[:3]:
            n = str(node).upper()
            commands.append(f"! {n} 전체 인터페이스 shutdown")
        commands.append("! 장애 적용 후 도달성 확인")
        commands.append("! === 원복 ===")

    elif metric == "worst_case_failure_analysis":
        commands.append("! 최악 시나리오 분석:")
        commands.append("! 주요 백본 링크를 순차적으로 다운")
        commands.append("! 각 단계에서 도달성 변화 관찰")

    else:
        commands.append(f"! 메트릭: {metric}")
        commands.append(f"! scope: {json.dumps(scope, ensure_ascii=False)}")
        commands.append("! 적절한 show/ping/traceroute 명령으로 검증")

    return commands


def _generate_method3_blank_checklist(samples: List[Dict], output_dir: Path) -> None:
    fieldnames = [
        "#", "qa_id", "level", "metric", "answer_type",
        "question", "dataset_answer",
        "my_result", "verdict", "memo",
    ]
    path = output_dir / "blank_checklist.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, s in enumerate(samples, 1):
            ev = _parse_evidence(s)
            writer.writerow({
                "#": i,
                "qa_id": s.get("id", ""),
                "level": s.get("level", ""),
                "metric": ev.get("metric", ""),
                "answer_type": s.get("answer_type", ""),
                "question": s.get("question", ""),
                "dataset_answer": _serialize(s.get("answer", "")),
                "my_result": "",
                "verdict": "",
                "memo": "",
            })


def _generate_method3_manifest(samples: List[Dict], output_dir: Path) -> None:
    manifest = []
    for i, s in enumerate(samples, 1):
        ev = _parse_evidence(s)
        manifest.append({
            "index": i,
            "qa_id": s.get("id", ""),
            "id_v2": s.get("id_v2", ""),
            "level": s.get("level", ""),
            "metric": ev.get("metric", ""),
            "answer_type": s.get("answer_type", ""),
            "question": s.get("question", ""),
            "dataset_answer": s.get("answer", ""),
            "scope": ev.get("scope", {}),
        })
    (output_dir / "sample_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _generate_method3_review_protocol(output_dir: Path) -> None:
    lines = [
        "# Method 3 Review Protocol",
        "",
        "## 목적",
        "- PNETLab에서 실제 CLI 결과를 확인한 뒤 L4-L5 표본 QA의 외부 타당성을 기록한다.",
        "- `blank_checklist.csv`를 복사해 `reviewed_checklist.csv`로 저장한 뒤 결과를 채운다.",
        "",
        "## 파일 규칙",
        "- 입력 템플릿: `blank_checklist.csv`",
        "- 권장 결과 파일명: `reviewed_checklist.csv`",
        "- 파이프라인 연동: `--method3-review <csv>` 또는 같은 디렉터리의 `reviewed_checklist.csv` 자동 감지",
        "",
        "## verdict 허용값",
        "- `AGREE`: dataset answer와 실환경 결과가 일치",
        "- `DISAGREE`: dataset answer와 실환경 결과가 불일치",
        "- `SKIP`: 장비 문제, 시간 부족, 조건 불충분 등으로 판정 보류",
        "",
        "## my_result 작성 규칙",
        "- 실제 CLI 결과를 간결하게 적는다.",
        "- 경로형 답변은 hop 순서를 유지한다.",
        "- 장애 주입이 필요한 경우 `memo`에 shutdown/no shutdown 여부를 기록한다.",
        "",
        "## 권장 판정 기준",
        "- 경로 질문: source와 destination이 같고 핵심 hop 순서가 같으면 `AGREE`",
        "- reachability 질문: reachable/unreachable 판정이 같으면 `AGREE`",
        "- root cause 질문: blocking point 또는 원인 장비가 같으면 `AGREE`",
        "- what-if 질문: 장애 후 `NONE/REROUTED/DISCONNECTED` 판정이 같으면 `AGREE`",
        "",
        "## 파이프라인 반영",
        "```bash",
        "python Make_Dataset/src/verification/run_verification_pipeline.py \\",
        "  --lab-path Data/Pnetlab/<LAB_NAME> \\",
        "  --skip-method1 --skip-method2 --skip-method4 \\",
        "  --method3-review Data/Pnetlab/<LAB_NAME>/Dataset/verification/method3_pnetlab/reviewed_checklist.csv",
        "```",
        "",
        "성공 시 `method3_verification_summary.json`과 `verification_summary.json`에 외부 검증 수치가 반영된다.",
    ]
    (output_dir / "review_protocol.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _generate_method3_sample_selection(samples: List[Dict], output_dir: Path) -> None:
    by_metric: Dict[str, int] = defaultdict(int)
    l4_count = 0
    l5_count = 0
    for s in samples:
        ev = _parse_evidence(s)
        by_metric[ev.get("metric", "")] += 1
        if s.get("level") == "L4":
            l4_count += 1
        else:
            l5_count += 1

    lines = [
        "# Method 3 — Sample Selection",
        "",
        f"Total: {len(samples)} (L4: {l4_count}, L5: {l5_count})",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for m in sorted(by_metric):
        lines.append(f"| {m} | {by_metric[m]} |")

    (output_dir / "sample_selection.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ════════════════════════════════════════════════════════════════
#  Unified Summary
# ════════════════════════════════════════════════════════════════

def generate_unified_summary(
    lab_name: str,
    dataset_total: int,
    m1_summary: Optional[Dict],
    m2_info: Optional[Dict],
    m3_info: Optional[Dict],
    m4_info: Optional[Dict],
    output_path: Path,
) -> None:
    """Generate unified verification_summary.json combining all methods."""
    now = datetime.now().strftime("%Y-%m-%d")

    summary: Dict[str, Any] = {
        "title": "NetConfigQA2.0 Ground Truth Verification Summary",
        "topology": lab_name,
        "date": now,
        "dataset_total_qa": dataset_total,
        "verification_methods": {},
    }

    # Method 1
    if m1_summary:
        total = m1_summary.get("verifiable", 0)
        match = m1_summary.get("match", 0)
        mismatch = m1_summary.get("mismatch", 0)
        summary["verification_methods"]["method1_independent_parser"] = {
            "description": "Batfish-independent .cfg parser (pure Python + Regex) for L1-L3 full verification",
            "scope": f"L1-L3 전수검증 ({total} QA)",
            "total_verified": total,
            "match": match,
            "mismatch": mismatch,
            "agreement_rate_raw": m1_summary.get("agreement_rate", 0),
            "by_level": m1_summary.get("by_level", {}),
            "by_answer_type": m1_summary.get("by_answer_type", {}),
        }

    # Method 2
    if m2_info and m2_info.get("total", 0) > 0:
        summary["verification_methods"]["method2_manual_check"] = {
            "description": "Stratified sampling + raw .cfg trace + policy-based verification",
            "scope": f"L1-L3 계층화 표본추출 ({m2_info['total']} QA)",
            "total_verified": m2_info["total"],
            "agree": m2_info["agree"],
            "disagree": m2_info["disagree"],
            "agreement_rate_raw": m2_info["rate"],
        }

    # Method 3
    if m3_info and m3_info.get("total", 0) > 0:
        method3_summary = {
            "description": "PNETLab 에뮬레이션 환경에서 traceroute/ping 실행하여 L4-L5 검증",
            "scope": f"L4-L5 표본 ({m3_info['total']} QA: L4 {m3_info['l4']}, L5 {m3_info['l5']})",
            "status": m3_info.get("status", "GUIDE_GENERATED"),
        }
        if method3_summary["status"] == "REVIEWED":
            method3_summary.update({
                "total_reviewed": m3_info.get("total_reviewed", 0),
                "agree": m3_info.get("agree", 0),
                "disagree": m3_info.get("disagree", 0),
                "skip": m3_info.get("skip", 0),
                "agreement_rate_raw": m3_info.get("agreement_rate_raw", 0.0),
                "by_level": m3_info.get("by_level", {}),
                "by_metric": m3_info.get("by_metric", {}),
                "checklist_path": m3_info.get("checklist_path", ""),
            })
        else:
            method3_summary["note"] = "가이드 및 체크리스트 생성 완료. 사람이 PNETLab에서 실행해야 함."
        summary["verification_methods"]["method3_pnetlab_emulation"] = method3_summary

    if m4_info and m4_info.get("total", 0) > 0:
        summary["verification_methods"]["method4_l45_replay"] = {
            "description": "Batfish replay verification for L4-L5 using row-level contracts",
            "scope": f"L4-L5 자동 재실행 ({m4_info['total']} QA)",
            "total_verified": m4_info["total"],
            "match": m4_info.get("match", 0),
            "mismatch": m4_info.get("mismatch", 0),
            "error": m4_info.get("error", 0),
            "quarantined": m4_info.get("quarantined", 0),
            "agreement_rate_raw": m4_info.get("agreement_rate", 0),
            "by_level": m4_info.get("by_level", {}),
            "paper_ready": m4_info.get("paper_ready", {}),
        }

    output_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


# ════════════════════════════════════════════════════════════════
#  Main Pipeline
# ════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetConfigQA2.0 — Unified Ground Truth Verification Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # 전체 파이프라인 실행
          python run_verification_pipeline.py --lab-path Data/Pnetlab/Research_Institute_Internal_DC/

          # Method 1만 스킵 (이미 완료)
          python run_verification_pipeline.py --lab-path Data/Pnetlab/Lab_B/ --skip-method1

          # 특정 데이터셋 지정
          python run_verification_pipeline.py --lab-path Data/Pnetlab/Lab_B/ \\
            --dataset Data/Pnetlab/Lab_B/Dataset/Lab_B_dataset_batfish_20260215.json
        """),
    )
    parser.add_argument("--lab-path", required=True, help="Lab root directory (contains configs/ and Dataset/)")
    parser.add_argument("--policies", default=None, help="policies.json path (auto-detected if omitted)")
    parser.add_argument("--dataset", default=None, help="Dataset JSON path (auto: latest in Dataset/)")
    parser.add_argument("--skip-method1", action="store_true", help="Skip Method 1 (use existing results)")
    parser.add_argument("--skip-method2", action="store_true", help="Skip Method 2")
    parser.add_argument("--skip-method3", action="store_true", help="Skip Method 3")
    parser.add_argument("--skip-method4", action="store_true", help="Skip Method 4")
    parser.add_argument("--method3-review", default=None, help="Completed Method 3 checklist CSV to ingest")
    parser.add_argument("--batfish-host", default="localhost", help="Batfish host for Method 4 replay")
    args = parser.parse_args()

    lab_path = Path(args.lab_path).resolve()
    print("=" * 65)
    print("  NetConfigQA2.0 — Ground Truth Verification Pipeline")
    print("=" * 65)
    print(f"  Lab: {lab_path.name}")

    # Discover
    info = discover_lab(lab_path)
    configs_dir = info["configs_dir"]
    dataset_path = Path(args.dataset).resolve() if args.dataset else info["dataset_path"]
    verification_dir = info["verification_dir"]

    print(f"  Configs: {configs_dir} ({len(list(configs_dir.glob('*.cfg')))} files)")
    print(f"  Dataset: {dataset_path.name}")
    print(f"  Output:  {verification_dir}/")
    print()

    # Load dataset for total count
    ds = json.loads(dataset_path.read_text(encoding="utf-8"))
    all_rows = ds.get("questions", ds) if isinstance(ds, dict) else ds
    dataset_total = len(all_rows)
    print(f"  Total QA in dataset: {dataset_total}")

    # Policies
    policies_path = Path(args.policies).resolve() if args.policies else discover_policies()
    print(f"  Policies: {policies_path.name}")
    print()

    m1_dir = verification_dir / "method1_independent_parser"
    m2_dir = verification_dir / "method2_manual_check"
    m3_dir = verification_dir / "method3_pnetlab"
    m4_dir = verification_dir / "method4_l45_replay"
    existing_unified = _load_existing_unified_summary(verification_dir)

    m1_summary = None
    m2_info = None
    m3_info = None
    m4_info = None

    # ── Method 1 ─────────────────────────────────
    if args.skip_method1:
        print("[Method 1] 스킵 (--skip-method1)")
        summary_path = m1_dir / "independent_parser_summary.json"
        if summary_path.exists():
            m1_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            print(f"  기존 결과 로드: {m1_summary.get('agreement_rate', 0):.1%}")
        print()
    else:
        print("[Method 1] Independent Parser — L1-L3 전수 검증")
        print("-" * 50)
        m1_summary = run_method1(configs_dir, dataset_path, m1_dir)
        print()

    # ── Method 2 ─────────────────────────────────
    if args.skip_method2:
        print("[Method 2] 스킵 (--skip-method2)")
        existing_m2 = existing_unified.get("method2_manual_check")
        if not existing_m2:
            existing_m2 = _safe_load_json(m2_dir / "manual_verification_summary.json")
        if existing_m2:
            m2_info = {
                "total": existing_m2.get("total_verified", existing_m2.get("total_samples", 0)),
                "agree": existing_m2.get("agree", existing_m2.get("agreed_samples", 0)),
                "disagree": existing_m2.get("disagree", existing_m2.get("disagreed_samples", 0)),
                "rate": existing_m2.get("agreement_rate_raw", existing_m2.get("agreement_rate", 0.0)),
            }
            print(f"  기존 결과 로드: {m2_info['rate']:.1%}")
        print()
    else:
        if m1_summary is None:
            print("[Method 2] 스킵 — Method 1 결과 필요")
            print()
        else:
            print("[Method 2] Manual Verification — L1-L3 계층화 표본")
            print("-" * 50)
            m2_info = run_method2(configs_dir, dataset_path, policies_path, m1_dir, m2_dir)
            print()

    # ── Method 3 ─────────────────────────────────
    if args.skip_method3:
        print("[Method 3] 스킵 (--skip-method3)")
        existing_m3 = existing_unified.get("method3_pnetlab_emulation")
        if not existing_m3:
            existing_m3 = _safe_load_json(m3_dir / "method3_verification_summary.json")
        if existing_m3:
            m3_info = {
                "total": 0,
                "l4": 0,
                "l5": 0,
                "status": existing_m3.get("status", "GUIDE_GENERATED"),
            }
            scope = str(existing_m3.get("scope", ""))
            match = re.search(r"L4\s+(\d+),\s*L5\s+(\d+)", scope)
            total_match = re.search(r"\((\d+)\s+QA", scope)
            if total_match:
                m3_info["total"] = int(total_match.group(1))
            if match:
                m3_info["l4"] = int(match.group(1))
                m3_info["l5"] = int(match.group(2))
            if m3_info["status"] == "REVIEWED":
                m3_info.update({
                    "total_reviewed": existing_m3.get("total_reviewed", 0),
                    "agree": existing_m3.get("agree", 0),
                    "disagree": existing_m3.get("disagree", 0),
                    "skip": existing_m3.get("skip", 0),
                    "agreement_rate_raw": existing_m3.get("agreement_rate_raw", 0.0),
                    "by_level": existing_m3.get("by_level", {}),
                    "by_metric": existing_m3.get("by_metric", {}),
                    "checklist_path": existing_m3.get("checklist_path", ""),
                })
                print(f"  기존 결과 로드: {m3_info['agreement_rate_raw']:.1%}")
            else:
                print("  기존 가이드 상태 로드")
        print()
    else:
        l4l5_count = sum(1 for r in all_rows if r.get("level") in ("L4", "L5"))
        if l4l5_count == 0:
            print("[Method 3] L4-L5 QA 없음 — 스킵")
            print()
        else:
            print(f"[Method 3] PNETLab Guide — L4-L5 ({l4l5_count} QA)")
            print("-" * 50)
            m3_info = run_method3_generation(configs_dir, dataset_path, policies_path, m3_dir, info["lab_name"])
            review_candidate = None
            if args.method3_review:
                review_candidate = Path(args.method3_review).resolve()
            else:
                default_review = m3_dir / "reviewed_checklist.csv"
                if default_review.exists():
                    review_candidate = default_review
            if review_candidate:
                reviewed = summarize_method3_review(review_candidate, m3_dir)
                if reviewed:
                    m3_info = {**m3_info, **reviewed}
                    print(
                        f"  Method 3 Review: {reviewed['agree']}/{reviewed['total_reviewed']} AGREE "
                        f"({reviewed['agreement_rate_raw']:.1%})"
                    )
            print()

    # ── Method 4 ─────────────────────────────────
    if args.skip_method4:
        print("[Method 4] 스킵 (--skip-method4)")
        existing_m4 = existing_unified.get("method4_l45_replay")
        if not existing_m4:
            existing_m4 = _safe_load_json(m4_dir / "l45_replay_summary.json")
        if existing_m4:
            m4_info = {
                "total": existing_m4.get("total_verified", existing_m4.get("total", 0)),
                "match": existing_m4.get("match", 0),
                "mismatch": existing_m4.get("mismatch", 0),
                "error": existing_m4.get("error", 0),
                "quarantined": existing_m4.get("quarantined", 0),
                "agreement_rate": existing_m4.get("agreement_rate_raw", existing_m4.get("agreement_rate", 0.0)),
                "by_level": existing_m4.get("by_level", {}),
                "paper_ready": existing_m4.get("paper_ready", {}),
            }
            print(f"  기존 결과 로드: {m4_info['agreement_rate']:.1%}")
        print()
    else:
        l4l5_count = sum(1 for r in all_rows if r.get("level") in ("L4", "L5"))
        if l4l5_count == 0:
            print("[Method 4] L4-L5 QA 없음 — 스킵")
            print()
        else:
            print(f"[Method 4] L4-L5 Replay Verification ({l4l5_count} QA)")
            print("-" * 50)
            m4_info = run_method4_replay(lab_path, dataset_path, policies_path, m4_dir, batfish_host=args.batfish_host)
            print()

    # ── Unified Summary ──────────────────────────
    print("[Summary] 통합 검증 요약 생성")
    summary_path = verification_dir / "verification_summary.json"
    generate_unified_summary(
        info["lab_name"], dataset_total,
        m1_summary, m2_info, m3_info, m4_info,
        summary_path,
    )
    print(f"  → {summary_path}")

    # ── Final Report ─────────────────────────────
    print()
    print("=" * 65)
    print("  Pipeline Complete!")
    print("=" * 65)
    print(f"  Output: {verification_dir}/")
    print()

    tree = [
        "  verification/",
    ]
    if m1_summary:
        rate = m1_summary.get("agreement_rate", 0)
        tree.append(f"  ├── method1_independent_parser/   ✅ {rate:.1%}")
    if m2_info:
        tree.append(f"  ├── method2_manual_check/         📋 {m2_info['total']} samples")
        tree.append(f"  │   ├── human_reviewer_guide.md   ← 사람에게 전달")
        tree.append(f"  │   └── blank_checklist.csv       ← Excel로 작성")
    if m3_info and m3_info.get("total", 0) > 0:
        if m3_info.get("status") == "REVIEWED":
            tree.append(f"  ├── method3_pnetlab/               ✅ {m3_info.get('agreement_rate_raw', 0):.1%} on {m3_info.get('total_reviewed', 0)} reviewed")
            tree.append(f"  │   ├── pnetlab_verification_guide.md")
            tree.append(f"  │   └── method3_verification_summary.json")
        else:
            tree.append(f"  ├── method3_pnetlab/               📋 {m3_info['total']} samples")
            tree.append(f"  │   ├── pnetlab_verification_guide.md  ← PNETLab에서 실행")
            tree.append(f"  │   └── blank_checklist.csv       ← Excel로 작성")
    if m4_info and m4_info.get("total", 0) > 0:
        tree.append(f"  ├── method4_l45_replay/           ✅ {m4_info.get('agreement_rate', 0):.1%}")
        tree.append(f"  │   ├── l45_replay_mismatch.md    ← 자동 mismatch/quarantine")
        tree.append(f"  │   └── paper_ready_dataset.json  ← 논문용 retained set")
    tree.append(f"  └── verification_summary.json     📊 통합 요약")

    for line in tree:
        print(line)
    print()


if __name__ == "__main__":
    main()
