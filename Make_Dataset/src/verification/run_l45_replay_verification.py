#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.core_batfish.batfish_builder import BatfishBuilder
from src.l45_contracts import build_l45_contract
from src.main_batfish import canonicalize_text_answer
from src.verification.compare import compare_answers
from pybatfish.datamodel.flow import HeaderConstraints


TEXT_TYPES = {"text", "scalar_str", "enum"}


def load_dataset(dataset_path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return list(payload.get("questions", [])), dict(payload.get("meta", {}))
    if isinstance(payload, list):
        return payload, {}
    raise ValueError(f"Unsupported dataset shape in {dataset_path}")


def parse_jsonish(val: Any, default: Any):
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str) and val.strip():
        try:
            return json.loads(val)
        except Exception:
            return default
    return default


def _row_metric(row: Dict[str, Any]) -> str:
    metric = str(row.get("metric", "")).strip()
    if metric:
        return metric
    evidence = parse_jsonish(row.get("evidence"), {})
    return str(evidence.get("metric", "")).strip()


def _row_scope(row: Dict[str, Any]) -> Dict[str, Any]:
    scope = parse_jsonish(row.get("scope"), None)
    if isinstance(scope, dict):
        return scope
    evidence = parse_jsonish(row.get("evidence"), {})
    scope = evidence.get("scope", {})
    return dict(scope) if isinstance(scope, dict) else {}


def _ensure_contract(row: Dict[str, Any], builder: BatfishBuilder) -> Dict[str, Any]:
    scenario = parse_jsonish(row.get("scenario"), None)
    query_contract = parse_jsonish(row.get("query_contract"), None)
    verification_contract = parse_jsonish(row.get("verification_contract"), None)
    metric = _row_metric(row)
    scope = _row_scope(row)
    if metric and isinstance(query_contract, dict) and isinstance(scenario, dict):
        return {
            "metric": metric,
            "scope": scope,
            "scenario": scenario,
            "query_contract": query_contract,
            "verification_contract": verification_contract or {"answer_shape": row.get("answer_type", "text"), "compare_mode": "canonical"},
            "oracle_source": row.get("oracle_source", "batfish_replay"),
            "verification_status": row.get("verification_status", "pending"),
            "quarantine_reason": row.get("quarantine_reason", ""),
        }
    pseudo_q = {
        "id": row.get("id", ""),
        "metric": metric,
        "answer_type": row.get("answer_type", "text"),
        "question": row.get("question", ""),
        "evidence_hint": {"metric": metric, "scope": scope},
    }
    return build_l45_contract(pseudo_q, builder)


def _materialize_snapshot(builder: BatfishBuilder, scenario: Dict[str, Any], row_id: str) -> str:
    base_snapshot = str(scenario.get("base_snapshot") or builder.snapshot_name)
    fork_ops = scenario.get("fork_ops", []) or []
    builder.bf.set_snapshot(base_snapshot)
    if not fork_ops:
        return base_snapshot

    deactivate_nodes: List[str] = []
    deactivate_interfaces: List[Any] = []
    for op in fork_ops:
        if not isinstance(op, dict):
            continue
        op_type = str(op.get("type", ""))
        if op_type == "deactivate_nodes":
            deactivate_nodes.extend([str(n) for n in op.get("nodes", []) if n])
        elif op_type == "deactivate_interfaces":
            deactivate_interfaces.extend(op.get("interfaces", []))

    snap_name = f"method4_{re.sub(r'[^A-Za-z0-9_.-]+', '_', row_id)}_{int(time.time() * 1000)}"
    builder.bf.fork_snapshot(
        base_name=base_snapshot,
        name=snap_name,
        deactivate_nodes=deactivate_nodes or None,
        deactivate_interfaces=deactivate_interfaces or None,
        overwrite=True,
    )
    builder.bf.set_snapshot(snap_name)
    return snap_name


def _format_text(metric: str, text: str) -> str:
    current = text
    for _ in range(3):
        updated = canonicalize_text_answer(metric, current)
        if updated == current:
            break
        current = updated
    return current


def _replay_redundant_paths(builder: BatfishBuilder, src_node: str, dst_ip: str) -> List[str]:
    src_fixed = builder._fix_start_location(src_node)
    traces_result = builder.bf.q.traceroute(
        startLocation=src_fixed,
        headers=HeaderConstraints(dstIps=dst_ip)
    ).answer(snapshot=builder.snapshot_name).frame()
    redundant_paths: List[str] = []
    if not traces_result.empty:
        traces = traces_result['Traces'].iloc[0]
        if traces:
            for trace in traces[:3]:
                path_nodes = []
                hops = getattr(trace, 'hops', []) if hasattr(trace, 'hops') else []
                for hop in hops:
                    node = getattr(hop, 'node', None)
                    if node:
                        node_name = getattr(node, 'hostname', str(node))
                        if node_name not in path_nodes:
                            path_nodes.append(node_name)
                if path_nodes:
                    path_str = " → ".join(path_nodes)
                    if path_str not in redundant_paths:
                        redundant_paths.append(path_str)
    return redundant_paths


def _format_answer(metric: str, res: Any, params: Dict[str, Any]) -> Any:
    if metric == "traceroute_path":
        path = res.value if res.status == "OK" and res.value else []
        return _format_text(metric, " → ".join(path) if path else "경로 없음")
    if metric == "reachability_status":
        reachable = res.value.get("reachable", False)
        path_list = res.value.get("path", [])
        disposition = res.value.get("disposition", "UNKNOWN")
        path_str = " → ".join(path_list) if path_list else "없음"
        if reachable:
            return _format_text(metric, f"경로: {path_str}, 도달: 가능")
        return _format_text(metric, f"경로: {path_str}, 도달: 불가 (원인: {disposition})")
    if metric == "acl_blocking_point":
        blocked = res.value.get("blocked", False)
        if blocked:
            return _format_text(metric, f"차단됨 (장비: {res.value.get('node', '')}, 원인: {res.value.get('reason', '')})")
        return _format_text(metric, "허용됨")
    if metric == "loop_detection":
        loops = res.value.get("loops", [])
        return _format_text(metric, f"발견: {loops[0] if loops else 'Loop detected'}" if res.value.get("detected", False) else "없음")
    if metric == "blackhole_destination_list":
        return res.value.get("blackholes", []) if res.status == "OK" else []
    if metric == "waypoint_traversal_path":
        path = res.value.get("path", [])
        path_str = " → ".join(path) if path else "경로 정보 없음"
        return _format_text(metric, path_str if res.value.get("passes_through", False) else "경유하지 않음")
    if metric == "leaked_prefixes_list":
        return res.value.get("leaked_prefixes", []) if res.status == "OK" else []
    if metric == "asymmetric_path_comparison":
        fwd = " → ".join(res.value.get("path_forward", []) or ["경로 없음"])
        rev = " → ".join(res.value.get("path_reverse", []) or ["경로 없음"])
        return _format_text(metric, f"Forward: {fwd}, Reverse: {rev}")
    if metric == "ospf_compatibility_check":
        return {"issues": res.value.get("issues", [])}
    if metric == "security_policy_bypass_check":
        if res.value.get("bypass_exists", False):
            path = " → ".join(res.value.get("bypass_path", []) or ["직접 경로"])
            return _format_text(metric, f"우회 경로 존재 (경로: {path})")
        return _format_text(metric, "우회 경로 없음 (정책 준수)")
    if metric == "bounded_path_length":
        return int(res.value.get("hops", 0))
    if metric == "link_failure_impact":
        return _format_text(metric, str(res.value.get("impact", "NONE")))
    if metric == "spof_detection":
        return res.value.get("spof_nodes", []) if res.status == "OK" else []
    if metric == "ospf_area0_routers":
        details = res.value.get("details", "")
        match = re.search(r'Backbone Routers: \d+ \(([^)]+)\)', details)
        if not match:
            return []
        routers_str = match.group(1).replace("...", "").strip()
        return [r.strip() for r in routers_str.split(',') if r.strip()]
    if metric == "redundant_paths_list":
        return res
    if metric == "root_cause_analysis":
        return _format_text(metric, str(res.value.get("blocking_point", "")))
    if metric == "node_failure_impact":
        return int(res.value.get("affected_count", 0))
    if metric == "redundancy_verification":
        isolated_count = int(res.value.get("isolated_flow_count", 0))
        return _format_text(metric, "없음" if isolated_count == 0 else f"{isolated_count}개")
    if metric == "triple_node_failure":
        iso_cnt = int(res.value.get("isolated_flow_count", 0))
        return _format_text(metric, "예, 완전 분리" if iso_cnt == 0 else f"아니오, {iso_cnt}개 흐름만 영향")
    if metric == "worst_case_failure_analysis":
        return _format_text(metric, f"{res.value.get('worst_node', 'NONE')} ({int(res.value.get('blocked_flow_count', 0))}개)")
    if metric == "non_existent_node_check":
        return 0
    if metric == "config_change_impact":
        changed = res.value.get("changed", False)
        affected = res.value.get("affected_flows", [])
        if not changed:
            return _format_text(metric, "NO_CHANGE")
        preview = ", ".join(affected[:3]) if affected else "-"
        return _format_text(metric, f"CHANGED ({len(affected)}건: {preview})")
    if metric == "differential_reachability":
        diff_count = int(res.value.get("diff_count", 0))
        flows = res.value.get("flows", [])
        if diff_count == 0:
            return _format_text(metric, "NO_DIFF")
        preview = ", ".join(flows[:3]) if flows else "-"
        return _format_text(metric, f"DIFF ({diff_count}건: {preview})")
    if metric == "policy_compliance_check":
        compliant = res.value.get("compliant", True)
        violations = res.value.get("violations", [])
        if compliant:
            return _format_text(metric, "COMPLIANT")
        preview = ", ".join(violations[:3]) if violations else "-"
        return _format_text(metric, f"VIOLATION: {preview}")
    if metric == "multi_link_failure_reachability":
        isolated = res.value.get("isolated", False)
        new_path = res.value.get("new_path", [])
        failure_reason = res.value.get("failure_reason", "")
        if isolated:
            return _format_text(metric, f"불가능 (원인: {failure_reason if failure_reason else '알 수 없음'})")
        path_str = " → ".join(new_path) if new_path else "대체경로 존재"
        return _format_text(metric, f"가능 (대체경로: {path_str})")
    return res.value if hasattr(res, 'value') else res


def _dispatch(builder: BatfishBuilder, metric: str, contract: Dict[str, Any], row_id: str) -> Any:
    query_contract = contract.get("query_contract", {})
    params = dict(query_contract.get("params", {}))
    replay_method = query_contract.get("replay_method", "")
    scenario = contract.get("scenario", {})
    base_snapshot = str(scenario.get("base_snapshot") or builder.snapshot_name)
    builder.bf.set_snapshot(base_snapshot)

    if metric in {"config_change_impact", "differential_reachability"} and scenario.get("fork_ops"):
        materialized = _materialize_snapshot(builder, scenario, row_id)
        if metric == "config_change_impact":
            params["after_snapshot"] = materialized
            params.setdefault("before_snapshot", base_snapshot)
        else:
            params["snapshot2"] = materialized
            params.setdefault("snapshot1", base_snapshot)
        builder.bf.set_snapshot(base_snapshot)

    if replay_method == "traceroute_path_set":
        return _replay_redundant_paths(builder, params["src_node"], params["dst_ip"])

    method = getattr(builder, replay_method)
    return method(**params)


def run_l45_replay_verification(lab_path: Path, dataset_path: Path, policies_path: Path, batfish_host: str = "localhost") -> List[Dict[str, Any]]:
    rows, _ = load_dataset(dataset_path)
    builder = BatfishBuilder(
        network_name="netconfig_qa",
        snapshot_path=str(lab_path),
        policies_path=str(policies_path),
        batfish_host=batfish_host,
        question_lang="ko",
    )
    if not builder.initialize():
        raise RuntimeError("Failed to initialize BatfishBuilder for Method 4")

    results: List[Dict[str, Any]] = []
    for row in rows:
        level = str(row.get("level", "")).upper()
        if level not in {"L4", "L5"}:
            continue

        contract = _ensure_contract(row, builder)
        metric = contract.get("metric", "")
        answer_type = str(row.get("answer_type", "text"))
        if contract.get("verification_status") == "quarantined":
            results.append({
                "id": row.get("id", ""),
                "id_v2": row.get("id_v2", ""),
                "level": level,
                "metric": metric,
                "answer_type": answer_type,
                "status": "QUARANTINED",
                "reason": contract.get("quarantine_reason", "missing_contract"),
                "replay_answer": "",
                "dataset_answer": row.get("answer", ""),
                "match": False,
                "score": 0.0,
                "detail": "",
            })
            continue

        try:
            replay_res = _dispatch(builder, metric, contract, str(row.get("id_v2", row.get("id", "row"))))
            actual = _format_answer(metric, replay_res, contract.get("query_contract", {}).get("params", {}))
            comparison = compare_answers(actual, row.get("answer"), answer_type)
            results.append({
                "id": row.get("id", ""),
                "id_v2": row.get("id_v2", ""),
                "level": level,
                "metric": metric,
                "answer_type": answer_type,
                "status": "MATCH" if comparison["match"] else "MISMATCH",
                "reason": "",
                "replay_answer": json.dumps(actual, ensure_ascii=False, sort_keys=True) if isinstance(actual, (dict, list, tuple, set)) else str(actual),
                "dataset_answer": row.get("answer", ""),
                "match": comparison["match"],
                "score": comparison.get("score", 0.0),
                "detail": comparison.get("detail", ""),
            })
        except Exception as e:
            results.append({
                "id": row.get("id", ""),
                "id_v2": row.get("id_v2", ""),
                "level": level,
                "metric": metric,
                "answer_type": answer_type,
                "status": "ERROR",
                "reason": f"replay_exception: {e}",
                "replay_answer": "",
                "dataset_answer": row.get("answer", ""),
                "match": False,
                "score": 0.0,
                "detail": str(e),
            })
    return results


def save_csv(results: List[Dict[str, Any]], path: Path) -> None:
    if not results:
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)


def generate_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    match_count = sum(1 for r in results if r["status"] == "MATCH")
    mismatch_count = sum(1 for r in results if r["status"] == "MISMATCH")
    error_count = sum(1 for r in results if r["status"] == "ERROR")
    quarantine_count = sum(1 for r in results if r["status"] == "QUARANTINED")
    by_level: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "match": 0, "mismatch": 0, "error": 0, "quarantined": 0})
    by_metric: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "match": 0, "mismatch": 0, "error": 0, "quarantined": 0})
    for r in results:
        by_level[r["level"]]["total"] += 1
        by_level[r["level"]][r["status"].lower() if r["status"] != "MATCH" else "match"] += 1
        by_metric[r["metric"]]["total"] += 1
        by_metric[r["metric"]][r["status"].lower() if r["status"] != "MATCH" else "match"] += 1
    return {
        "total": total,
        "match": match_count,
        "mismatch": mismatch_count,
        "error": error_count,
        "quarantined": quarantine_count,
        "agreement_rate": (match_count / total) if total else 0.0,
        "by_level": dict(by_level),
        "by_metric": dict(by_metric),
    }


def save_summary_json(summary: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def save_mismatch_report(results: List[Dict[str, Any]], path: Path) -> None:
    mismatches = [r for r in results if r["status"] in {"MISMATCH", "ERROR", "QUARANTINED"}]
    lines = ["# Method 4 L4/L5 Replay Mismatch Report", ""]
    if not mismatches:
        lines.append("All L4/L5 rows passed replay verification.")
    else:
        for row in mismatches:
            lines.extend([
                f"## {row['id_v2']}",
                f"- status: {row['status']}",
                f"- metric: {row['metric']}",
                f"- reason: {row['reason']}",
                f"- detail: {row['detail']}",
                f"- replay_answer: {row['replay_answer']}",
                f"- dataset_answer: {row['dataset_answer']}",
                "",
            ])
    path.write_text("\n".join(lines), encoding="utf-8")


def save_paper_dataset(dataset_path: Path, results: List[Dict[str, Any]], output_path: Path) -> Dict[str, int]:
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows = payload.get("questions", payload if isinstance(payload, list) else [])
    result_by_id = {r["id_v2"]: r for r in results}
    retained = []
    dropped = 0
    for row in rows:
        if str(row.get("level", "")).upper() not in {"L4", "L5"}:
            retained.append(row)
            continue
        result = result_by_id.get(row.get("id_v2", ""))
        if result and result.get("status") == "MATCH":
            row = dict(row)
            row["verification_status"] = "passed"
            retained.append(row)
        else:
            dropped += 1
    if isinstance(payload, dict):
        payload = dict(payload)
        payload["questions"] = retained
        payload.setdefault("meta", {})["paper_ready_filter"] = {"l45_retained": len([r for r in retained if str(r.get('level','')).upper() in {'L4','L5'}]), "l45_dropped": dropped}
    else:
        payload = retained
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"retained": len(retained), "dropped_l45": dropped}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Method 4 L4/L5 replay verification")
    parser.add_argument("--lab-path", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--policies", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--batfish-host", default="localhost")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = run_l45_replay_verification(Path(args.lab_path), Path(args.dataset), Path(args.policies), batfish_host=args.batfish_host)
    save_csv(results, output_dir / "l45_replay_results.csv")
    summary = generate_summary(results)
    save_summary_json(summary, output_dir / "l45_replay_summary.json")
    save_mismatch_report(results, output_dir / "l45_replay_mismatch.md")
    save_paper_dataset(Path(args.dataset), results, output_dir / "paper_ready_dataset.json")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
