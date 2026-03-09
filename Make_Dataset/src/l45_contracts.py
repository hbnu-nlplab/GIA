from __future__ import annotations

import re
from typing import Any, Dict


def _node_ip(builder: Any, node: str) -> str:
    if not node:
        return ""
    ips = getattr(builder, "node_ips", {}).get(node, [])
    return ips[0] if ips else ""


def _parse_evidence(question: Dict[str, Any]) -> Dict[str, Any]:
    evidence = question.get("evidence_hint", {})
    return evidence if isinstance(evidence, dict) else {}


def _scope(question: Dict[str, Any]) -> Dict[str, Any]:
    ev = _parse_evidence(question)
    scope = ev.get("scope", {})
    return dict(scope) if isinstance(scope, dict) else {}


def _metric(question: Dict[str, Any]) -> str:
    ev = _parse_evidence(question)
    metric = str(ev.get("metric", "")).strip()
    return metric or str(question.get("metric", "")).strip()


def _default_scenario(builder: Any) -> Dict[str, Any]:
    return {
        "base_snapshot": getattr(builder, "snapshot_name", "baseline"),
        "fork_ops": [],
    }


def _answer_shape(question: Dict[str, Any]) -> str:
    return str(question.get("answer_type", "text")).strip().lower() or "text"


def _parse_reachability_from_question(question_text: str) -> Dict[str, Any]:
    text = str(question_text or "")
    match = re.search(r"\((\d+)\/([A-Za-z]+)\)", text)
    if not match:
        return {}
    return {"dst_port": int(match.group(1)), "protocol": match.group(2).upper()}


def build_l45_contract(question: Dict[str, Any], builder: Any) -> Dict[str, Any]:
    metric = _metric(question)
    scope = _scope(question)
    scenario = _default_scenario(builder)
    answer_shape = _answer_shape(question)

    query_contract: Dict[str, Any] = {"replay_method": "", "params": {}}
    quarantine_reason = ""

    if metric == "traceroute_path":
        src = scope.get("src", "")
        dst = scope.get("dst", "")
        dst_ip = _node_ip(builder, dst)
        query_contract = {
            "replay_method": "traceroute_path",
            "params": {"src_location": src, "dst_ip": dst_ip, "target_name": dst},
        }
        if not src or not dst_ip:
            quarantine_reason = "missing_src_or_dst_ip"

    elif metric == "reachability_status":
        parsed = _parse_reachability_from_question(question.get("question", ""))
        scope.setdefault("dst_port", parsed.get("dst_port", scope.get("dst_port", 0)))
        scope.setdefault("protocol", parsed.get("protocol", scope.get("protocol", "TCP")))
        query_contract = {
            "replay_method": "reachability_status",
            "params": {
                "src_ip": scope.get("src_ip", ""),
                "dst_ip": scope.get("dst_ip", ""),
                "dst_port": int(scope.get("dst_port", 0) or 0),
                "protocol": str(scope.get("protocol", "TCP") or "TCP").upper(),
            },
        }
        if not scope.get("src_ip") or not scope.get("dst_ip"):
            quarantine_reason = "missing_flow_ips"

    elif metric == "acl_blocking_point":
        query_contract = {
            "replay_method": "acl_blocking_point",
            "params": {
                "src_ip": scope.get("src_ip", ""),
                "dst_ip": scope.get("dst_ip", ""),
                "dst_port": int(scope.get("dst_port", 80) or 80),
            },
        }
        if not scope.get("src_ip") or not scope.get("dst_ip"):
            quarantine_reason = "missing_flow_ips"

    elif metric == "loop_detection":
        query_contract = {"replay_method": "loop_detection", "params": {}}

    elif metric == "blackhole_destination_list":
        query_contract = {
            "replay_method": "blackhole_detection",
            "params": {"dst_prefix": scope.get("dst_prefix", "0.0.0.0/0")},
        }

    elif metric == "waypoint_traversal_path":
        query_contract = {
            "replay_method": "waypoint_check",
            "params": {
                "src_ip": scope.get("src", ""),
                "dst_ip": scope.get("dst", ""),
                "waypoint_node": scope.get("waypoint", ""),
            },
        }
        if not scope.get("src") or not scope.get("dst") or not scope.get("waypoint"):
            quarantine_reason = "missing_waypoint_scope"

    elif metric == "leaked_prefixes_list":
        query_contract = {
            "replay_method": "isolation_check",
            "params": {"vrf1": scope.get("vrf1", ""), "vrf2": scope.get("vrf2", "")},
        }
        if not scope.get("vrf1") or not scope.get("vrf2"):
            quarantine_reason = "missing_vrf_pair"

    elif metric == "asymmetric_path_comparison":
        query_contract = {
            "replay_method": "asymmetric_path_check",
            "params": {"node1": scope.get("node1", ""), "node2": scope.get("node2", "")},
        }
        if not scope.get("node1") or not scope.get("node2"):
            quarantine_reason = "missing_node_pair"

    elif metric == "ospf_compatibility_check":
        query_contract = {
            "replay_method": "ospf_compatibility_check",
            "params": {"node1": scope.get("node1", ""), "node2": scope.get("node2", "")},
        }
        if not scope.get("node1") or not scope.get("node2"):
            quarantine_reason = "missing_node_pair"

    elif metric == "security_policy_bypass_check":
        query_contract = {
            "replay_method": "security_policy_bypass_check",
            "params": {
                "src_node": scope.get("src", ""),
                "dst_node": scope.get("dst", ""),
                "required_waypoint": scope.get("waypoint", ""),
            },
        }
        if not scope.get("src") or not scope.get("dst") or not scope.get("waypoint"):
            quarantine_reason = "missing_security_policy_scope"

    elif metric == "bounded_path_length":
        src = scope.get("src", "")
        dst = scope.get("dst", "")
        dst_ip = _node_ip(builder, dst)
        query_contract = {
            "replay_method": "bounded_path_length",
            "params": {"src_location": src, "dst_ip": dst_ip, "max_hops": 5},
        }
        if not src or not dst_ip:
            quarantine_reason = "missing_src_or_dst_ip"

    elif metric == "link_failure_impact":
        query_contract = {
            "replay_method": "link_failure_impact",
            "params": {
                "node1": scope.get("node1", ""),
                "node2": scope.get("node2", ""),
                "test_src": scope.get("src", ""),
                "test_dst": scope.get("dst", ""),
            },
        }
        if not all(scope.get(k) for k in ("node1", "node2", "src", "dst")):
            quarantine_reason = "missing_link_failure_scope"

    elif metric == "spof_detection":
        query_contract = {"replay_method": "spof_detection", "params": {}}

    elif metric == "ospf_area0_routers":
        query_contract = {"replay_method": "ospf_backbone_contiguity", "params": {}}

    elif metric == "redundant_paths_list":
        src = scope.get("src", "")
        dst = scope.get("dst", "")
        dst_ip = _node_ip(builder, dst)
        query_contract = {
            "replay_method": "traceroute_path_set",
            "params": {"src_node": src, "dst_node": dst, "dst_ip": dst_ip},
        }
        if not src or not dst_ip:
            quarantine_reason = "missing_redundant_path_scope"

    elif metric == "root_cause_analysis":
        query_contract = {
            "replay_method": "root_cause_analysis",
            "params": {"src_node": scope.get("src", ""), "dst_node": scope.get("dst", "")},
        }
        if not scope.get("src") or not scope.get("dst"):
            quarantine_reason = "missing_node_pair"

    elif metric == "node_failure_impact":
        query_contract = {
            "replay_method": "blast_radius_estimation",
            "params": {"failed_node": scope.get("node", "")},
        }
        if not scope.get("node"):
            quarantine_reason = "missing_node"

    elif metric == "redundancy_verification":
        nodes = scope.get("nodes", [])
        if not nodes and scope.get("src") and scope.get("dst"):
            nodes = [scope.get("src"), scope.get("dst")]
        query_contract = {
            "replay_method": "redundancy_verification",
            "params": {"node1": nodes[0] if len(nodes) > 0 else "", "node2": nodes[1] if len(nodes) > 1 else ""},
        }
        if len(nodes) < 2:
            quarantine_reason = "missing_redundancy_nodes"

    elif metric == "triple_node_failure":
        nodes = scope.get("nodes", [])
        query_contract = {
            "replay_method": "triple_node_failure",
            "params": {
                "node1": nodes[0] if len(nodes) > 0 else "",
                "node2": nodes[1] if len(nodes) > 1 else "",
                "node3": nodes[2] if len(nodes) > 2 else "",
            },
        }
        if len(nodes) < 3:
            quarantine_reason = "missing_triplet_nodes"

    elif metric == "worst_case_failure_analysis":
        query_contract = {
            "replay_method": "find_worst_failure_node",
            "params": {"candidate_nodes": list(getattr(builder, "nodes", [])[:10])},
        }

    elif metric == "non_existent_node_check":
        query_contract = {
            "replay_method": "check_non_existent_node",
            "params": {"node_name": scope.get("node", "non_existent_router_999")},
        }

    elif metric == "config_change_impact":
        failure_node = scope.get("failure_node", "")
        if failure_node:
            scenario["fork_ops"] = [{"type": "deactivate_nodes", "nodes": [failure_node]}]
        query_contract = {
            "replay_method": "config_change_impact",
            "params": {
                "before_snapshot": scope.get("base_snapshot", getattr(builder, "snapshot_name", "baseline")),
                "after_snapshot": scope.get("changed_snapshot", getattr(builder, "snapshot_name", "baseline")),
                "src_node": scope.get("src", ""),
                "dst_node": scope.get("dst", ""),
            },
        }
        if not scope.get("src") or not scope.get("dst"):
            quarantine_reason = "missing_snapshot_diff_scope"

    elif metric == "differential_reachability":
        failure_node = scope.get("failure_node", "")
        if failure_node:
            scenario["fork_ops"] = [{"type": "deactivate_nodes", "nodes": [failure_node]}]
        query_contract = {
            "replay_method": "differential_reachability",
            "params": {
                "snapshot1": scope.get("base_snapshot", getattr(builder, "snapshot_name", "baseline")),
                "snapshot2": scope.get("changed_snapshot", getattr(builder, "snapshot_name", "baseline")),
                "src_node": scope.get("src", ""),
                "dst_ip": scope.get("dst_ip", _node_ip(builder, scope.get("dst", ""))),
            },
        }
        if not scope.get("src") or not query_contract["params"]["dst_ip"]:
            quarantine_reason = "missing_differential_scope"

    elif metric == "policy_compliance_check":
        query_contract = {
            "replay_method": "policy_compliance_check",
            "params": {
                "policy_type": "waypoint",
                "waypoint_node": str(question.get("id", "")).replace("POLICY_COMPLIANCE_", "", 1).strip(),
                "policy_name": scope.get("policy_name", ""),
            },
        }
        if not query_contract["params"]["waypoint_node"]:
            quarantine_reason = "missing_policy_waypoint"

    elif metric == "multi_link_failure_reachability":
        query_contract = {
            "replay_method": "multi_link_failure_analysis",
            "params": {
                "link1_iface1": scope.get("link1_iface1", ""),
                "link1_iface2": scope.get("link1_iface2", ""),
                "link2_iface1": scope.get("link2_iface1", ""),
                "link2_iface2": scope.get("link2_iface2", ""),
                "test_src": scope.get("test_src", ""),
                "test_dst": scope.get("test_dst", ""),
            },
        }
        if not all(query_contract["params"].values()):
            quarantine_reason = "missing_multi_link_scope"

    else:
        quarantine_reason = f"unsupported_metric:{metric or 'missing'}"

    verification_status = "quarantined" if quarantine_reason else "pending"
    return {
        "metric": metric,
        "scope": scope,
        "scenario": scenario,
        "query_contract": query_contract,
        "verification_contract": {
            "answer_shape": answer_shape,
            "compare_mode": "canonical",
        },
        "oracle_source": "batfish_replay",
        "verification_status": verification_status,
        "quarantine_reason": quarantine_reason,
    }
