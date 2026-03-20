"""
Add question_type field to every metric in policies.json.
Rules based on metric name, level, and answer_type.
"""

import json
import sys

POLICIES_PATH = "/home/sdlab08/projects/GIA/Make_Dataset/policies.json"

# Explicit overrides for specific metrics (name → question_type)
EXPLICIT_MAP = {
    # identification
    "system_hostname_text": "identification",
    "system_version_text": "identification",
    "system_timezone_text": "identification",
    "domain_name_text": "identification",
    "bgp_local_as_numeric": "identification",
    "logging_buffered_severity_text": "identification",

    # enumeration
    "system_user_list": "enumeration",
    "ntp_server_list": "enumeration",
    "snmp_community_list": "enumeration",
    "syslog_server_list": "enumeration",
    "ospf_process_ids_set": "enumeration",
    "neighbor_list_ibgp": "enumeration",
    "neighbor_list_ebgp": "enumeration",
    "ssh_enabled_devices": "enumeration",
    "interface_list": "enumeration",
    "vrf_list": "enumeration",

    # counting
    "system_user_count": "counting",
    "interface_count": "counting",
    "bgp_neighbor_count": "counting",
    "vrf_count": "counting",
    "ssh_missing_count": "counting",
    "ospf_area0_if_count": "counting",

    # comparison
    "compare_bgp_as": "comparison",
    "compare_ospf_areas": "comparison",
    "bgp_as_distribution": "comparison",
    "all_devices_same_as": "comparison",
    "ibgp_missing_pairs": "comparison",
    "ibgp_under_peered_devices": "comparison",
    "vrf_without_rt_pairs": "comparison",
    "ospf_compatibility_check": "comparison",
    "max_interface_device": "comparison",
    "min_interface_device": "comparison",

    # impact_analysis
    "link_failure_impact": "impact_analysis",
    "spof_detection": "impact_analysis",
    "node_failure_impact": "impact_analysis",
    "redundancy_verification": "impact_analysis",
    "triple_node_failure": "impact_analysis",
    "worst_case_failure_analysis": "impact_analysis",
    "non_existent_node_check": "impact_analysis",
}

# Keywords in metric name → question_type
NAME_KEYWORD_MAP = [
    # Most specific first
    (["traceroute", "reachability", "path", "route_trace", "loop_detect",
      "blackhole", "acl_analysis", "reach"], "reachability"),
    (["failure_impact", "spof", "node_failure", "redundancy", "triple_node",
      "worst_case", "non_existent", "link_failure", "what_if", "differential",
      "fault_inject"], "impact_analysis"),
    (["ibgp_missing", "ibgp_under", "missing_pairs", "distribution",
      "all_devices", "compare_", "compatibility", "max_interface", "min_interface",
      "vrf_without_rt"], "comparison"),
    (["_count", "_missing_count", "_num"], "counting"),
    (["_list", "_set", "_ids", "_devices", "_pairs"], "enumeration"),
    (["configured", "_ok", "_enabled", "_disabled", "cdp_", "ssh_configured",
      "ntp_configured", "syslog_configured", "fullmesh"], "validation"),
]


def infer_question_type(name: str, level: str, answer_type: str) -> str:
    """Determine question_type via explicit map, name keywords, then fallback rules."""

    # 1. Explicit override
    if name in EXPLICIT_MAP:
        return EXPLICIT_MAP[name]

    # 2. Level-based rules first for L4/L5/L6
    if level == "L4":
        return "reachability"
    if level in ("L5", "L6"):
        return "impact_analysis"

    # 3. Name keyword scan
    name_lower = name.lower()
    for keywords, qtype in NAME_KEYWORD_MAP:
        if any(kw in name_lower for kw in keywords):
            return qtype

    # 4. Fallback: answer_type + level
    if answer_type == "bool":
        return "validation"
    if answer_type in ("text", "scalar_str"):
        return "identification"
    if answer_type == "set_str":
        if level in ("L2", "L3"):
            return "comparison"
        return "enumeration"
    if answer_type == "scalar_int":
        if level in ("L2", "L3"):
            return "comparison"
        return "counting"
    if answer_type in ("map_str_int", "map_str_str", "map"):
        if level in ("L2", "L3"):
            return "comparison"
        return "enumeration"

    # Ultimate fallback
    return "identification"


def main():
    with open(POLICIES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    metrics = data.get("metrics_metadata", {})
    if not isinstance(metrics, dict):
        print("ERROR: metrics_metadata is not a dict", file=sys.stderr)
        sys.exit(1)

    counts = {}
    for name, metric in metrics.items():
        level = metric.get("level", "L1")
        answer_type = metric.get("answer_type", "text")
        qt = infer_question_type(name, level, answer_type)
        metric["question_type"] = qt
        counts[qt] = counts.get(qt, 0) + 1

    with open(POLICIES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    print(f"Done. {len(metrics)} metrics updated.")
    print("Distribution:")
    for qt, cnt in sorted(counts.items()):
        print(f"  {qt}: {cnt}")


if __name__ == "__main__":
    main()
