from __future__ import annotations
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
from pathlib import Path

# ---- Level definitions for dataset generation ----
LEVEL_DEFINITIONS = {
    "L1": "단일 장비 설정값 조회",
    "L2": "복수 장비 설정값 집계",
    "L3": "복수 장비 + 계산/비교",
    "L4": "네트워크 흐름 도달성 (Batfish)",
    "L5": "What-If / Differential 분석 (Batfish)"
}

# ---- Allowed metrics by category ----
ALLOWED_METRICS = {
    # === L1: 단일 장비 설정값 조회 ===
    "System_Inventory": [
        "system_hostname_text", "system_version_text", "system_timezone_text",
        "system_user_list", "system_user_count", "logging_buffered_severity_text",
        "ntp_server_list", "snmp_community_list", "syslog_server_list"
    ],
    "Security_Inventory": [
        "ssh_present_bool", "ssh_version_text", "aaa_present_bool",
        "vty_transport_input_text", "vty_login_mode_text"
    ],
    "Interface_Inventory": [
        "interface_count", "interface_ip_map", "subinterface_count", "vrf_bind_map"
    ],
    "Routing_Inventory": [
        "bgp_local_as_numeric", "bgp_neighbor_count", "neighbor_list_ibgp", "neighbor_list_ebgp",
        "ospf_process_ids_set", "ospf_area_set", "ospf_area0_if_list"
    ],
    "Services_Inventory": [
        "vrf_names_set", "vrf_count", "vrf_rd_map", "rt_import_count", "rt_export_count",
        "mpls_ldp_present_bool", "l2vpn_pw_id_set"
    ],
    
    # === L2: 복수 장비 설정값 집계 ===
    "Security_Policy": [
        "ssh_enabled_devices", "ssh_missing_devices", "ssh_missing_count",
        "aaa_enabled_devices", "aaa_missing_devices", "devices_with_same_vrf"
    ],
    "OSPF_Consistency": [
        "ospf_area_membership", "ospf_area0_if_count"
    ],
    "L2VPN_Consistency": [
        "l2vpn_pairs", "l2vpn_unidirectional_pairs", "l2vpn_unidir_count",
        "l2vpn_pwid_mismatch_pairs", "l2vpn_mismatch_count"
    ],
    
    # === L3: 복수 장비 + 계산/검증 ===
    "BGP_Consistency": [
        "ibgp_fullmesh_ok", "ibgp_missing_pairs", "ibgp_missing_pairs_count",
        "ibgp_under_peered_devices", "ibgp_under_peered_count"
    ],
    "VRF_Consistency": [
        "vrf_without_rt_pairs", "vrf_without_rt_count",
        "vrf_interface_bind_count", "vrf_rt_list_per_device"
    ],
    
    # === L3: 장비 간 비교 분석 ===
    "Comparison_Analysis": [
        "compare_bgp_neighbor_count", "compare_interface_count", "compare_vrf_count",
        "compare_bgp_as", "max_interface_device", "max_bgp_peer_device",
        "all_devices_same_as", "compare_ospf_areas"
    ],
    
    # === L4/L5: Batfish 기반 (placeholder) ===
    "Reachability_Analysis": [
        "traceroute_path", "reachability_status", "acl_blocking_point"
    ],
    "What_If_Analysis": [
        "link_failure_impact", "config_change_impact", "policy_compliance_check"
    ]
}


def default_patterns(metric: str) -> str:
    """메트릭별 기본 질문 패턴"""
    table = {
        # === System_Inventory (L1) ===
        "system_hostname_text": "{host} 장비의 호스트네임은 무엇입니까?",
        "system_version_text": "{host} 장비의 운영체제(OS) 버전은 무엇입니까?",
        "system_timezone_text": "{host} 장비의 시간대(Timezone)는 무엇입니까?",
        "system_user_list": "{host} 장비에 등록된 로컬 사용자 목록을 알려주세요.",
        "system_user_count": "{host} 장비에 등록된 로컬 사용자는 총 몇 명입니까?",
        "logging_buffered_severity_text": "{host} 장비에서 logging buffered의 severity-level은 무엇입니까?",
        "ntp_server_list": "{host} 장비에 설정된 NTP 서버 목록을 알려주세요.",
        "snmp_community_list": "{host} 장비에 설정된 SNMP 커뮤니티 목록을 알려주세요.",
        "syslog_server_list": "{host} 장비에 설정된 Syslog 서버 목록을 알려주세요.",
        
        # === Security_Inventory (L1) ===
        "ssh_present_bool": "{host} 장비에 SSH가 활성화되어 있습니까? (true/false)",
        "ssh_version_text": "{host} 장비의 SSH 버전은 무엇입니까?",
        "aaa_present_bool": "{host} 장비에 AAA 기능이 설정되어 있습니까? (true/false)",
        "vty_transport_input_text": "{host} 장비의 VTY transport input 설정은 무엇입니까?",
        "vty_login_mode_text": "{host} 장비의 VTY line 로그인 방식은 무엇입니까?",
        
        # === Interface_Inventory (L1) ===
        "interface_count": "{host} 장비에 설정된 네트워크 인터페이스는 총 몇 개입니까?",
        "interface_ip_map": "{host} 장비의 각 인터페이스에 할당된 IP 주소를 알려주세요.",
        "subinterface_count": "{host} 장비에 설정된 서브인터페이스는 총 몇 개입니까?",
        "vrf_bind_map": "{host} 장비의 각 인터페이스별 VRF 바인딩 현황을 알려주세요.",
        
        # === Routing_Inventory (L1) ===
        "bgp_local_as_numeric": "{host} 장비의 BGP Local-AS 번호는 무엇입니까?",
        "bgp_neighbor_count": "{host} 장비의 BGP 피어(이웃)는 총 몇 개입니까?",
        "neighbor_list_ibgp": "{host} 장비와 iBGP로 연결된 피어들의 IP 주소 목록을 알려주세요.",
        "neighbor_list_ebgp": "{host} 장비와 eBGP로 연결된 피어들의 IP 주소 목록을 알려주세요.",
        "ospf_process_ids_set": "{host} 장비에 설정된 OSPF 프로세스 ID 목록을 알려주세요.",
        "ospf_area_set": "{host} 장비가 참여하는 OSPF Area 목록을 알려주세요.",
        "ospf_area0_if_list": "{host} 장비의 OSPF Area 0에 연결된 인터페이스 목록을 알려주세요.",
        
        # === Services_Inventory (L1) ===
        "vrf_names_set": "{host} 장비에 설정된 VRF 이름 목록을 알려주세요.",
        "vrf_count": "{host} 장비에 설정된 VRF는 총 몇 개입니까?",
        "vrf_rd_map": "{host} 장비에 설정된 VRF들의 이름과 RD(Route Distinguisher) 값을 함께 보여주세요.",
        "rt_import_count": "{host} 장비의 Route Target Import 설정은 총 몇 개입니까?",
        "rt_export_count": "{host} 장비의 Route Target Export 설정은 총 몇 개입니까?",
        "mpls_ldp_present_bool": "{host} 장비에서 MPLS LDP가 설정되어 있습니까? (true/false)",
        "l2vpn_pw_id_set": "{host} 장비에 설정된 L2VPN Pseudowire ID 목록을 알려주세요.",
        
        # === Security_Policy (L2) ===
        "ssh_enabled_devices": "SSH 접속이 가능한 장비 목록을 알려주세요.",
        "ssh_missing_devices": "SSH 접속이 불가능한 장비 목록을 알려주세요.",
        "ssh_missing_count": "SSH 접속이 불가능한 장비는 총 몇 대입니까?",
        "aaa_enabled_devices": "AAA 기능이 활성화된 장비 목록을 알려주세요.",
        "aaa_missing_devices": "AAA 기능이 비활성화된 장비 목록을 알려주세요.",
        "devices_with_same_vrf": "{vrf} VRF를 사용하는 장비 목록을 알려주세요.",
        
        # === OSPF_Consistency (L2) ===
        "ospf_area_membership": "OSPF Area {area}에 속한 장비 목록을 알려주세요.",
        "ospf_area0_if_count": "{host} 장비의 OSPF Area 0에 연결된 인터페이스는 총 몇 개입니까?",
        
        # === L2VPN_Consistency (L2/L3) ===
        "l2vpn_pairs": "구성된 L2VPN pseudowire 회선(장비쌍) 목록을 알려주세요.",
        "l2vpn_unidirectional_pairs": "단방향으로만 설정된 L2VPN 회선(장비쌍) 목록을 알려주세요.",
        "l2vpn_unidir_count": "단방향으로만 설정된 L2VPN 회선은 총 몇 개입니까?",
        "l2vpn_pwid_mismatch_pairs": "PW-ID가 불일치하는 L2VPN 회선(장비쌍) 목록을 알려주세요.",
        "l2vpn_mismatch_count": "PW-ID 불일치 또는 단방향 L2VPN 회선은 총 몇 개입니까?",
        
        # === BGP_Consistency (L3) ===
        "ibgp_fullmesh_ok": "AS {asn}의 iBGP Full-Mesh 구성은 완벽합니까? (true/false)",
        "ibgp_missing_pairs": "AS {asn}의 iBGP Full-Mesh에서 누락된 장비쌍 목록을 알려주세요.",
        "ibgp_missing_pairs_count": "AS {asn}의 iBGP Full-Mesh에서 누락된 링크는 총 몇 개입니까?",
        "ibgp_under_peered_devices": "AS {asn}에서 iBGP 피어 수가 부족한 장비 목록을 알려주세요.",
        "ibgp_under_peered_count": "AS {asn}에서 iBGP 피어 수가 부족한 장비는 총 몇 대입니까?",
        
        # === VRF_Consistency (L3) ===
        "vrf_without_rt_pairs": "route-target이 없는 VRF(장비/VRF) 목록을 알려주세요.",
        "vrf_without_rt_count": "route-target이 없는 VRF(장비/VRF)는 총 몇 개입니까?",
        "vrf_interface_bind_count": "{host} 장비의 {vrf} VRF에 바인딩된 인터페이스는 총 몇 개입니까?",
        "vrf_rt_list_per_device": "{host} 장비에 설정된 route-target(중복 제거) 전체 목록을 알려주세요.",
        
        # === Reachability_Analysis (L4) ===
        "traceroute_path": "{src_ip}에서 {dst_ip}까지의 네트워크 경로를 알려주세요.",
        "reachability_status": "{src_ip}에서 {dst_ip}:{dst_port}/{protocol}로 접근 가능합니까?",
        "acl_blocking_point": "{src_ip}에서 {dst_ip}로의 트래픽이 차단되는 지점은 어디입니까?",
        
        # === What_If_Analysis (L5) ===
        "link_failure_impact": "{link}가 다운되면 {src}에서 {dst}까지 도달 가능합니까?",
        "config_change_impact": "설정 변경 후 {src}에서 {dst}까지의 경로가 변경됩니까?",
        "policy_compliance_check": "네트워크 정책 '{policy_name}'을 준수하고 있습니까?",
        
        # === Comparison_Analysis (L3) ===
        "compare_bgp_neighbor_count": "{host1}과 {host2}의 BGP 피어 수가 같습니까?",
        "compare_interface_count": "{host1}과 {host2}의 인터페이스 수가 같습니까?",
        "compare_vrf_count": "{host1}과 {host2}의 VRF 수가 같습니까?",
        "compare_bgp_as": "{host1}과 {host2}가 같은 BGP AS에 속해 있습니까?",
        "compare_ospf_areas": "{host1}과 {host2}가 참여하는 OSPF Area가 동일합니까?",
        "max_interface_device": "인터페이스 수가 가장 많은 장비는 무엇입니까?",
        "max_bgp_peer_device": "BGP 피어가 가장 많은 장비는 무엇입니까?",
        "all_devices_same_as": "모든 장비가 같은 BGP AS에 속해 있습니까?"
    }
    return table.get(metric, f"{metric}에 대한 질문을 자연스럽게 작성해주세요.")


GOAL2METRICS = {
    "System_Inventory": {
        "extraction": [
            "system_hostname_text", "system_version_text", "system_timezone_text",
            "system_user_list", "system_user_count", "logging_buffered_severity_text",
            "ntp_server_list", "snmp_community_list", "syslog_server_list"
        ]
    },
    "Security_Inventory": {
        "extraction": [
            "ssh_present_bool", "ssh_version_text", "aaa_present_bool",
            "vty_transport_input_text", "vty_login_mode_text"
        ]
    },
    "Interface_Inventory": {
        "extraction": [
            "interface_count", "interface_ip_map", "subinterface_count", "vrf_bind_map"
        ]
    },
    "Routing_Inventory": {
        "extraction": [
            "bgp_local_as_numeric", "bgp_neighbor_count", "neighbor_list_ibgp", "neighbor_list_ebgp",
            "ospf_process_ids_set", "ospf_area_set", "ospf_area0_if_list"
        ]
    },
    "Services_Inventory": {
        "extraction": [
            "vrf_names_set", "vrf_count", "vrf_rd_map", "rt_import_count", "rt_export_count",
            "mpls_ldp_present_bool", "l2vpn_pw_id_set"
        ]
    },
    "Security_Policy": {
        "compliance": [
            "ssh_enabled_devices", "ssh_missing_devices", "ssh_missing_count",
            "aaa_enabled_devices", "aaa_missing_devices", "devices_with_same_vrf"
        ]
    },
    "OSPF_Consistency": {
        "consistency": ["ospf_area_membership", "ospf_area0_if_count"]
    },
    "L2VPN_Consistency": {
        "visibility": ["l2vpn_pairs"],
        "consistency": [
            "l2vpn_unidirectional_pairs", "l2vpn_unidir_count",
            "l2vpn_pwid_mismatch_pairs", "l2vpn_mismatch_count"
        ]
    },
    "BGP_Consistency": {
        "consistency": [
            "ibgp_fullmesh_ok", "ibgp_missing_pairs", "ibgp_missing_pairs_count",
            "ibgp_under_peered_devices", "ibgp_under_peered_count"
        ]
    },
    "VRF_Consistency": {
        "consistency": [
            "vrf_without_rt_pairs", "vrf_without_rt_count",
            "vrf_interface_bind_count", "vrf_rt_list_per_device"
        ]
    },
    "Comparison_Analysis": {
        "comparison": [
            "compare_bgp_neighbor_count", "compare_interface_count", "compare_vrf_count",
            "compare_bgp_as", "compare_ospf_areas"
        ],
        "aggregation": [
            "max_interface_device", "max_bgp_peer_device", "all_devices_same_as"
        ]
    },
    "Reachability_Analysis": {
        "reachability": ["traceroute_path", "reachability_status", "acl_blocking_point"]
    },
    "What_If_Analysis": {
        "what_if": ["link_failure_impact"],
        "differential": ["config_change_impact"],
        "compliance": ["policy_compliance_check"]
    }
}

SCOPE_HINT = {
    "GLOBAL":      ({"type": "GLOBAL"}, []),
    "AS":          ({"type": "AS", "asn": "{asn}"}, ["asn"]),
    "DEVICE":      ({"type": "DEVICE", "host": "{host}"}, ["host"]),
    "VRF":         ({"type": "VRF", "vrf": "{vrf}"}, ["vrf"]),
    "DEVICE_VRF":  ({"type": "DEVICE_VRF", "host": "{host}", "vrf": "{vrf}"}, ["host", "vrf"]),
    "DEVICE_IF":   ({"type": "DEVICE_IF", "host": "{host}", "if": "{if}"}, ["host", "if"]),
    "DEVICE_PAIR": ({"type": "DEVICE_PAIR", "host1": "{host1}", "host2": "{host2}"}, ["host1", "host2"]),
    "OSPF_AREA":   ({"type": "OSPF_AREA", "area": "{area}"}, ["area"]),
    "FLOW":        ({"type": "FLOW", "src_ip": "{src_ip}", "dst_ip": "{dst_ip}"}, ["src_ip", "dst_ip"]),
    "LINK_FAILURE": ({"type": "LINK_FAILURE", "link": "{link}"}, ["link"]),
    "CONFIG_CHANGE": ({"type": "CONFIG_CHANGE"}, []),
    "POLICY":      ({"type": "POLICY", "policy_name": "{policy_name}"}, ["policy_name"])
}

METRIC_AGG = {
    # === L1 metrics ===
    "system_hostname_text": "text",
    "system_version_text": "text",
    "system_timezone_text": "text",
    "system_user_list": "set",
    "system_user_count": "numeric",
    "logging_buffered_severity_text": "text",
    "ntp_server_list": "set",
    "snmp_community_list": "set",
    "syslog_server_list": "set",
    "ssh_present_bool": "boolean",
    "ssh_version_text": "text",
    "aaa_present_bool": "boolean",
    "vty_transport_input_text": "text",
    "vty_login_mode_text": "text",
    "interface_count": "numeric",
    "interface_ip_map": "map",
    "subinterface_count": "numeric",
    "vrf_bind_map": "map",
    "bgp_local_as_numeric": "numeric",
    "bgp_neighbor_count": "numeric",
    "neighbor_list_ibgp": "set",
    "neighbor_list_ebgp": "set",
    "ospf_process_ids_set": "set",
    "ospf_area_set": "set",
    "ospf_area0_if_list": "set",
    "vrf_names_set": "set",
    "vrf_count": "numeric",
    "vrf_rd_map": "map",
    "rt_import_count": "numeric",
    "rt_export_count": "numeric",
    "mpls_ldp_present_bool": "boolean",
    "l2vpn_pw_id_set": "set",
    
    # === L2 metrics ===
    "ssh_enabled_devices": "set",
    "ssh_missing_devices": "set",
    "ssh_missing_count": "numeric",
    "aaa_enabled_devices": "set",
    "aaa_missing_devices": "set",
    "devices_with_same_vrf": "set",
    "ospf_area_membership": "set",
    "ospf_area0_if_count": "numeric",
    "l2vpn_pairs": "set",
    
    # === L3 metrics ===
    "ibgp_fullmesh_ok": "boolean",
    "ibgp_missing_pairs": "set",
    "ibgp_missing_pairs_count": "numeric",
    "ibgp_under_peered_devices": "set",
    "ibgp_under_peered_count": "numeric",
    "vrf_without_rt_pairs": "set",
    "vrf_without_rt_count": "numeric",
    "vrf_interface_bind_count": "numeric",
    "vrf_rt_list_per_device": "set",
    "l2vpn_unidirectional_pairs": "set",
    "l2vpn_unidir_count": "numeric",
    "l2vpn_pwid_mismatch_pairs": "set",
    "l2vpn_mismatch_count": "numeric",
    
    # === L3 comparison metrics ===
    "compare_bgp_neighbor_count": "boolean",
    "compare_interface_count": "boolean",
    "compare_vrf_count": "boolean",
    "compare_bgp_as": "boolean",
    "compare_ospf_areas": "boolean",
    "max_interface_device": "text",
    "max_bgp_peer_device": "text",
    "all_devices_same_as": "boolean",
    
    # === L4/L5 metrics (Batfish) ===
    "traceroute_path": "set",
    "reachability_status": "boolean",
    "acl_blocking_point": "text",
    "link_failure_impact": "boolean",
    "config_change_impact": "boolean",
    "policy_compliance_check": "boolean"
}

CANDIDATES = {
    "System_Inventory": [
        ("system_hostname_text", "text"),
        ("system_user_count", "numeric"),
        ("ntp_server_list", "set"),
    ],
    "Security_Inventory": [
        ("ssh_present_bool", "boolean"),
        ("ssh_version_text", "text"),
    ],
    "Interface_Inventory": [
        ("interface_count", "numeric"),
        ("interface_ip_map", "map"),
    ],
    "Routing_Inventory": [
        ("bgp_neighbor_count", "numeric"),
        ("ospf_area_set", "set"),
    ],
    "Services_Inventory": [
        ("vrf_names_set", "set"),
        ("vrf_rd_map", "map"),
        ("mpls_ldp_present_bool", "boolean"),
    ],
    "Security_Policy": [
        ("ssh_missing_count", "numeric"),
        ("ssh_enabled_devices", "set"),
    ],
    "OSPF_Consistency": [
        ("ospf_area0_if_count", "numeric"),
        ("ospf_area_membership", "set"),
    ],
    "BGP_Consistency": [
        ("ibgp_fullmesh_ok", "boolean"),
        ("ibgp_missing_pairs", "set"),
        ("ibgp_missing_pairs_count", "numeric"),
    ],
    "VRF_Consistency": [
        ("vrf_without_rt_pairs", "set"),
        ("vrf_without_rt_count", "numeric"),
    ],
    "L2VPN_Consistency": [
        ("l2vpn_unidirectional_pairs", "set"),
        ("l2vpn_mismatch_count", "numeric"),
    ],
}


def normalize_to_plain_text(data: Any) -> str:
    """모든 데이터 타입을 '정규화된 평문'으로 변환합니다."""
    if data is None:
        return ""

    if isinstance(data, list):
        str_items = sorted(list(set(map(str, data))))
        return ", ".join(str_items)

    if isinstance(data, dict):
        sorted_items = sorted(data.items())
        return ", ".join([f"{k}: {v}" for k, v in sorted_items])

    return str(data)


def _allowed(cat: str, metric: str) -> bool:
    return metric in (ALLOWED_METRICS.get(cat) or [])


def _mk(metric: str, agg: str, cat: str) -> Dict[str, Any]:
    scope = {"type": "GLOBAL"}
    placeholders = []
    
    # Device-level metrics
    device_metrics = [
        "system_hostname_text", "system_version_text", "system_timezone_text",
        "system_user_list", "system_user_count", "logging_buffered_severity_text",
        "ntp_server_list", "snmp_community_list", "syslog_server_list",
        "ssh_present_bool", "ssh_version_text", "aaa_present_bool",
        "vty_transport_input_text", "vty_login_mode_text",
        "interface_count", "interface_ip_map", "subinterface_count", "vrf_bind_map",
        "bgp_local_as_numeric", "bgp_neighbor_count", "neighbor_list_ibgp", "neighbor_list_ebgp",
        "ospf_process_ids_set", "ospf_area_set", "ospf_area0_if_list", "ospf_area0_if_count",
        "vrf_names_set", "vrf_count", "vrf_rd_map", "rt_import_count", "rt_export_count",
        "mpls_ldp_present_bool", "l2vpn_pw_id_set", "vrf_rt_list_per_device"
    ]
    
    if metric in device_metrics:
        scope = {"type": "DEVICE", "host": "{host}"}
        placeholders = ["host"]
    elif "ibgp" in metric:
        scope = {"type": "AS", "asn": "{asn}"}
        placeholders = ["asn"]
    elif metric == "vrf_interface_bind_count":
        scope = {"type": "DEVICE_VRF", "host": "{host}", "vrf": "{vrf}"}
        placeholders = ["host", "vrf"]
    elif metric == "devices_with_same_vrf":
        scope = {"type": "VRF", "vrf": "{vrf}"}
        placeholders = ["vrf"]
    elif metric == "ospf_area_membership":
        scope = {"type": "OSPF_AREA", "area": "{area}"}
        placeholders = ["area"]
        
    return {
        "id": metric.upper(),
        "category": cat,
        "intent": {"metric": metric, "scope": scope, "aggregation": agg, "placeholders": placeholders},
        "pattern": default_patterns(metric)
    }


def _count_agg(items: List[Dict[str, Any]]) -> Dict[str, int]:
    cnt = {"boolean": 0, "numeric": 0, "set": 0, "map": 0, "text": 0}
    for it in items:
        a = (it.get("intent") or {}).get("aggregation")
        if a in cnt:
            cnt[a] += 1
    return cnt


def fix_coverage_budget(dsl: List[Dict[str, Any]], budget: Dict[str, int]) -> List[Dict[str, Any]]:
    by_cat = {}
    for t in dsl:
        by_cat.setdefault(t["category"], []).append(t)
    out = list(dsl)
    for cat, items in by_cat.items():
        need = dict(budget or {"boolean": 1, "set": 1, "numeric": 1, "map": 1})
        have = _count_agg(items)
        for k in list(need.keys()):
            need[k] = max(0, need.get(k, 0) - have.get(k, 0))
        for metric, agg in CANDIDATES.get(cat, []):
            if need.get(agg, 0) <= 0:
                continue
            out.append(_mk(metric, agg, cat))
            need[agg] -= 1
            if all(v <= 0 for v in need.values()):
                break
    return out


@dataclass
class RuleBasedGeneratorConfig:
    policies_path: str
    min_per_cat: int = 4
    scenario_type: str = "normal"


class RuleBasedGenerator:
    def __init__(self, cfg: RuleBasedGeneratorConfig):
        self.cfg = cfg
        self._bundle = json.loads(
            Path(self.cfg.policies_path).read_text(encoding="utf-8"))
        self.defaults = self._bundle.get("defaults", {})
        self.policies = self._bundle.get("policies", [])

    def compile(
        self,
        capabilities: Dict[str, Any],
        categories: List[str],
        scenario_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """정책 기반 DSL 생성"""

        dsl: List[Dict[str, Any]] = []
        scen = (scenario_type or self.cfg.scenario_type or "normal").lower()
        label_map = {"normal": "정상", "failure": "장애", "expansion": "확장"}
        scen_label = label_map.get(scen, scen)
        prefix = f"[{scen_label}] " if scen_label else ""

        for pol in self.policies:
            cat = pol["category"]
            if cat not in categories:
                continue
            levels = pol.get("levels", {})
            if isinstance(levels, list):
                levels = {"L2": levels}
            for lvl, items in levels.items():
                for it in items:
                    goal = it.get("goal")
                    targets = it.get("targets", ["GLOBAL"])
                    primary_metric = it.get("primary_metric")
                    conditions = it.get("conditions")
                    notes = it.get("notes")

                    # Merge primary_metric + GOAL2METRICS[goal]
                    merged_metrics: List[str] = []
                    if primary_metric and _allowed(cat, primary_metric):
                        merged_metrics.append(primary_metric)
                    for m in GOAL2METRICS.get(cat, {}).get(goal, []) or []:
                        if _allowed(cat, m) and m not in merged_metrics:
                            merged_metrics.append(m)

                    for metric in merged_metrics:
                        patt = default_patterns(metric)
                        agg = METRIC_AGG.get(metric, "set")
                        for tgt in targets:
                            scope, placeholders = SCOPE_HINT.get(
                                tgt, SCOPE_HINT["GLOBAL"])
                            dsl.append({
                                "id": metric.upper(),
                                "category": cat,
                                "intent": {
                                    "metric": metric,
                                    "scope": scope,
                                    "aggregation": agg,
                                    "placeholders": placeholders
                                },
                                "pattern": f"{prefix}{patt}".strip(),
                                "scenario": scen_label,
                                "level": lvl,
                                "goal": goal,
                                "policy_hints": {
                                    "primary_metric": primary_metric,
                                    "conditions": conditions,
                                    "notes": notes
                                },
                                "origin": "Universal"
                            })

        # 얕은 중복 제거
        import json as _json
        seen = set()
        out = []
        for t in dsl:
            key = (t["category"], t["intent"]["metric"], _json.dumps(
                t["intent"]["scope"], sort_keys=True, ensure_ascii=False))
            if key in seen:
                continue
            seen.add(key)
            out.append(t)
        return out
