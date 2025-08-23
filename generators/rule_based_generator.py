from __future__ import annotations
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
from pathlib import Path

# ---- allowed metrics + default patterns (from legacy synthesizer) ----
ALLOWED_METRICS = {
    "BGP_Consistency": [
        "ibgp_fullmesh_ok","ibgp_missing_pairs","ibgp_under_peered_devices","ibgp_under_peered_count","ibgp_missing_pairs_count",
        "neighbor_list_ibgp","neighbor_list_ebgp","ebgp_remote_as_map","ibgp_update_source_missing_set",
    ],
    "VRF_Consistency": [
        "vrf_rd_map","vrf_rt_list_per_device","vrf_without_rt_pairs","vrf_without_rt_count","vrf_interface_bind_count","vrf_rd_format_invalid_set",
    ],
    "L2VPN_Consistency": [
        "l2vpn_pairs","l2vpn_unidirectional_pairs","l2vpn_unidir_count","l2vpn_pwid_mismatch_pairs","l2vpn_mismatch_count",
    ],
    "OSPF_Consistency": [
        "ospf_proc_ids","ospf_area0_if_list","ospf_area0_if_count",
    ],
    "Security_Policy": [
        "ssh_enabled_devices","ssh_missing_devices","ssh_missing_count","aaa_enabled_devices","aaa_missing_devices",
    ],
    "Interface_Inventory": [
        "interface_count","interface_ip_map","interface_vlan_set","subinterface_count","vrf_bind_map"
    ],
    "Routing_Inventory": [
        "bgp_local_as_numeric","bgp_neighbor_count","ospf_area_set","ospf_process_ids_set"
    ],
    "Security_Inventory": [
        "aaa_present_bool","password_policy_present_bool","ssh_present_bool","ssh_version_text"
    ],
    "Services_Inventory": [
        "l2vpn_pw_id_set","mpls_ldp_present_bool","rt_export_count","rt_import_count","vrf_count","vrf_names_set","vrf_rd_map"
    ],
    "System_Inventory": [
        "system_hostname_text","system_timezone_text","system_user_count","system_user_list","system_version_text"
    ],
    # ---- New: Basic info sanity checks ----
    "Basic_Info": [
        "system_hostname_text","system_mgmt_address_text","system_version_text","ios_config_register_text",
        "logging_buffered_severity_text","http_server_enabled_bool","ip_forward_protocol_nd_bool","ip_cef_enabled_bool",
        "vty_first_last_text","vty_login_mode_text","vty_password_secret_text","vty_transport_input_text",
        "system_users_detail_map","interface_mop_xenabled_bool"
    ],
}

def default_patterns(metric: str) -> str:
    table = {
        "ibgp_fullmesh_ok": "AS {asn} 도메인의 iBGP 풀메시 구성이 완전한가",
        "ibgp_missing_pairs": "AS {asn} iBGP 풀메시에서 누락된 링크(장비쌍) 목록은?",
        "ibgp_under_peered_devices": "AS {asn} 에서 iBGP 피어 수가 기대치보다 적은 장비 목록은?",
        "ibgp_under_peered_count": "AS {asn} 에서 iBGP 피어 수가 기대치보다 적은 장비 수는?",
        "ibgp_missing_pairs_count": "AS {asn} iBGP 풀메시에서 누락된 링크 개수는?",
        "neighbor_list_ibgp": "{host} 장비의 iBGP 피어 목록은?",
        "neighbor_list_ebgp": "{host} 장비의 eBGP 피어 목록은?",
        "vrf_rd_map": "VRF {vrf} 의 장비별 RD 매핑은?",
        "vrf_rt_list_per_device": "{host} 의 VRF {vrf} route-target 목록은?",
        "vrf_without_rt_pairs": "route-target이 없는 VRF (장비/VRF) 목록은?",
        "vrf_without_rt_count": "route-target이 없는 VRF (장비/VRF) 개수는?",
        "l2vpn_pairs": "구성된 L2VPN pseudowire 회선(장비쌍) 목록은?",
        "l2vpn_unidirectional_pairs": "역방향이 없는 L2VPN 회선(장비쌍) 목록은?",
        "l2vpn_unidir_count": "역방향이 없는 L2VPN 회선(장비쌍) 개수는?",
        "l2vpn_pwid_mismatch_pairs": "PW-ID 불일치 L2VPN 회선(장비쌍) 목록은?",
        "l2vpn_mismatch_count": "PW-ID 불일치(또는 역방향 미존재) 회선 수는?",
        "ospf_proc_ids": "{host} 의 OSPF 프로세스 ID는?",
        "ospf_area0_if_list": "{host} 의 OSPF Area 0 인터페이스 목록은?",
        "ospf_area0_if_count": "{host} 의 OSPF Area 0 인터페이스 수는?",
        "ssh_enabled_devices": "SSH가 활성화된 장비 목록은?",
        "ssh_missing_devices": "SSH가 비활성화(또는 설정 없음)인 장비는?",
        "ssh_missing_count": "SSH가 비활성화(또는 설정 없음)인 장비 수는?",
        "aaa_enabled_devices": "AAA가 활성화된 장비 목록은?",
        "aaa_missing_devices": "AAA가 비활성화(또는 설정 없음)인 장비는?",
        "ebgp_remote_as_map": "{host} VRF {vrf}의 eBGP 피어 remote-as 매핑은?",
        "ibgp_update_source_missing_set": "AS {asn} iBGP에서 update-source가 누락된 피어는?",
        "vrf_interface_bind_count": "{host}의 VRF {vrf}에 바인딩된 인터페이스 수는?",
        "vrf_rd_format_invalid_set": "RD 형식이 비정상인 VRF 목록은?",
        "system_hostname_text": "{host} 장비의 호스트네임은?",
        "system_version_text": "{host} 장비의 OS/이미지 버전은?",
        "system_timezone_text": "{host} 장비의 시간대(Timezone)는?",
        "system_user_list": "{host} 장비의 로컬 사용자 목록은?",
        "system_user_count": "{host} 장비의 로컬 사용자 수는?",
        "interface_count": "{host} 장비의 인터페이스 개수는?",
        "interface_ip_map": "{host} 장비의 인터페이스-IP 매핑은?",
        "interface_vlan_set": "{host} 장비의 VLAN 목록은?",
        "subinterface_count": "{host} 장비의 서브인터페이스 개수는?",
        "vrf_bind_map": "{host} 장비의 인터페이스별 VRF 바인딩 현황은?",
        "bgp_local_as_numeric": "{host} 장비의 BGP Local-AS 번호는?",
        "bgp_neighbor_count": "{host} 장비의 BGP 이웃(피어) 수는?",
        "ospf_process_ids_set": "{host} 장비의 OSPF 프로세스 ID 목록은?",
        "ospf_area_set": "{host} 장비가 참여한 OSPF Area 목록은?",
        "vrf_names_set": "{host} 장비의 VRF 이름 목록은?",
        "vrf_count": "{host} 장비의 VRF 개수는?",
        # Basic Info
        "system_mgmt_address_text": "{host} 장비의 관리 IP 주소는?",
        "ios_config_register_text": "{host} 장비의 config-register 값은?",
        "logging_buffered_severity_text": "{host} 장비에서 logging buffered의 severity-level은?",
        "http_server_enabled_bool": "{host} 장비에서 HTTP 서버가 활성화되어 있습니까?",
        "ip_forward_protocol_nd_bool": "{host} 장비에서 ip forward-protocol nd가 설정되어 있습니까?",
        "ip_cef_enabled_bool": "{host} 장비에서 IP CEF가 활성화되어 있습니까?",
        "vty_first_last_text": "{host} 장비에서 VTY의 first~last 라인 번호는?",
        "vty_login_mode_text": "{host} 장비에서 VTY line의 login 방식은?",
        "vty_password_secret_text": "{host} 장비의 VTY password secret 값은?",
        "vty_transport_input_text": "{host} 장비에서 VTY의 transport input은?",
        "system_users_detail_map": "{host} 장비의 사용자 상세(UID/GID/HOME 등)는?",
        "interface_mop_xenabled_bool": "{host} 장비에서 {if} 인터페이스의 MOP xenabled 설정은?"
    }
    return table.get(metric, f"{metric} 측정값은?")

GOAL2METRICS = {
    "Security_Policy": {
        "validity":    ["ssh_enabled_devices","aaa_enabled_devices"],
        "visibility":  ["ssh_enabled_devices","ssh_missing_devices","aaa_enabled_devices"],
        "completeness":["ssh_missing_devices","ssh_missing_count"],
        "compliance":  ["ssh_missing_devices","aaa_missing_devices"]
    },
    "BGP_Consistency": {
        "visibility":  ["neighbor_list_ibgp","neighbor_list_ebgp"],
        "completeness":["ibgp_missing_pairs","ibgp_missing_pairs_count"],
        "consistency": ["ibgp_fullmesh_ok","ibgp_under_peered_devices","ibgp_missing_pairs"]
    },
    "VRF_Consistency": {
        "visibility":  ["vrf_rd_map","vrf_rt_list_per_device"],
        "completeness":["vrf_without_rt_pairs","vrf_without_rt_count"],
        "consistency": ["vrf_rd_map"]
    },
    "L2VPN_Consistency": {
        "visibility":  ["l2vpn_pairs"],
        "consistency": ["l2vpn_unidirectional_pairs","l2vpn_pwid_mismatch_pairs","l2vpn_mismatch_count"]
    },
    "OSPF_Consistency": {
        "visibility":  ["ospf_proc_ids","ospf_area0_if_list","ospf_area0_if_count"],
        "consistency": ["ospf_area0_if_count"]
    },
    # ---- Added Inventory categories (goal: extraction) ----
    "System_Inventory": {
        "extraction": [
            "system_hostname_text","system_version_text","system_user_count","system_user_list","system_timezone_text"
        ]
    },
    "Security_Inventory": {
        "extraction": [
            "ssh_present_bool","ssh_version_text","aaa_present_bool","password_policy_present_bool"
        ]
    },
    "Interface_Inventory": {
        "extraction": [
            "interface_count","interface_ip_map","interface_vlan_set","subinterface_count","vrf_bind_map"
        ]
    },
    "Routing_Inventory": {
        "extraction": [
            "bgp_local_as_numeric","bgp_neighbor_count","ospf_area_set","ospf_process_ids_set"
        ]
    },
    "Services_Inventory": {
        "extraction": [
            "vrf_names_set","vrf_rd_map","l2vpn_pw_id_set","mpls_ldp_present_bool","rt_import_count","rt_export_count","vrf_count"
        ]
    },
    # ---- Basic Info sanity checks ----
    "Basic_Info": {
        "sanity": [
            "system_hostname_text","system_mgmt_address_text","system_version_text","ios_config_register_text",
            "logging_buffered_severity_text","http_server_enabled_bool","ip_forward_protocol_nd_bool","ip_cef_enabled_bool",
            "vty_first_last_text","vty_login_mode_text","vty_password_secret_text","vty_transport_input_text",
            "system_users_detail_map"
        ],
        "interface": [
            "interface_mop_xenabled_bool"
        ]
    }
}

SCOPE_HINT = {
    "GLOBAL":      ({"type":"GLOBAL"}, []),
    "AS":          ({"type":"AS","asn":"{asn}"}, ["asn"]),
    "DEVICE":      ({"type":"DEVICE","host":"{host}"}, ["host"]),
    "VRF":         ({"type":"VRF","vrf":"{vrf}"}, ["vrf"]),
    "DEVICE_VRF":  ({"type":"DEVICE_VRF","host":"{host}","vrf":"{vrf}"}, ["host","vrf"]),
    # New: device and interface placeholder
    "DEVICE_IF":   ({"type":"DEVICE_IF","host":"{host}","if":"{if}"}, ["host","if"])
}

METRIC_AGG = {
    "ssh_enabled_devices":"set",
    "ssh_missing_devices":"set",
    "ssh_missing_count":"numeric",
    "aaa_enabled_devices":"set",
    "aaa_missing_devices":"set",
    "neighbor_list_ibgp":"set",
    "neighbor_list_ebgp":"set",
    "ibgp_missing_pairs":"set",
    "ibgp_missing_pairs_count":"numeric",
    "ibgp_fullmesh_ok":"boolean",
    "ibgp_under_peered_devices":"set",
    "ibgp_under_peered_count":"numeric",
    "vrf_rd_map":"map",
    "vrf_rt_list_per_device":"set",
    "vrf_without_rt_pairs":"set",
    "vrf_without_rt_count":"numeric",
    "l2vpn_pairs":"set",
    "l2vpn_unidirectional_pairs":"set",
    "l2vpn_pwid_mismatch_pairs":"set",
    "l2vpn_mismatch_count":"numeric",
    "ospf_proc_ids":"text",
    "ospf_area0_if_list":"set",
    "ospf_area0_if_count":"numeric",
    # Inventory
    "interface_count":"numeric",
    "interface_ip_map":"map",
    "interface_vlan_set":"set",
    "subinterface_count":"numeric",
    "vrf_bind_map":"map",
    "bgp_local_as_numeric":"numeric",
    "bgp_neighbor_count":"numeric",
    "ospf_area_set":"set",
    "ospf_process_ids_set":"text",
    "ssh_present_bool":"boolean",
    "ssh_version_text":"text",
    "aaa_present_bool":"boolean",
    "password_policy_present_bool":"boolean",
    "l2vpn_pw_id_set":"set",
    "mpls_ldp_present_bool":"boolean",
    "rt_export_count":"numeric",
    "rt_import_count":"numeric",
    "vrf_count":"numeric",
    "vrf_names_set":"set",
    "system_hostname_text":"text",
    "system_timezone_text":"text",
    "system_user_count":"numeric",
    "system_user_list":"set",
    "system_version_text":"text",
    # Basic Info
    "system_mgmt_address_text":"text",
    "ios_config_register_text":"text",
    "logging_buffered_severity_text":"text",
    "http_server_enabled_bool":"boolean",
    "ip_forward_protocol_nd_bool":"boolean",
    "ip_cef_enabled_bool":"boolean",
    "vty_first_last_text":"text",
    "vty_login_mode_text":"text",
    "vty_password_secret_text":"text",
    "vty_transport_input_text":"text",
    "system_users_detail_map":"map",
    "interface_mop_xenabled_bool":"boolean"
}

CANDIDATES = {
    "BGP_Consistency": [
        ("ibgp_fullmesh_ok", "boolean"),
        ("ibgp_missing_pairs", "set"),
        ("ibgp_missing_pairs_count", "numeric"),
    ],
    "VRF_Consistency": [
        ("vrf_without_rt_pairs", "set"),
        ("vrf_without_rt_count", "numeric"),
        ("vrf_rd_map", "map"),
    ],
    "L2VPN_Consistency": [
        ("l2vpn_unidirectional_pairs", "set"),
        ("l2vpn_mismatch_count", "numeric"),
    ],
    "OSPF_Consistency": [
        ("ospf_area0_if_list", "set"),
        ("ospf_area0_if_count", "numeric"),
    ],
    # ---- Added Inventory coverage boosters ----
    "System_Inventory": [
        ("system_user_count", "numeric"),
        ("system_hostname_text", "text"),
    ],
    "Security_Inventory": [
        ("ssh_present_bool", "boolean"),
        ("ssh_version_text", "text"),
    ],
    "Interface_Inventory": [
        ("interface_count", "numeric"),
        ("interface_ip_map", "map"),
        ("interface_vlan_set", "set"),
    ],
    "Routing_Inventory": [
        ("bgp_neighbor_count", "numeric"),
        ("ospf_area_set", "set"),
        ("ospf_process_ids_set", "text"),
    ],
    "Services_Inventory": [
        ("vrf_names_set", "set"),
        ("vrf_rd_map", "map"),
        ("mpls_ldp_present_bool", "boolean"),
    ],
    # Basic Info boosters
    "Basic_Info": [
        ("system_hostname_text", "text"),
        ("system_mgmt_address_text", "text"),
        ("system_version_text", "text"),
        ("ios_config_register_text", "text"),
        ("http_server_enabled_bool", "boolean")
    ]
}


def _allowed(cat: str, metric: str) -> bool:
    return metric in (ALLOWED_METRICS.get(cat) or [])


def _mk(metric: str, agg: str, cat: str) -> Dict[str, Any]:
    scope={"type":"GLOBAL"}; placeholders=[]
    if "ibgp" in metric:
        scope={"type":"AS","asn":"{asn}"}; placeholders=["asn"]
    if metric in ("neighbor_list_ibgp","neighbor_list_ebgp","ospf_area0_if_list","ospf_area0_if_count","ospf_proc_ids",
                  "system_hostname_text","system_mgmt_address_text","system_version_text","ios_config_register_text",
                  "logging_buffered_severity_text","http_server_enabled_bool","ip_forward_protocol_nd_bool","ip_cef_enabled_bool",
                  "vty_first_last_text","vty_login_mode_text","vty_password_secret_text","vty_transport_input_text",
                  "system_users_detail_map"):
        scope={"type":"DEVICE","host":"{host}"}; placeholders=["host"]
    if metric == "interface_mop_xenabled_bool":
        scope={"type":"DEVICE_IF","host":"{host}","if":"{if}"}; placeholders=["host","if"]
    if "vrf" in metric and "map" in metric:
        scope={"type":"VRF","vrf":"{vrf}"}; placeholders=["vrf"]
    return {
        "id": metric.upper(),
        "category": cat,
        "intent": {"metric": metric, "scope": scope, "aggregation": agg, "placeholders": placeholders},
        "pattern": default_patterns(metric)
    }


def _count_agg(items: List[Dict[str,Any]]) -> Dict[str,int]:
    cnt={"boolean":0,"numeric":0,"set":0,"map":0,"text":0}
    for it in items:
        a = (it.get("intent") or {}).get("aggregation")
        if a in cnt: cnt[a]+=1
    return cnt


def fix_coverage_budget(dsl: List[Dict[str,Any]], budget: Dict[str,int]) -> List[Dict[str,Any]]:
    by_cat = {}
    for t in dsl:
        by_cat.setdefault(t["category"], []).append(t)
    out=list(dsl)
    for cat, items in by_cat.items():
        need = dict(budget or {"boolean":1,"set":1,"numeric":1,"map":1})
        have = _count_agg(items)
        for k in list(need.keys()):
            need[k] = max(0, need.get(k,0) - have.get(k,0))
        for metric, agg in CANDIDATES.get(cat, []):
            if need.get(agg,0) <= 0:
                continue
            out.append(_mk(metric, agg, cat))
            need[agg] -= 1
            if all(v<=0 for v in need.values()):
                break
    return out


@dataclass
class RuleBasedGeneratorConfig:
    policies_path: str
    min_per_cat: int = 4
    scenario_type: str = "normal"  # normal, failure, expansion

class RuleBasedGenerator:
    def __init__(self, cfg: RuleBasedGeneratorConfig):
        self.cfg = cfg
        self._bundle = json.loads(Path(self.cfg.policies_path).read_text(encoding="utf-8"))
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
                levels = {"2": levels}
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
                        agg  = METRIC_AGG.get(metric, "set")
                        for tgt in targets:
                            scope, placeholders = SCOPE_HINT.get(tgt, SCOPE_HINT["GLOBAL"])
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
                                "level": int(lvl),
                                "goal": goal,
                                "policy_hints": {
                                    "primary_metric": primary_metric,
                                    "conditions": conditions,
                                    "notes": notes
                                },
                                "origin": "Universal"
                            })
        budget = self.defaults.get("mix", {"boolean":1,"set":1,"numeric":1,"map":1})
        dsl = fix_coverage_budget(dsl, budget)

        # 얕은 중복 제거
        import json as _json
        seen=set(); out=[]
        for t in dsl:
            key=(t["category"], t["intent"]["metric"], _json.dumps(t["intent"]["scope"], sort_keys=True, ensure_ascii=False))
            if key in seen:
                continue
            seen.add(key); out.append(t)
        return out
