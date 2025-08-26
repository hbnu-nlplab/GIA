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
    "Security_Compliance": [
        "ssh_acl_applied_check"
    ],
    "Routing_Policy_Inspection": [
        "bgp_advertised_prefixes_list"
    ],
    "QoS_Verification": [
        "qos_policer_applied_interfaces_list"
    ],
    "Command_Generation": [
        "cmd_show_bgp_summary",
        "cmd_show_ip_interface_brief",
        "cmd_show_ip_route_ospf",
        "cmd_show_processes_cpu",
        "cmd_show_l2vpn_vc",
        "cmd_show_ip_ospf_neighbor",
        "cmd_show_users",
        "cmd_show_logging",
        "cmd_ssh_direct_access",
        "cmd_set_static_route",
        "cmd_set_bgp_routemap",
        "cmd_set_interface_description",
        "cmd_create_vrf_and_assign",
        "cmd_set_ospf_cost",
        "cmd_set_vty_acl",
        "cmd_set_hostname",
        "cmd_ssh_proxy_jump",
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
        "rt_import_count": "{host} 장비의 Route Target Import 설정 개수는?",
        "rt_export_count": "{host} 장비의 Route Target Export 설정 개수는?",
        "l2vpn_pw_id_set": "{host} 장비의 L2VPN Pseudowire ID 목록은?",
        "mpls_ldp_present_bool": "{host} 장비에서 MPLS LDP가 설정되어 있습니까?",
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
        "system_users_detail_map": "{host} 장비의 사용자 상세(UID/GID/password/ssh_keydir/homedir 등)는?",
        "interface_mop_xenabled_bool": "{host} 장비에서 {if} 인터페이스의 MOP xenabled 설정은?",
        "ssh_acl_applied_check": "{host} 장비에 SSH 접속 ACL이 적용되어 있는가?",
        "bgp_advertised_prefixes_list": "{host} 장비가 BGP를 통해 외부로 광고하는 prefix 목록은?",
        "qos_policer_applied_interfaces_list": "{host} 장비에서 QoS Policer가 적용된 인터페이스 목록은?",
        # Command generation
        "cmd_show_bgp_summary": "{host} 장비에서 BGP 피어 상태를 요약해서 확인하는 명령어는?",
        "cmd_show_ip_interface_brief": "{host} 장비의 인터페이스 IP 상태를 간단히 보는 명령어는?",
        "cmd_show_ip_route_ospf": "{host} 장비에서 OSPF로 학습된 라우팅 정보를 확인하는 명령어는?",
        "cmd_show_processes_cpu": "{host} 장비에서 CPU 사용률 순으로 프로세스를 확인하는 명령어는?",
        "cmd_show_l2vpn_vc": "{host} 장비에서 L2VPN 가상회선 상태를 확인하는 명령어는?",
        "cmd_show_ip_ospf_neighbor": "{host} 장비에서 OSPF 이웃 상태를 조회하는 명령어는?",
        "cmd_show_users": "{host} 장비에 현재 접속한 사용자 목록을 보는 명령어는?",
        "cmd_show_logging": "{host} 장비의 로그 버퍼를 확인하는 명령어는?",
        "cmd_ssh_direct_access": "{user} 계정으로 {host} 장비에 직접 SSH 접속하는 명령어는?",
        "cmd_set_static_route": "{host} 장비에서 {prefix}/{mask} 네트워크로 가는 정적 경로를 {next_hop} 다음 홉으로 설정하는 명령어는?",
        "cmd_set_bgp_routemap": "{host} 장비에서 BGP AS {asn}의 {neighbor_ip} 이웃에 {map_name} 라우트맵을 outbound로 적용하는 명령어는?",
        "cmd_set_interface_description": "{host} 장비에서 {interface} 인터페이스에 '{description}' 설명을 설정하는 명령어는?",
        "cmd_create_vrf_and_assign": "{host} 장비에서 {vrf_name} VRF를 생성하고 {interface} 인터페이스에 할당하는 명령어 시퀀스는?",
        "cmd_set_ospf_cost": "{host} 장비에서 OSPF 프로세스 {process_id}의 {interface} 인터페이스 비용을 {cost}으로 설정하는 명령어는?",
        "cmd_set_vty_acl": "{host} 장비의 VTY 라인에 {acl_name} ACL을 inbound로 적용하는 명령어는?",
        "cmd_set_hostname": "{host} 장비의 호스트네임을 {new_hostname}(으)로 변경하는 명령어는?",
        "cmd_ssh_proxy_jump": "{user} 계정으로 {jump_host}를 거쳐 {destination_host} 장비에 SSH 접속하는 명령어는?",
        
        # Command generation (cmd_ 접두사 없는 버전)
        "show_bgp_summary": "{host} 장비에서 BGP 피어 상태를 요약해서 확인하는 명령어는?",
        "show_ip_interface_brief": "{host} 장비의 인터페이스 IP 상태를 간단히 보는 명령어는?",
        "show_ip_route_ospf": "{host} 장비에서 OSPF로 학습된 라우팅 정보를 확인하는 명령어는?",
        "show_processes_cpu": "{host} 장비에서 CPU 사용률 순으로 프로세스를 확인하는 명령어는?",
        "show_l2vpn_vc": "{host} 장비에서 L2VPN 가상회선 상태를 확인하는 명령어는?",
        "show_ip_ospf_neighbor": "{host} 장비에서 OSPF 이웃 상태를 조회하는 명령어는?",
        "show_users": "{host} 장비에 현재 접속한 사용자 목록을 보는 명령어는?",
        "show_logging": "{host} 장비의 로그 버퍼를 확인하는 명령어는?",
        "ssh_direct_access": "{user} 계정으로 {host} 장비에 직접 SSH 접속하는 명령어는?",
        "set_static_route": "{host} 장비에서 {prefix}/{mask} 네트워크로 가는 정적 경로를 {next_hop} 다음 홉으로 설정하는 명령어는?",
        "set_bgp_routemap": "{host} 장비에서 BGP AS {asn}의 {neighbor_ip} 이웃에 {map_name} 라우트맵을 outbound로 적용하는 명령어는?",
        "set_interface_description": "{host} 장비에서 {interface} 인터페이스에 '{description}' 설명을 설정하는 명령어는?",
        "create_vrf_and_assign": "{host} 장비에서 {vrf_name} VRF를 생성하고 {interface} 인터페이스에 할당하는 명령어 시퀀스는?",
        "set_ospf_cost": "{host} 장비에서 OSPF 프로세스 {process_id}의 {interface} 인터페이스 비용을 {cost}으로 설정하는 명령어는?",
        "set_vty_acl": "{host} 장비의 VTY 라인에 {acl_name} ACL을 inbound로 적용하는 명령어는?",
        "set_hostname": "{host} 장비의 호스트네임을 {new_hostname}(으)로 변경하는 명령어는?",
        "ssh_proxy_jump": "{user} 계정으로 {jump_host}를 거쳐 {destination_host} 장비에 SSH 접속하는 명령어는?",
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
    },
    # ---- Command Generation goals ----
    "Command_Generation": {
        "show_commands": [
            "cmd_show_bgp_summary","cmd_show_ip_interface_brief","cmd_show_ip_route_ospf",
            "cmd_show_ip_ospf_neighbor","cmd_show_users","cmd_show_logging",
            "cmd_show_processes_cpu","cmd_show_l2vpn_vc"
        ],
        "config_commands": [
            "cmd_set_static_route","cmd_set_bgp_routemap","cmd_set_interface_description",
            "cmd_create_vrf_and_assign","cmd_set_ospf_cost","cmd_set_vty_acl","cmd_set_hostname"
        ],
        "ssh_commands": [
            "cmd_ssh_direct_access","cmd_ssh_proxy_jump"
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
    "interface_mop_xenabled_bool":"boolean",
    "ssh_acl_applied_check":"boolean",
    "bgp_advertised_prefixes_list":"set",
    "qos_policer_applied_interfaces_list":"set",
    # Command Generation
    "cmd_show_bgp_summary":"text",
    "cmd_show_ip_interface_brief":"text",
    "cmd_show_ip_route_ospf":"text",
    "cmd_show_processes_cpu":"text",
    "cmd_show_l2vpn_vc":"text",
    "cmd_show_ip_ospf_neighbor":"text",
    "cmd_show_users":"text",
    "cmd_show_logging":"text",
    "cmd_ssh_direct_access":"text",
    "cmd_set_static_route":"text",
    "cmd_set_bgp_routemap":"text",
    "cmd_set_interface_description":"text",
    "cmd_create_vrf_and_assign":"text",
    "cmd_set_ospf_cost":"text",
    "cmd_set_vty_acl":"text",
    "cmd_set_hostname":"text",
    "cmd_ssh_proxy_jump":"text"
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
                  "system_users_detail_map","ssh_acl_applied_check","bgp_advertised_prefixes_list","qos_policer_applied_interfaces_list"):
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
        if "Command_Generation" in categories:
            out.extend(self._generate_command_questions(capabilities))
        return out

    def _generate_command_questions(self, facts: Dict[str, Any]) -> List[Dict[str, Any]]:
        devices = facts.get("devices", [])
        first = devices[0] if devices else {}
        host = (
            first.get("system", {}).get("hostname")
            or first.get("name")
            or first.get("file")
            or "device1"
        )
        interfaces = (first.get("interfaces") or [{}])
        interface = interfaces[0].get("name", "GigabitEthernet0/0")
        bgp = first.get("routing", {}).get("bgp", {})
        asn = bgp.get("local_as", 65000)
        neighbors = bgp.get("neighbors") or [{}]
        neighbor_ip = neighbors[0].get("id") or neighbors[0].get("ip") or "2.2.2.2"
        hosts = [(
            d.get("system", {}).get("hostname")
            or d.get("name")
            or d.get("file")
            or host
        ) for d in devices]
        jump_host = hosts[1] if len(hosts) > 1 else "jumphost"
        dest_host = hosts[2] if len(hosts) > 2 else host

        level_map = {
            "cmd_show_bgp_summary": 1,
            "cmd_show_ip_interface_brief": 1,
            "cmd_show_ip_route_ospf": 1,
            "cmd_show_processes_cpu": 1,
            "cmd_show_l2vpn_vc": 1,
            "cmd_show_ip_ospf_neighbor": 1,
            "cmd_show_users": 1,
            "cmd_show_logging": 1,
            "cmd_ssh_direct_access": 1,
            "cmd_set_static_route": 2,
            "cmd_set_bgp_routemap": 2,
            "cmd_set_interface_description": 2,
            "cmd_create_vrf_and_assign": 2,
            "cmd_set_ospf_cost": 2,
            "cmd_set_vty_acl": 2,
            "cmd_set_hostname": 2,
            "cmd_ssh_proxy_jump": 2,
        }

        params_base = {
            "host": host,
            "interface": interface,
            "asn": asn,
            "neighbor_ip": neighbor_ip,
            "user": "admin",
            "prefix": "192.0.2.0",
            "mask": "255.255.255.0",
            "next_hop": "10.0.0.1",
            "map_name": "RM_OUT",
            "description": "Uplink to core",
            "vrf_name": "CUSTOMER_A",
            "process_id": 1,
            "cost": 100,
            "acl_name": "SSH_ONLY",
            "new_hostname": f"{host}-NEW",
            "jump_host": jump_host,
            "destination_host": dest_host,
        }

        cmd_items: List[Dict[str, Any]] = []
        for metric in ALLOWED_METRICS.get("Command_Generation", []):
            params = dict(params_base)
            if metric == "cmd_ssh_direct_access":
                params = {"user": params["user"], "host": host}
            elif metric == "cmd_set_static_route":
                params = {
                    "host": host,
                    "prefix": params["prefix"],
                    "mask": params["mask"],
                    "next_hop": params["next_hop"],
                }
            elif metric == "cmd_set_bgp_routemap":
                params = {
                    "host": host,
                    "asn": asn,
                    "neighbor_ip": neighbor_ip,
                    "map_name": params["map_name"],
                }
            elif metric == "cmd_set_interface_description":
                params = {
                    "host": host,
                    "interface": interface,
                    "description": params["description"],
                }
            elif metric == "cmd_create_vrf_and_assign":
                params = {
                    "host": host,
                    "vrf_name": params["vrf_name"],
                    "interface": interface,
                }
            elif metric == "cmd_set_ospf_cost":
                params = {
                    "host": host,
                    "process_id": params_base["process_id"],
                    "interface": interface,
                    "cost": params_base["cost"],
                }
            elif metric == "cmd_set_vty_acl":
                params = {"host": host, "acl_name": params_base["acl_name"]}
            elif metric == "cmd_set_hostname":
                params = {"host": host, "new_hostname": params_base["new_hostname"]}
            elif metric == "cmd_ssh_proxy_jump":
                params = {
                    "user": params_base["user"],
                    "jump_host": params_base["jump_host"],
                    "destination_host": params_base["destination_host"],
                }
            elif metric == "cmd_show_processes_cpu":
                params = {"host": host}
            elif metric == "cmd_show_l2vpn_vc":
                params = {"host": host}
            else:
                params = {"host": host}

            question = default_patterns(metric).format(**params)
            cmd_items.append({
                "test_id": metric.upper(),
                "category": "Command_Generation",
                "question": question,
                "intent": {"metric": metric, "params": params},
                "level": level_map.get(metric, 1),
            })
        return cmd_items
