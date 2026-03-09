# Method 2 — Stratified Sample Selection

Total samples selected: 73

## Selection Criteria

1. All Method 1 MISMATCH cases (PARSER_CORRECT: Batfish double-counting)
2. L3 metrics: 2 samples per metric (normal + boundary case)
3. L2 metrics: 1 sample per metric
4. L1 boundary cases: 5 diverse boundary cases (answer = 0, [], empty)
5. answer_type coverage: at least 1 sample per answer_type

## Sample Distribution

### By Level

- L1: 36
- L2: 10
- L3: 27

### By Answer Type

- map: 1
- map_str_int: 3
- number: 13
- set: 18
- text: 38

### By Metric

- aaa_enabled_devices: 1
- aaa_missing_devices: 1
- all_devices_same_as: 1
- bgp_as_distribution: 1
- bgp_local_as_numeric: 1
- bgp_neighbor_count: 1
- compare_bgp_as: 1
- compare_bgp_neighbor_count: 1
- compare_interface_count: 1
- compare_ospf_areas: 1
- compare_vrf_count: 1
- devices_with_same_vrf: 1
- ibgp_missing_pairs: 2
- ibgp_missing_pairs_count: 2
- ibgp_under_peered_count: 2
- ibgp_under_peered_devices: 2
- interface_status_map: 1
- l2vpn_mismatch_count: 1
- l2vpn_pairs: 1
- l2vpn_pwid_mismatch_pairs: 1
- l2vpn_unidir_count: 1
- l2vpn_unidirectional_pairs: 1
- logging_buffered_severity_text: 10
- max_bgp_peer_device: 1
- max_interface_device: 1
- min_interface_device: 1
- neighbor_list_ibgp: 1
- ospf_area0_if_count: 1
- ospf_area_membership: 1
- ospf_neighbor_count_per_area: 1
- snmp_community_list: 1
- ssh_enabled_devices: 1
- ssh_missing_count: 1
- ssh_missing_devices: 1
- subinterface_count: 1
- system_timezone_text: 20
- vrf_rt_list_per_device: 2
- vrf_usage_statistics: 1
- vrf_without_rt_count: 1
- vrf_without_rt_pairs: 1

## Full Sample List

| # | QA ID | Level | Metric | Answer Type |
|---:|---|---|---|---|
| 1 | BGP_LOCAL_AS_NUMERIC_p9 | L1 | bgp_local_as_numeric | number |
| 2 | BGP_NEIGHBOR_COUNT_p1 | L1 | bgp_neighbor_count | number |
| 3 | INTERFACE_STATUS_MAP_leaf2 | L1 | interface_status_map | map |
| 4 | LOGGING_BUFFERED_SEVERITY_TEXT_leaf10 | L1 | logging_buffered_severity_text | text |
| 5 | LOGGING_BUFFERED_SEVERITY_TEXT_leaf14 | L1 | logging_buffered_severity_text | text |
| 6 | LOGGING_BUFFERED_SEVERITY_TEXT_leaf16 | L1 | logging_buffered_severity_text | text |
| 7 | LOGGING_BUFFERED_SEVERITY_TEXT_leaf3 | L1 | logging_buffered_severity_text | text |
| 8 | LOGGING_BUFFERED_SEVERITY_TEXT_leaf9 | L1 | logging_buffered_severity_text | text |
| 9 | LOGGING_BUFFERED_SEVERITY_TEXT_p12 | L1 | logging_buffered_severity_text | text |
| 10 | LOGGING_BUFFERED_SEVERITY_TEXT_p2 | L1 | logging_buffered_severity_text | text |
| 11 | LOGGING_BUFFERED_SEVERITY_TEXT_p7 | L1 | logging_buffered_severity_text | text |
| 12 | LOGGING_BUFFERED_SEVERITY_TEXT_p9 | L1 | logging_buffered_severity_text | text |
| 13 | LOGGING_BUFFERED_SEVERITY_TEXT_pe4 | L1 | logging_buffered_severity_text | text |
| 14 | NEIGHBOR_LIST_IBGP_p8 | L1 | neighbor_list_ibgp | set |
| 15 | SNMP_COMMUNITY_LIST_p11 | L1 | snmp_community_list | set |
| 16 | SUBINTERFACE_COUNT_p9 | L1 | subinterface_count | number |
| 17 | SYSTEM_TIMEZONE_TEXT_asbr1 | L1 | system_timezone_text | text |
| 18 | SYSTEM_TIMEZONE_TEXT_leaf1 | L1 | system_timezone_text | text |
| 19 | SYSTEM_TIMEZONE_TEXT_leaf10 | L1 | system_timezone_text | text |
| 20 | SYSTEM_TIMEZONE_TEXT_leaf14 | L1 | system_timezone_text | text |
| 21 | SYSTEM_TIMEZONE_TEXT_leaf16 | L1 | system_timezone_text | text |
| 22 | SYSTEM_TIMEZONE_TEXT_leaf3 | L1 | system_timezone_text | text |
| 23 | SYSTEM_TIMEZONE_TEXT_leaf6 | L1 | system_timezone_text | text |
| 24 | SYSTEM_TIMEZONE_TEXT_leaf9 | L1 | system_timezone_text | text |
| 25 | SYSTEM_TIMEZONE_TEXT_p10 | L1 | system_timezone_text | text |
| 26 | SYSTEM_TIMEZONE_TEXT_p11 | L1 | system_timezone_text | text |
| 27 | SYSTEM_TIMEZONE_TEXT_p12 | L1 | system_timezone_text | text |
| 28 | SYSTEM_TIMEZONE_TEXT_p5 | L1 | system_timezone_text | text |
| 29 | SYSTEM_TIMEZONE_TEXT_p6 | L1 | system_timezone_text | text |
| 30 | SYSTEM_TIMEZONE_TEXT_p8 | L1 | system_timezone_text | text |
| 31 | SYSTEM_TIMEZONE_TEXT_p9 | L1 | system_timezone_text | text |
| 32 | SYSTEM_TIMEZONE_TEXT_pe1 | L1 | system_timezone_text | text |
| 33 | SYSTEM_TIMEZONE_TEXT_pe2 | L1 | system_timezone_text | text |
| 34 | SYSTEM_TIMEZONE_TEXT_pe4 | L1 | system_timezone_text | text |
| 35 | SYSTEM_TIMEZONE_TEXT_pe7 | L1 | system_timezone_text | text |
| 36 | SYSTEM_TIMEZONE_TEXT_pe8 | L1 | system_timezone_text | text |
| 37 | AAA_ENABLED_DEVICES | L2 | aaa_enabled_devices | set |
| 38 | AAA_MISSING_DEVICES | L2 | aaa_missing_devices | set |
| 39 | DEVICES_WITH_SAME_VRF_VRF_ISP | L2 | devices_with_same_vrf | set |
| 40 | L2VPN_PAIRS | L2 | l2vpn_pairs | set |
| 41 | OSPF_AREA0_IF_COUNT_p12 | L2 | ospf_area0_if_count | number |
| 42 | OSPF_AREA_MEMBERSHIP_1 | L2 | ospf_area_membership | set |
| 43 | OSPF_NEIGHBOR_COUNT_PER_AREA_2 | L2 | ospf_neighbor_count_per_area | number |
| 44 | SSH_ENABLED_DEVICES | L2 | ssh_enabled_devices | set |
| 45 | SSH_MISSING_COUNT | L2 | ssh_missing_count | number |
| 46 | SSH_MISSING_DEVICES | L2 | ssh_missing_devices | set |
| 47 | ALL_DEVICES_SAME_AS | L3 | all_devices_same_as | text |
| 48 | BGP_AS_DISTRIBUTION | L3 | bgp_as_distribution | text |
| 49 | COMPARE_BGP_AS_p4_pe1 | L3 | compare_bgp_as | text |
| 50 | COMPARE_BGP_NEIGHBOR_COUNT_leaf4_p11 | L3 | compare_bgp_neighbor_count | map_str_int |
| 51 | COMPARE_INTERFACE_COUNT_leaf11_leaf7 | L3 | compare_interface_count | map_str_int |
| 52 | COMPARE_OSPF_AREAS_asbr2_leaf11 | L3 | compare_ospf_areas | text |
| 53 | COMPARE_VRF_COUNT_leaf15_p3 | L3 | compare_vrf_count | map_str_int |
| 54 | IBGP_MISSING_PAIRS_65001 | L3 | ibgp_missing_pairs | set |
| 55 | IBGP_MISSING_PAIRS_65002 | L3 | ibgp_missing_pairs | set |
| 56 | IBGP_MISSING_PAIRS_COUNT_65000 | L3 | ibgp_missing_pairs_count | number |
| 57 | IBGP_MISSING_PAIRS_COUNT_65001 | L3 | ibgp_missing_pairs_count | number |
| 58 | IBGP_UNDER_PEERED_COUNT_65000 | L3 | ibgp_under_peered_count | number |
| 59 | IBGP_UNDER_PEERED_COUNT_65001 | L3 | ibgp_under_peered_count | number |
| 60 | IBGP_UNDER_PEERED_DEVICES_65000 | L3 | ibgp_under_peered_devices | set |
| 61 | IBGP_UNDER_PEERED_DEVICES_65001 | L3 | ibgp_under_peered_devices | set |
| 62 | L2VPN_MISMATCH_COUNT | L3 | l2vpn_mismatch_count | number |
| 63 | L2VPN_PWID_MISMATCH_PAIRS | L3 | l2vpn_pwid_mismatch_pairs | set |
| 64 | L2VPN_UNIDIRECTIONAL_PAIRS | L3 | l2vpn_unidirectional_pairs | set |
| 65 | L2VPN_UNIDIR_COUNT | L3 | l2vpn_unidir_count | number |
| 66 | MAX_BGP_PEER_DEVICE | L3 | max_bgp_peer_device | text |
| 67 | MAX_INTERFACE_DEVICE | L3 | max_interface_device | text |
| 68 | MIN_INTERFACE_DEVICE | L3 | min_interface_device | text |
| 69 | VRF_RT_LIST_PER_DEVICE_p5 | L3 | vrf_rt_list_per_device | set |
| 70 | VRF_RT_LIST_PER_DEVICE_pe4 | L3 | vrf_rt_list_per_device | set |
| 71 | VRF_USAGE_STATISTICS | L3 | vrf_usage_statistics | text |
| 72 | VRF_WITHOUT_RT_COUNT | L3 | vrf_without_rt_count | number |
| 73 | VRF_WITHOUT_RT_PAIRS | L3 | vrf_without_rt_pairs | set |
