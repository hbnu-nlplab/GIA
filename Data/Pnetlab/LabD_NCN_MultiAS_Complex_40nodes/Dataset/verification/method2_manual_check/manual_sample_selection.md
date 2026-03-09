# Method 2 — Stratified Sample Selection

Total samples selected: 43

## Selection Criteria

1. All Method 1 MISMATCH cases (PARSER_CORRECT: Batfish double-counting)
2. L3 metrics: 2 samples per metric (normal + boundary case)
3. L2 metrics: 1 sample per metric
4. L1 boundary cases: 5 diverse boundary cases (answer = 0, [], empty)
5. answer_type coverage: at least 1 sample per answer_type

## Sample Distribution

### By Level

- L1: 6
- L2: 10
- L3: 27

### By Answer Type

- map: 1
- map_str_int: 3
- number: 13
- set: 18
- text: 8

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
| 4 | NEIGHBOR_LIST_IBGP_p8 | L1 | neighbor_list_ibgp | set |
| 5 | SNMP_COMMUNITY_LIST_leaf15 | L1 | snmp_community_list | set |
| 6 | SUBINTERFACE_COUNT_p9 | L1 | subinterface_count | number |
| 7 | AAA_ENABLED_DEVICES | L2 | aaa_enabled_devices | set |
| 8 | AAA_MISSING_DEVICES | L2 | aaa_missing_devices | set |
| 9 | DEVICES_WITH_SAME_VRF_VRF_ISP | L2 | devices_with_same_vrf | set |
| 10 | L2VPN_PAIRS | L2 | l2vpn_pairs | set |
| 11 | OSPF_AREA0_IF_COUNT_p12 | L2 | ospf_area0_if_count | number |
| 12 | OSPF_AREA_MEMBERSHIP_1 | L2 | ospf_area_membership | set |
| 13 | OSPF_NEIGHBOR_COUNT_PER_AREA_2 | L2 | ospf_neighbor_count_per_area | number |
| 14 | SSH_ENABLED_DEVICES | L2 | ssh_enabled_devices | set |
| 15 | SSH_MISSING_COUNT | L2 | ssh_missing_count | number |
| 16 | SSH_MISSING_DEVICES | L2 | ssh_missing_devices | set |
| 17 | ALL_DEVICES_SAME_AS | L3 | all_devices_same_as | text |
| 18 | BGP_AS_DISTRIBUTION | L3 | bgp_as_distribution | text |
| 19 | COMPARE_BGP_AS_p4_pe1 | L3 | compare_bgp_as | text |
| 20 | COMPARE_BGP_NEIGHBOR_COUNT_leaf4_p11 | L3 | compare_bgp_neighbor_count | map_str_int |
| 21 | COMPARE_INTERFACE_COUNT_leaf11_leaf7 | L3 | compare_interface_count | map_str_int |
| 22 | COMPARE_OSPF_AREAS_asbr2_leaf11 | L3 | compare_ospf_areas | text |
| 23 | COMPARE_VRF_COUNT_leaf15_p3 | L3 | compare_vrf_count | map_str_int |
| 24 | IBGP_MISSING_PAIRS_65001 | L3 | ibgp_missing_pairs | set |
| 25 | IBGP_MISSING_PAIRS_65002 | L3 | ibgp_missing_pairs | set |
| 26 | IBGP_MISSING_PAIRS_COUNT_65000 | L3 | ibgp_missing_pairs_count | number |
| 27 | IBGP_MISSING_PAIRS_COUNT_65001 | L3 | ibgp_missing_pairs_count | number |
| 28 | IBGP_UNDER_PEERED_COUNT_65000 | L3 | ibgp_under_peered_count | number |
| 29 | IBGP_UNDER_PEERED_COUNT_65001 | L3 | ibgp_under_peered_count | number |
| 30 | IBGP_UNDER_PEERED_DEVICES_65000 | L3 | ibgp_under_peered_devices | set |
| 31 | IBGP_UNDER_PEERED_DEVICES_65001 | L3 | ibgp_under_peered_devices | set |
| 32 | L2VPN_MISMATCH_COUNT | L3 | l2vpn_mismatch_count | number |
| 33 | L2VPN_PWID_MISMATCH_PAIRS | L3 | l2vpn_pwid_mismatch_pairs | set |
| 34 | L2VPN_UNIDIRECTIONAL_PAIRS | L3 | l2vpn_unidirectional_pairs | set |
| 35 | L2VPN_UNIDIR_COUNT | L3 | l2vpn_unidir_count | number |
| 36 | MAX_BGP_PEER_DEVICE | L3 | max_bgp_peer_device | text |
| 37 | MAX_INTERFACE_DEVICE | L3 | max_interface_device | text |
| 38 | MIN_INTERFACE_DEVICE | L3 | min_interface_device | text |
| 39 | VRF_RT_LIST_PER_DEVICE_p5 | L3 | vrf_rt_list_per_device | set |
| 40 | VRF_RT_LIST_PER_DEVICE_pe4 | L3 | vrf_rt_list_per_device | set |
| 41 | VRF_USAGE_STATISTICS | L3 | vrf_usage_statistics | text |
| 42 | VRF_WITHOUT_RT_COUNT | L3 | vrf_without_rt_count | number |
| 43 | VRF_WITHOUT_RT_PAIRS | L3 | vrf_without_rt_pairs | set |
