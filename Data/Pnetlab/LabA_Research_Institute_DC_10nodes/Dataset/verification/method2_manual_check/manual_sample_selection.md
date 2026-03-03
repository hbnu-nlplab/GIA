# Method 2 — Stratified Sample Selection

Total samples selected: 67

## Selection Criteria

1. All Method 1 MISMATCH cases (PARSER_CORRECT: Batfish double-counting)
2. L3 metrics: 2 samples per metric (normal + boundary case)
3. L2 metrics: 1 sample per metric
4. L1 boundary cases: 5 diverse boundary cases (answer = 0, [], empty)
5. answer_type coverage: at least 1 sample per answer_type

## Sample Distribution

### By Level

- L1: 15
- L2: 10
- L3: 42

### By Answer Type

- map: 1
- map_str_int: 3
- number: 10
- set: 17
- text: 36

### By Metric

- aaa_enabled_devices: 1
- aaa_missing_devices: 1
- all_devices_same_as: 1
- bgp_as_distribution: 1
- bgp_local_as_numeric: 1
- compare_bgp_as: 20
- compare_bgp_neighbor_count: 1
- compare_interface_count: 1
- compare_ospf_areas: 1
- compare_vrf_count: 1
- configured_bgp_as_numbers: 2
- devices_with_same_vrf: 1
- ibgp_missing_pairs: 1
- ibgp_missing_pairs_count: 1
- ibgp_under_peered_count: 1
- ibgp_under_peered_devices: 1
- interface_status_map: 1
- l2vpn_mismatch_count: 1
- l2vpn_pairs: 1
- l2vpn_pwid_mismatch_pairs: 1
- l2vpn_unidir_count: 1
- l2vpn_unidirectional_pairs: 1
- max_bgp_peer_device: 1
- max_interface_device: 1
- min_interface_device: 1
- mpls_ldp_router_id: 7
- ntp_server_list: 1
- ospf_area0_if_count: 1
- ospf_area_membership: 1
- ospf_neighbor_count_per_area: 1
- snmp_community_list: 1
- ssh_enabled_devices: 1
- ssh_missing_count: 1
- ssh_missing_devices: 1
- subinterface_count: 1
- syslog_server_list: 1
- vrf_rt_list_per_device: 2
- vrf_usage_statistics: 1
- vrf_without_rt_count: 1
- vrf_without_rt_pairs: 1

## Full Sample List

| # | QA ID | Level | Metric | Answer Type |
|---:|---|---|---|---|
| 1 | BGP_LOCAL_AS_NUMERIC_p2 | L1 | bgp_local_as_numeric | number |
| 2 | CONFIGURED_BGP_AS_NUMBERS_leaf2 | L1 | configured_bgp_as_numbers | text |
| 3 | CONFIGURED_BGP_AS_NUMBERS_p2 | L1 | configured_bgp_as_numbers | text |
| 4 | INTERFACE_STATUS_MAP_p1 | L1 | interface_status_map | map |
| 5 | MPLS_LDP_ROUTER_ID_leaf1 | L1 | mpls_ldp_router_id | text |
| 6 | MPLS_LDP_ROUTER_ID_leaf2 | L1 | mpls_ldp_router_id | text |
| 7 | MPLS_LDP_ROUTER_ID_leaf3 | L1 | mpls_ldp_router_id | text |
| 8 | MPLS_LDP_ROUTER_ID_leaf4 | L1 | mpls_ldp_router_id | text |
| 9 | MPLS_LDP_ROUTER_ID_p4 | L1 | mpls_ldp_router_id | text |
| 10 | MPLS_LDP_ROUTER_ID_pe1 | L1 | mpls_ldp_router_id | text |
| 11 | MPLS_LDP_ROUTER_ID_pe2 | L1 | mpls_ldp_router_id | text |
| 12 | NTP_SERVER_LIST_p2 | L1 | ntp_server_list | set |
| 13 | SNMP_COMMUNITY_LIST_leaf1 | L1 | snmp_community_list | set |
| 14 | SUBINTERFACE_COUNT_p1 | L1 | subinterface_count | number |
| 15 | SYSLOG_SERVER_LIST_p3 | L1 | syslog_server_list | set |
| 16 | AAA_ENABLED_DEVICES | L2 | aaa_enabled_devices | set |
| 17 | AAA_MISSING_DEVICES | L2 | aaa_missing_devices | set |
| 18 | DEVICES_WITH_SAME_VRF_VRF_BIO | L2 | devices_with_same_vrf | set |
| 19 | L2VPN_PAIRS | L2 | l2vpn_pairs | set |
| 20 | OSPF_AREA0_IF_COUNT_leaf4 | L2 | ospf_area0_if_count | number |
| 21 | OSPF_AREA_MEMBERSHIP_0 | L2 | ospf_area_membership | set |
| 22 | OSPF_NEIGHBOR_COUNT_PER_AREA_0 | L2 | ospf_neighbor_count_per_area | number |
| 23 | SSH_ENABLED_DEVICES | L2 | ssh_enabled_devices | set |
| 24 | SSH_MISSING_COUNT | L2 | ssh_missing_count | number |
| 25 | SSH_MISSING_DEVICES | L2 | ssh_missing_devices | set |
| 26 | ALL_DEVICES_SAME_AS | L3 | all_devices_same_as | text |
| 27 | BGP_AS_DISTRIBUTION | L3 | bgp_as_distribution | text |
| 28 | COMPARE_BGP_AS_leaf1_leaf3 | L3 | compare_bgp_as | text |
| 29 | COMPARE_BGP_AS_leaf1_p1 | L3 | compare_bgp_as | text |
| 30 | COMPARE_BGP_AS_leaf1_p2 | L3 | compare_bgp_as | text |
| 31 | COMPARE_BGP_AS_leaf1_pe1 | L3 | compare_bgp_as | text |
| 32 | COMPARE_BGP_AS_leaf1_pe2 | L3 | compare_bgp_as | text |
| 33 | COMPARE_BGP_AS_leaf2_p1 | L3 | compare_bgp_as | text |
| 34 | COMPARE_BGP_AS_leaf2_p3 | L3 | compare_bgp_as | text |
| 35 | COMPARE_BGP_AS_leaf2_pe2 | L3 | compare_bgp_as | text |
| 36 | COMPARE_BGP_AS_leaf3_leaf4 | L3 | compare_bgp_as | text |
| 37 | COMPARE_BGP_AS_leaf3_p1 | L3 | compare_bgp_as | text |
| 38 | COMPARE_BGP_AS_leaf3_p2 | L3 | compare_bgp_as | text |
| 39 | COMPARE_BGP_AS_leaf3_p4 | L3 | compare_bgp_as | text |
| 40 | COMPARE_BGP_AS_leaf3_pe1 | L3 | compare_bgp_as | text |
| 41 | COMPARE_BGP_AS_leaf4_p2 | L3 | compare_bgp_as | text |
| 42 | COMPARE_BGP_AS_p1_p4 | L3 | compare_bgp_as | text |
| 43 | COMPARE_BGP_AS_p1_pe2 | L3 | compare_bgp_as | text |
| 44 | COMPARE_BGP_AS_p2_p4 | L3 | compare_bgp_as | text |
| 45 | COMPARE_BGP_AS_p4_pe1 | L3 | compare_bgp_as | text |
| 46 | COMPARE_BGP_AS_p4_pe2 | L3 | compare_bgp_as | text |
| 47 | COMPARE_BGP_AS_pe1_pe2 | L3 | compare_bgp_as | text |
| 48 | COMPARE_BGP_NEIGHBOR_COUNT_leaf2_leaf3 | L3 | compare_bgp_neighbor_count | map_str_int |
| 49 | COMPARE_INTERFACE_COUNT_leaf1_p1 | L3 | compare_interface_count | map_str_int |
| 50 | COMPARE_OSPF_AREAS_leaf3_p4 | L3 | compare_ospf_areas | text |
| 51 | COMPARE_VRF_COUNT_leaf2_p1 | L3 | compare_vrf_count | map_str_int |
| 52 | IBGP_MISSING_PAIRS_65000 | L3 | ibgp_missing_pairs | set |
| 53 | IBGP_MISSING_PAIRS_COUNT_65000 | L3 | ibgp_missing_pairs_count | number |
| 54 | IBGP_UNDER_PEERED_COUNT_65000 | L3 | ibgp_under_peered_count | number |
| 55 | IBGP_UNDER_PEERED_DEVICES_65000 | L3 | ibgp_under_peered_devices | set |
| 56 | L2VPN_MISMATCH_COUNT | L3 | l2vpn_mismatch_count | number |
| 57 | L2VPN_PWID_MISMATCH_PAIRS | L3 | l2vpn_pwid_mismatch_pairs | set |
| 58 | L2VPN_UNIDIRECTIONAL_PAIRS | L3 | l2vpn_unidirectional_pairs | set |
| 59 | L2VPN_UNIDIR_COUNT | L3 | l2vpn_unidir_count | number |
| 60 | MAX_BGP_PEER_DEVICE | L3 | max_bgp_peer_device | text |
| 61 | MAX_INTERFACE_DEVICE | L3 | max_interface_device | text |
| 62 | MIN_INTERFACE_DEVICE | L3 | min_interface_device | text |
| 63 | VRF_RT_LIST_PER_DEVICE_p4 | L3 | vrf_rt_list_per_device | set |
| 64 | VRF_RT_LIST_PER_DEVICE_pe2 | L3 | vrf_rt_list_per_device | set |
| 65 | VRF_USAGE_STATISTICS | L3 | vrf_usage_statistics | text |
| 66 | VRF_WITHOUT_RT_COUNT | L3 | vrf_without_rt_count | number |
| 67 | VRF_WITHOUT_RT_PAIRS | L3 | vrf_without_rt_pairs | set |
