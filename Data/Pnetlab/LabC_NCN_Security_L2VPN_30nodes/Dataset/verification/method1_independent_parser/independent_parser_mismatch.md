# Independent Parser — Mismatch Report

Total mismatches: 113

## logging_buffered_severity_text (20 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| LOGGING_BUFFERED_SEVERITY_TEXT_p5 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p4 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p2 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p1 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p8 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p10 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf2 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_asbr2 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf1 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_pe2 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| ... | ... | ... | ... | ... | (10 more) |

## ibgp_under_peered_devices (18 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_UNDER_PEERED_DEVICES_65000 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs2 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs6 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs7 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs6__rs9 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs7__rs11 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs7__rs12 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs7__rs13 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs6__rs9__rs15 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs2__rs21 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe2', 'p7', 'pe4', 'pe3', 'pe1 |
| ... | ... | ... | ... | ... | (8 more) |

## snmp_community_list (11 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| SNMP_COMMUNITY_LIST_p5 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe4 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-ro', 'ncn-rw'} |
| SNMP_COMMUNITY_LIST_p7 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe3 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-ro', 'ncn-rw'} |
| SNMP_COMMUNITY_LIST_asbr1 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-ro', 'ncn-rw'} |
| SNMP_COMMUNITY_LIST_asbr2 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-ro', 'ncn-rw'} |
| SNMP_COMMUNITY_LIST_pe5 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-ro', 'ncn-rw'} |
| SNMP_COMMUNITY_LIST_p10 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_p4 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_p2 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| ... | ... | ... | ... | ... | (1 more) |

## banner_motd_content (11 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| BANNER_MOTD_CONTENT_pe3 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p8 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p2 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p3 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_pe1 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_asbr1 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p7 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_pe6 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_pe4 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p1 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| ... | ... | ... | ... | ... | (1 more) |

## ibgp_under_peered_count (9 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_UNDER_PEERED_COUNT_65000 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs3 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs3__rs10 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs14 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs14__rs19 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs14__rs23 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs14__rs25 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs14__rs23__rs35 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs14__rs19__rs39 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |

## interfaces_missing_description_count (9 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe6 | L1 | `8` | `4` | 0.00 | parser=8.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_asbr1 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe4 | L1 | `6` | `4` | 0.00 | parser=6.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe2 | L1 | `7` | `4` | 0.00 | parser=7.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_p3 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_p7 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_p8 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_asbr2 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_p5 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |

## ibgp_missing_pairs_count (6 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_MISSING_PAIRS_COUNT_65000 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs1 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs1__rs4 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs20 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs33 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs33__rs40 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |

## interface_ip_map (5 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| INTERFACE_IP_MAP_pe3 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.11.0/31", "GigabitEthernet0/1":` | 0.50 | GigabitEthernet0/0: parser=, gold=10.0.1 |
| INTERFACE_IP_MAP_pe5 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.31.3/31", "GigabitEthernet0/1":` | 0.43 | GigabitEthernet0/0: parser=, gold=10.0.3 |
| INTERFACE_IP_MAP_pe6 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.32.3/31", "GigabitEthernet0/1":` | 0.38 | GigabitEthernet0/0: parser=, gold=10.0.3 |
| INTERFACE_IP_MAP_pe1 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.1.0/31", "GigabitEthernet0/1": ` | 0.50 | GigabitEthernet0/0: parser=, gold=10.0.1 |
| INTERFACE_IP_MAP_asbr1 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.30.1/31", "GigabitEthernet0/1":` | 0.40 | GigabitEthernet0/0: parser=, gold=10.0.3 |

## ospf_area0_if_list (4 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| OSPF_AREA0_IF_LIST_pe4 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]` | 0.50 | missing={'gigabitethernet0/1', 'gigabite |
| OSPF_AREA0_IF_LIST_asbr2 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "Loopback0"]` | 0.67 | missing={'gigabitethernet0/0'} |
| OSPF_AREA0_IF_LIST_pe2 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]` | 0.50 | missing={'gigabitethernet0/1', 'gigabite |
| OSPF_AREA0_IF_LIST_asbr1 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "Loopback0"]` | 0.67 | missing={'gigabitethernet0/0'} |

## acl_applied_interfaces_list (4 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| ACL_APPLIED_INTERFACES_LIST_leaf12 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |
| ACL_APPLIED_INTERFACES_LIST_leaf10 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |
| ACL_APPLIED_INTERFACES_LIST_leaf11 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |
| ACL_APPLIED_INTERFACES_LIST_leaf9 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |

## routing_table_entry_count (3 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| ROUTING_TABLE_ENTRY_COUNT_pe2 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |
| ROUTING_TABLE_ENTRY_COUNT_pe3 | L1 | `3` | `6` | 0.00 | parser=3.0, gold=6.0 |
| ROUTING_TABLE_ENTRY_COUNT_pe5 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |

## vrf_bind_map (3 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| VRF_BIND_MAP_pe3 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "VRF` | 0.67 | GigabitEthernet0/1: parser=default, gold |
| VRF_BIND_MAP_pe1 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "VRF` | 0.67 | GigabitEthernet0/1: parser=default, gold |
| VRF_BIND_MAP_pe6 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "VRF` | 0.62 | GigabitEthernet0/1: parser=default, gold |

## ospf_area0_if_count (3 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| OSPF_AREA0_IF_COUNT_pe4 | L2 | `1` | `3` | 0.00 | parser=1.0, gold=3.0 |
| OSPF_AREA0_IF_COUNT_asbr1 | L2 | `1` | `2` | 0.00 | parser=1.0, gold=2.0 |
| OSPF_AREA0_IF_COUNT_asbr2 | L2 | `1` | `2` | 0.00 | parser=1.0, gold=2.0 |

## ibgp_missing_pairs (3 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_MISSING_PAIRS_65000 | L3 | `[]` | `["p7<->p8", "p7<->pe1", "p7<->pe2", "p7<->pe3", "p7<->pe4", ` | 0.00 | missing={'p8<->pe3', 'p7<->pe3', 'p7<->p |
| IBGP_MISSING_PAIRS_65000__rs32 | L3 | `[]` | `["p7<->p8", "p7<->pe1", "p7<->pe2", "p7<->pe3", "p7<->pe4", ` | 0.00 | missing={'p8<->pe3', 'p7<->pe3', 'p7<->p |
| IBGP_MISSING_PAIRS_65000__rs32__rs36 | L3 | `[]` | `["p7<->p8", "p7<->pe1", "p7<->pe2", "p7<->pe3", "p7<->pe4", ` | 0.00 | missing={'p8<->pe3', 'p7<->pe3', 'p7<->p |

## hsrp_groups_list (2 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| HSRP_GROUPS_LIST_pe5 | L1 | `[]` | `["10"]` | 0.00 | missing={'10'} |
| HSRP_GROUPS_LIST_pe6 | L1 | `[]` | `["10"]` | 0.00 | missing={'10'} |

## all_devices_same_as (1 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| ALL_DEVICES_SAME_AS | L3 | `asbr1: AS 65001, asbr2: AS 65001, p7: AS 65000, p8: AS 65000` | `"asbr1: AS 65001, asbr2: AS 65001, leaf1: AS N/A, leaf10: AS` | 0.56 | token_f1=0.560 |

## prefix_list_count (1 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| PREFIX_LIST_COUNT_asbr1 | L1 | `2` | `1` | 0.00 | parser=2.0, gold=1.0 |
