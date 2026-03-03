# Independent Parser — Mismatch Report

Total mismatches: 116

## logging_buffered_severity_text (20 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf9 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p9 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf3 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_pe4 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf10 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p12 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p7 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf16 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf14 | L1 | `informational` | `null` | 0.00 | gold_empty |
| LOGGING_BUFFERED_SEVERITY_TEXT_p2 | L1 | `warnings` | `null` | 0.00 | gold_empty |
| ... | ... | ... | ... | ... | (10 more) |

## ibgp_under_peered_count (12 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_UNDER_PEERED_COUNT_65000 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65002 | L3 | `0` | `3` | 0.00 | parser=0.0, gold=3.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs2 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs6 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs10 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs6__rs13 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs6__rs18 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs19 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs19__rs26 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_UNDER_PEERED_COUNT_65000__rs19__rs27 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| ... | ... | ... | ... | ... | (2 more) |

## banner_motd_content (12 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| BANNER_MOTD_CONTENT_p10 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_asbr1 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_fw2 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_asbr2 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p1 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_pe3 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p11 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_pe5 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p7 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| BANNER_MOTD_CONTENT_p5 | L1 | `Configured` | `"None"` | 0.00 | gold_empty |
| ... | ... | ... | ... | ... | (2 more) |

## snmp_community_list (11 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| SNMP_COMMUNITY_LIST_p11 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_p6 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe7 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-rw', 'ncn-ro'} |
| SNMP_COMMUNITY_LIST_p12 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_asbr1 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-rw', 'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe3 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-rw', 'ncn-ro'} |
| SNMP_COMMUNITY_LIST_p5 | L1 | `["NCN-RO"]` | `[]` | 0.00 | extra={'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe6 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-rw', 'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe1 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-rw', 'ncn-ro'} |
| SNMP_COMMUNITY_LIST_pe5 | L1 | `["NCN-RO", "NCN-RW"]` | `[]` | 0.00 | extra={'ncn-rw', 'ncn-ro'} |
| ... | ... | ... | ... | ... | (1 more) |

## ibgp_missing_pairs (8 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_MISSING_PAIRS_65002 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |
| IBGP_MISSING_PAIRS_65000 | L3 | `[]` | `["p7<->p8", "p7<->pe1", "p7<->pe2", "p7<->pe3", "p7<->pe4", ` | 0.00 | missing={'p8<->pe2', 'p7<->pe3', 'p7<->p |
| IBGP_MISSING_PAIRS_65002__rs11 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |
| IBGP_MISSING_PAIRS_65002__rs11__rs12 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |
| IBGP_MISSING_PAIRS_65002__rs11__rs20 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |
| IBGP_MISSING_PAIRS_65002__rs11__rs20__rs22 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |
| IBGP_MISSING_PAIRS_65002__rs24 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |
| IBGP_MISSING_PAIRS_65002__rs11__rs20__rs37 | L3 | `[]` | `["fw1<->fw2", "fw1<->pe7", "fw1<->pe8", "fw2<->pe7", "fw2<->` | 0.00 | missing={'pe7<->pe8', 'fw1<->pe8', 'fw1< |

## ibgp_missing_pairs_count (8 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_MISSING_PAIRS_COUNT_65000 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65002 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs3 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65002__rs9 | L3 | `0` | `6` | 0.00 | parser=0.0, gold=6.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs14 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs35 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs14__rs36 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |
| IBGP_MISSING_PAIRS_COUNT_65000__rs38 | L3 | `0` | `11` | 0.00 | parser=0.0, gold=11.0 |

## ibgp_under_peered_devices (8 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| IBGP_UNDER_PEERED_DEVICES_65000 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe3', 'pe2', 'p8', 'pe4', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65002 | L3 | `[]` | `["fw1", "fw2", "pe7"]` | 0.00 | missing={'pe7', 'fw2', 'fw1'} |
| IBGP_UNDER_PEERED_DEVICES_65002__rs1 | L3 | `[]` | `["fw1", "fw2", "pe7"]` | 0.00 | missing={'pe7', 'fw2', 'fw1'} |
| IBGP_UNDER_PEERED_DEVICES_65000__rs7 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe3', 'pe2', 'p8', 'pe4', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65002__rs15 | L3 | `[]` | `["fw1", "fw2", "pe7"]` | 0.00 | missing={'pe7', 'fw2', 'fw1'} |
| IBGP_UNDER_PEERED_DEVICES_65002__rs21 | L3 | `[]` | `["fw1", "fw2", "pe7"]` | 0.00 | missing={'pe7', 'fw2', 'fw1'} |
| IBGP_UNDER_PEERED_DEVICES_65000__rs7__rs25 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe3', 'pe2', 'p8', 'pe4', 'pe1 |
| IBGP_UNDER_PEERED_DEVICES_65000__rs34 | L3 | `[]` | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | 0.00 | missing={'pe3', 'pe2', 'p8', 'pe4', 'pe1 |

## interfaces_missing_description_count (7 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| INTERFACES_MISSING_DESCRIPTION_COUNT_p5 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe2 | L1 | `7` | `4` | 0.00 | parser=7.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_p8 | L1 | `5` | `4` | 0.00 | parser=5.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe4 | L1 | `6` | `4` | 0.00 | parser=6.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe3 | L1 | `6` | `3` | 0.00 | parser=6.0, gold=3.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_asbr2 | L1 | `6` | `4` | 0.00 | parser=6.0, gold=4.0 |
| INTERFACES_MISSING_DESCRIPTION_COUNT_pe7 | L1 | `6` | `4` | 0.00 | parser=6.0, gold=4.0 |

## routing_table_entry_count (6 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| ROUTING_TABLE_ENTRY_COUNT_pe7 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |
| ROUTING_TABLE_ENTRY_COUNT_asbr2 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |
| ROUTING_TABLE_ENTRY_COUNT_pe3 | L1 | `3` | `6` | 0.00 | parser=3.0, gold=6.0 |
| ROUTING_TABLE_ENTRY_COUNT_pe2 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |
| ROUTING_TABLE_ENTRY_COUNT_pe8 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |
| ROUTING_TABLE_ENTRY_COUNT_asbr1 | L1 | `3` | `7` | 0.00 | parser=3.0, gold=7.0 |

## ospf_area0_if_count (6 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| OSPF_AREA0_IF_COUNT_pe4 | L2 | `1` | `3` | 0.00 | parser=1.0, gold=3.0 |
| OSPF_AREA0_IF_COUNT_pe2 | L2 | `1` | `3` | 0.00 | parser=1.0, gold=3.0 |
| OSPF_AREA0_IF_COUNT_pe3 | L2 | `1` | `2` | 0.00 | parser=1.0, gold=2.0 |
| OSPF_AREA0_IF_COUNT_pe1 | L2 | `1` | `2` | 0.00 | parser=1.0, gold=2.0 |
| OSPF_AREA0_IF_COUNT_asbr1 | L2 | `1` | `2` | 0.00 | parser=1.0, gold=2.0 |
| OSPF_AREA0_IF_COUNT_pe3__rs14 | L2 | `1` | `2` | 0.00 | parser=1.0, gold=2.0 |

## vrf_bind_map (5 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| VRF_BIND_MAP_pe2 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | 0.71 | GigabitEthernet0/2: parser=default, gold |
| VRF_BIND_MAP_pe3 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "VRF` | 0.67 | GigabitEthernet0/1: parser=default, gold |
| VRF_BIND_MAP_pe6 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "VRF` | 0.62 | GigabitEthernet0/1: parser=default, gold |
| VRF_BIND_MAP_pe4 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | 0.67 | GigabitEthernet0/2: parser=default, gold |
| VRF_BIND_MAP_pe1 | L1 | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "def` | `{"GigabitEthernet0/0": "default", "GigabitEthernet0/1": "VRF` | 0.67 | GigabitEthernet0/1: parser=default, gold |

## interface_ip_map (4 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| INTERFACE_IP_MAP_pe1 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.1.0/31", "GigabitEthernet0/1": ` | 0.50 | GigabitEthernet0/0: parser=, gold=10.0.1 |
| INTERFACE_IP_MAP_pe2 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.4.1/31", "GigabitEthernet0/1": ` | 0.43 | GigabitEthernet0/0: parser=, gold=10.0.4 |
| INTERFACE_IP_MAP_asbr1 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.30.1/31", "GigabitEthernet0/1":` | 0.33 | GigabitEthernet0/0: parser=, gold=10.0.3 |
| INTERFACE_IP_MAP_pe7 | L1 | `{"GigabitEthernet0/0": "", "GigabitEthernet0/1": "", "Gigabi` | `{"GigabitEthernet0/0": "10.0.41.3/31", "GigabitEthernet0/1":` | 0.33 | GigabitEthernet0/0: parser=, gold=10.0.4 |

## ospf_area0_if_list (3 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| OSPF_AREA0_IF_LIST_pe2 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]` | 0.50 | missing={'gigabitethernet0/0', 'gigabite |
| OSPF_AREA0_IF_LIST_pe4 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]` | 0.50 | missing={'gigabitethernet0/0', 'gigabite |
| OSPF_AREA0_IF_LIST_pe3 | L1 | `["Loopback0"]` | `["GigabitEthernet0/0", "Loopback0"]` | 0.67 | missing={'gigabitethernet0/0'} |

## acl_applied_interfaces_list (3 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| ACL_APPLIED_INTERFACES_LIST_leaf10 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |
| ACL_APPLIED_INTERFACES_LIST_leaf12 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |
| ACL_APPLIED_INTERFACES_LIST_leaf11 | L1 | `[]` | `["GigabitEthernet0/0"]` | 0.00 | missing={'gigabitethernet0/0'} |

## prefix_list_count (2 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| PREFIX_LIST_COUNT_asbr2 | L1 | `2` | `1` | 0.00 | parser=2.0, gold=1.0 |
| PREFIX_LIST_COUNT_asbr1 | L1 | `2` | `1` | 0.00 | parser=2.0, gold=1.0 |

## all_devices_same_as (1 mismatches)

| ID | Level | Parser Answer | Dataset Answer | Score | Detail |
|---|---|---|---|---|---|
| ALL_DEVICES_SAME_AS | L3 | `asbr1: AS 65001, asbr2: AS 65001, fw1: AS 65002, fw2: AS 650` | `"asbr1: AS 65001, asbr2: AS 65001, fw1: AS 65002, fw2: AS 65` | 0.58 | token_f1=0.576 |
