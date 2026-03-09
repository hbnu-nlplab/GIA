# Method 2 — Disagreement Log

Total disagreements: 30 / 67

## CONFIGURED_BGP_AS_NUMBERS_leaf2

- **Metric**: configured_bgp_as_numbers
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"Not Configured"`
- **Manual Answer**: `[]`
- **Classification**: DATA_ERROR
- **Rationale**: [Method1-crossref] configured_bgp_as_numbers(leaf2) = []

## CONFIGURED_BGP_AS_NUMBERS_p2

- **Metric**: configured_bgp_as_numbers
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"Not Configured"`
- **Manual Answer**: `[]`
- **Classification**: DATA_ERROR
- **Rationale**: [Method1-crossref] configured_bgp_as_numbers(p2) = []

## MPLS_LDP_ROUTER_ID_leaf1

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in leaf1.cfg → 미설정

## MPLS_LDP_ROUTER_ID_leaf2

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in leaf2.cfg → 미설정

## MPLS_LDP_ROUTER_ID_leaf3

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in leaf3.cfg → 미설정

## MPLS_LDP_ROUTER_ID_leaf4

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in leaf4.cfg → 미설정

## MPLS_LDP_ROUTER_ID_p4

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in p4.cfg → 미설정

## MPLS_LDP_ROUTER_ID_pe1

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in pe1.cfg → 미설정

## MPLS_LDP_ROUTER_ID_pe2

- **Metric**: mpls_ldp_router_id
- **Level**: L1
- **Answer Type**: text
- **Dataset Answer**: `"NOT_CONFIGURED"`
- **Manual Answer**: `미설정`
- **Classification**: INVESTIGATION_NEEDED
- **Rationale**: No 'mpls ldp router-id' in pe2.cfg → 미설정

## ALL_DEVICES_SAME_AS

- **Metric**: all_devices_same_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: AS N/A, leaf2: AS N/A, leaf3: AS N/A, leaf4: AS N/A, p1: AS N/A, p2: AS N/A, p3: AS N/A, p4: AS N/A, pe1: AS 65000, pe2: AS 65000"`
- **Manual Answer**: `pe1: AS 65000, pe2: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS numbers found: {'65000'} | [Method1-crossref] all_devices_same_as({'type': 'GLOBAL'}) = pe1: AS 65000, pe2: AS 65000

## COMPARE_BGP_AS_leaf1_leaf3

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: AS N/A, leaf3: AS N/A"`
- **Manual Answer**: `leaf1: AS None, leaf3: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf1=0, leaf3=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf1', 'host2': 'leaf3'}) = leaf1: AS None, leaf3: AS None

## COMPARE_BGP_AS_leaf1_p1

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: AS N/A, p1: AS N/A"`
- **Manual Answer**: `leaf1: AS None, p1: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf1=0, p1=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf1', 'host2': 'p1'}) = leaf1: AS None, p1: AS None

## COMPARE_BGP_AS_leaf1_p2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: AS N/A, p2: AS N/A"`
- **Manual Answer**: `leaf1: AS None, p2: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf1=0, p2=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf1', 'host2': 'p2'}) = leaf1: AS None, p2: AS None

## COMPARE_BGP_AS_leaf1_pe1

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: AS N/A, pe1: AS 65000"`
- **Manual Answer**: `leaf1: AS None, pe1: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf1=0, pe1=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf1', 'host2': 'pe1'}) = leaf1: AS None, pe1: AS 65000

## COMPARE_BGP_AS_leaf1_pe2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: AS N/A, pe2: AS 65000"`
- **Manual Answer**: `leaf1: AS None, pe2: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf1=0, pe2=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf1', 'host2': 'pe2'}) = leaf1: AS None, pe2: AS 65000

## COMPARE_BGP_AS_leaf2_p1

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf2: AS N/A, p1: AS N/A"`
- **Manual Answer**: `leaf2: AS None, p1: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf2=0, p1=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf2', 'host2': 'p1'}) = leaf2: AS None, p1: AS None

## COMPARE_BGP_AS_leaf2_p3

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf2: AS N/A, p3: AS N/A"`
- **Manual Answer**: `leaf2: AS None, p3: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf2=0, p3=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf2', 'host2': 'p3'}) = leaf2: AS None, p3: AS None

## COMPARE_BGP_AS_leaf2_pe2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf2: AS N/A, pe2: AS 65000"`
- **Manual Answer**: `leaf2: AS None, pe2: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf2=0, pe2=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf2', 'host2': 'pe2'}) = leaf2: AS None, pe2: AS 65000

## COMPARE_BGP_AS_leaf3_leaf4

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf3: AS N/A, leaf4: AS N/A"`
- **Manual Answer**: `leaf3: AS None, leaf4: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf3=0, leaf4=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf3', 'host2': 'leaf4'}) = leaf3: AS None, leaf4: AS None

## COMPARE_BGP_AS_leaf3_p1

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf3: AS N/A, p1: AS N/A"`
- **Manual Answer**: `leaf3: AS None, p1: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf3=0, p1=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf3', 'host2': 'p1'}) = leaf3: AS None, p1: AS None

## COMPARE_BGP_AS_leaf3_p2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf3: AS N/A, p2: AS N/A"`
- **Manual Answer**: `leaf3: AS None, p2: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf3=0, p2=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf3', 'host2': 'p2'}) = leaf3: AS None, p2: AS None

## COMPARE_BGP_AS_leaf3_p4

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf3: AS N/A, p4: AS N/A"`
- **Manual Answer**: `leaf3: AS None, p4: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf3=0, p4=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf3', 'host2': 'p4'}) = leaf3: AS None, p4: AS None

## COMPARE_BGP_AS_leaf3_pe1

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf3: AS N/A, pe1: AS 65000"`
- **Manual Answer**: `leaf3: AS None, pe1: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf3=0, pe1=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf3', 'host2': 'pe1'}) = leaf3: AS None, pe1: AS 65000

## COMPARE_BGP_AS_leaf4_p2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf4: AS N/A, p2: AS N/A"`
- **Manual Answer**: `leaf4: AS None, p2: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS leaf4=0, p2=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'leaf4', 'host2': 'p2'}) = leaf4: AS None, p2: AS None

## COMPARE_BGP_AS_p1_p4

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"p1: AS N/A, p4: AS N/A"`
- **Manual Answer**: `p1: AS None, p4: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS p1=0, p4=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'p1', 'host2': 'p4'}) = p1: AS None, p4: AS None

## COMPARE_BGP_AS_p1_pe2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"p1: AS N/A, pe2: AS 65000"`
- **Manual Answer**: `p1: AS None, pe2: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS p1=0, pe2=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'p1', 'host2': 'pe2'}) = p1: AS None, pe2: AS 65000

## COMPARE_BGP_AS_p2_p4

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"p2: AS N/A, p4: AS N/A"`
- **Manual Answer**: `p2: AS None, p4: AS None`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS p2=0, p4=0 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'p2', 'host2': 'p4'}) = p2: AS None, p4: AS None

## COMPARE_BGP_AS_p4_pe1

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"p4: AS N/A, pe1: AS 65000"`
- **Manual Answer**: `p4: AS None, pe1: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS p4=0, pe1=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'p4', 'host2': 'pe1'}) = p4: AS None, pe1: AS 65000

## COMPARE_BGP_AS_p4_pe2

- **Metric**: compare_bgp_as
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"p4: AS N/A, pe2: AS 65000"`
- **Manual Answer**: `p4: AS None, pe2: AS 65000`
- **Classification**: DATA_ERROR
- **Rationale**: Manual: BGP AS p4=0, pe2=65000 | [Method1-crossref] compare_bgp_as({'type': 'DEVICE_PAIR', 'host1': 'p4', 'host2': 'pe2'}) = p4: AS None, pe2: AS 65000

## VRF_USAGE_STATISTICS

- **Metric**: vrf_usage_statistics
- **Level**: L3
- **Answer Type**: text
- **Dataset Answer**: `"leaf1: 0, leaf2: 0, leaf3: 0, leaf4: 0, p1: 0, p2: 0, p3: 0, p4: 0, pe1: 3, pe2: 3"`
- **Manual Answer**: `leaf1: 0개, leaf2: 0개, leaf3: 0개, leaf4: 0개, p1: 0개, p2: 0개, p3: 0개, p4: 0개, pe1: 3개, pe2: 3개`
- **Classification**: DATA_ERROR
- **Rationale**: [Method1-crossref] vrf_usage_statistics({'type': 'GLOBAL'}) = leaf1: 0개, leaf2: 0개, leaf3: 0개, leaf4: 0개, p1: 0개, p2: 0개, p3: 0개, p4: 0개, pe1: 3개, pe2: 3개

