# Method 3 외부 검증 우선순위

## 목적

Method 3는 `L4-L5`를 PNETLab에서 실제로 확인하는 표본 검증이다.
시간이 제한되어 있으므로 모든 샘플을 한 번에 보지 말고, 아래 우선순위 순서로 진행한다.

## 우선순위 기준

### Tier 1: 가장 먼저 검증

이 메트릭들은 Batfish 의미론 의존도가 높고, 논문에서 질문을 받을 가능성이 가장 높다.

- `root_cause_analysis`
- `link_failure_impact`
- `policy_compliance_check`
- `spof_detection`
- `redundant_paths_list`
- `multi_link_failure_reachability`
- `config_change_impact`
- `differential_reachability`

### Tier 2: 그 다음 검증

- `node_failure_impact`
- `redundancy_verification`
- `triple_node_failure`
- `worst_case_failure_analysis`
- `security_policy_bypass_check`

### Tier 3: 마지막 검증

- `reachability_status`
- `traceroute_path`
- `acl_blocking_point`
- `waypoint_traversal_path`
- `asymmetric_path_comparison`
- `bounded_path_length`
- `blackhole_destination_list`
- `loop_detection`
- `leaked_prefixes_list`
- `ospf_area0_routers`
- `non_existent_node_check`

## Lab별 1차 검증 권장 세트

아래 항목은 각 Lab에서 가장 먼저 확인할 `qa_id` 목록이다.

### LabA

- `ROOT_CAUSE_leaf4_leaf3`
- `ROOT_CAUSE_leaf4_p4`
- `ROOT_CAUSE_pe2_leaf3`
- `POLICY_COMPLIANCE_leaf1`
- `SPOF_DETECTION_GLOBAL`
- `K_FAILURE_leaf1_p3`
- `MULTI_FAIL_leaf1_p1_leaf2_p4`
- `CONFIG_CHANGE_BASELINE`
- `DIFF_REACH_BASELINE`

### LabB

- `ROOT_CAUSE_leaf1_p4`
- `ROOT_CAUSE_leaf6_p3`
- `ROOT_CAUSE_leaf6_pe1`
- `POLICY_COMPLIANCE_leaf6`
- `SPOF_DETECTION_GLOBAL`
- `K_FAILURE_leaf6_p7`
- `MULTI_FAIL_leaf1_leaf7_leaf2_leaf3`
- `CONFIG_CHANGE_BASELINE`
- `DIFF_REACH_BASELINE`

### LabC

- `ROOT_CAUSE_leaf10_leaf6`
- `ROOT_CAUSE_leaf5_p5`
- `ROOT_CAUSE_p10_leaf6`
- `LINK_FAILURE_asbr1_p7`
- `LINK_FAILURE_asbr1_p9`
- `POLICY_COMPLIANCE_p10`
- `SPOF_DETECTION_GLOBAL`
- `K_FAILURE_p7_p8`
- `CONFIG_CHANGE_BASELINE`
- `DIFF_REACH_BASELINE`
- `SEC_BYPASS_p7_p8_p10`

### LabD

- `ROOT_CAUSE_leaf10_leaf7`
- `ROOT_CAUSE_p10_leaf7`
- `ROOT_CAUSE_p10_leaf9`
- `LINK_FAILURE_asbr1_p7`
- `LINK_FAILURE_asbr1_p9`
- `POLICY_COMPLIANCE_asbr1`
- `SPOF_DETECTION_GLOBAL`
- `K_FAILURE_p7_fw1`
- `CONFIG_CHANGE_BASELINE`
- `DIFF_REACH_BASELINE`
- `SEC_BYPASS_p7_fw1_asbr1`

## 2차 검증 권장 세트

Tier 1을 끝낸 뒤 아래 항목을 추가한다.

### 공통

- `NODE_FAILURE_*`
- `DUAL_FAILURE_*`
- `TRIPLE_FAILURE_*`
- `WORST_CASE_FAILURE`

### LabC/LabD 공통

- `SEC_BYPASS_*`
- `LINK_FAILURE_*`

## 실행 규칙

1. 각 Lab에서 Tier 1만 먼저 수행
2. `DISAGREE`가 하나라도 나오면 같은 metric의 나머지 샘플을 즉시 추가 검증
3. `DISAGREE`가 반복되면 해당 metric은 quarantine 후보로 분류
4. `AGREE`가 지속되면 Tier 2로 이동

## 권장 운영 방식

- 하루 단위 점검:
  - LabA/B의 Tier 1
  - LabC/D의 Tier 1
- 다음 점검:
  - LabC/D의 `link_failure_impact`, `security_policy_bypass_check` 확대
- 마지막 점검:
  - traceroute/reachability/ACL 계열 L4 샘플 보강

## 참고

정확한 전체 샘플 목록은 각 Lab의 아래 파일을 기준으로 한다.

- `Dataset/verification/method3_pnetlab/sample_manifest.json`
