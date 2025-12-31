# NetConfigQA 메트릭 레벨 분석 및 분류 체계

> **버전**: 4.0 (Code Sync)  
> **최종 수정일**: 2024-12-20  
> **기반 코드**: `src/core_batfish/*.py`

---

## 1. 개요

본 문서는 `NetConfigQA` 데이터셋 생성 파이프라인(`src/core_batfish/`)에 구현된 실제 메트릭의 레벨 분류와 정의를 기술합니다.
전체 분석 시스템은 **규칙 기반(Rule-based) 엔진**과 **Batfish 분석 엔진**의 하이브리드 구조로 동작하며, 복잡도에 따라 L1부터 L5까지 5단계로 분류됩니다.

---

## 2. 분석 엔진 및 레벨 정의

| Level  | 정의                     | 구현 방식 (Code)                      | 주요 엔진                                          | 복잡도     |
| ------ | ------------------------ | ------------------------------------- | -------------------------------------------------- | ---------- |
| **L1** | **단일 장비 설정 조회**  | Regex Parsing + Batfish Questions     | `batfish_parser.py` <br> `rule_based_generator.py` | ⭐         |
| **L2** | **복수 장비 설정 집계**  | Python Logic (Set/Count Aggregation)  | `rule_based_generator.py`                          | ⭐⭐       |
| **L3** | **장비 간 정합성 비교**  | Cross-Device Logic Check              | `rule_based_generator.py`                          | ⭐⭐⭐     |
| **L4** | **네트워크 도달성 분석** | Traceroute & Reachability Query       | `l4_analyzer.py` (Batfish)                         | ⭐⭐⭐⭐   |
| **L5** | **What-If / 장애 분석**  | Snapshot Fork & Differential Analysis | `l5_analyzer.py` (Batfish)                         | ⭐⭐⭐⭐⭐ |

---

## 3. 메트릭 상세 목록 (Implemented Metrics)

### 3.1 L1: 단일 장비 설정 조회 (Single Device Inventory)

> **구현**: `batfish_parser.py`에서 텍스트 파싱 및 Batfish Question 결과 추출 후 `rule_based_generator.py`에서 질문 생성

#### System & Services

| 메트릭 ID                        | 타입    | 설명                          |
| -------------------------------- | ------- | ----------------------------- |
| `system_hostname_text`           | text    | 장비 호스트네임               |
| `system_version_text`            | text    | OS 버전                       |
| `system_timezone_text`           | text    | 시간대 설정                   |
| `system_user_list`               | set     | 로컬 사용자 목록              |
| `system_user_count`              | numeric | 로컬 사용자 수                |
| `logging_buffered_severity_text` | text    | 로깅 버퍼 Severity 레벨       |
| `ntp_server_list`                | set     | NTP 서버 목록                 |
| `snmp_community_list`            | set     | SNMP 커뮤니티 문자열 목록     |
| `syslog_server_list`             | set     | Syslog 서버 목록              |
| `ssh_present_bool`               | boolean | SSH 서비스 활성화 여부        |
| `ssh_version_text`               | text    | SSH 프로토콜 버전             |
| `aaa_present_bool`               | boolean | AAA (New Model) 활성화 여부   |
| `vty_transport_input_text`       | text    | VTY 라인 Transport Input 설정 |
| `vty_login_mode_text`            | text    | VTY 라인 로그인 방식          |

#### Interface & Routing

| 메트릭 ID                   | 타입    | 설명                             |
| --------------------------- | ------- | -------------------------------- |
| `interface_count`           | numeric | 전체 인터페이스 개수             |
| `interface_ip_map`          | map     | 인터페이스명-IP 매핑             |
| `subinterface_count`        | numeric | 서브인터페이스(.x) 개수          |
| `interface_status_map`      | map     | 인터페이스 Up/Down 상태          |
| `routing_table_entry_count` | number  | 라우팅 테이블 엔트리 수          |
| `bgp_local_as_numeric`      | numeric | BGP Local AS 번호                |
| `bgp_neighbor_count`        | numeric | BGP Neighbor 개수                |
| `neighbor_list_ibgp`        | set     | iBGP Neighbor IP 목록            |
| `neighbor_list_ebgp`        | set     | eBGP Neighbor IP 목록            |
| `ospf_process_ids_set`      | set     | OSPF 프로세스 ID 목록            |
| `ospf_area_set`             | set     | 참여 중인 OSPF Area 목록         |
| `ospf_area0_if_list`        | set     | OSPF Area 0(Backbone) 인터페이스 |

#### MPLS & VRF

| 메트릭 ID               | 타입    | 설명                           |
| ----------------------- | ------- | ------------------------------ |
| `vrf_names_set`         | set     | 정의된 VRF 이름 목록           |
| `vrf_count`             | numeric | VRF 개수                       |
| `vrf_rd_map`            | map     | VRF별 Route Distinguisher (RD) |
| `vrf_bind_map`          | map     | 인터페이스별 VRF 바인딩        |
| `rt_import_count`       | numeric | Route Target Import 개수       |
| `rt_export_count`       | numeric | Route Target Export 개수       |
| `mpls_ldp_present_bool` | boolean | MPLS LDP 활성화 여부           |
| `l2vpn_pw_id_set`       | set     | L2VPN Pseudowire ID 목록       |

---

### 3.2 L2: 복수 장비 설정 집계 (Multi-Device Aggregation)

> **구현**: `rule_based_generator.py`에서 전체 장비 데이(`GLOBAL` scope)를 순회하며 집계

| 메트릭 ID                      | 타입    | 설명                                  |
| ------------------------------ | ------- | ------------------------------------- |
| `ssh_enabled_devices`          | set     | SSH가 활성화된 장비 목록              |
| `ssh_missing_devices`          | set     | SSH가 비활성화된(보안 취약) 장비 목록 |
| `ssh_missing_count`            | numeric | SSH 미설정 장비 개수                  |
| `aaa_enabled_devices`          | set     | AAA가 활성화된 장비 목록              |
| `aaa_missing_devices`          | set     | AAA가 미설정된 장비 목록              |
| `devices_with_same_vrf`        | set     | 특정 VRF가 설정된 장비 목록           |
| `ospf_area_membership`         | set     | 특정 OSPF Area에 소속된 장비 목록     |
| `ospf_area0_if_count`          | numeric | 전체 망의 OSPF Area 0 인터페이스 총합 |
| `ospf_neighbor_count_per_area` | number  | 특정 Area 내의 총 OSPF Neighbor 수    |
| `l2vpn_pairs`                  | set     | 구성된 L2VPN 회선(Source-Dest) 목록   |
| `devices_in_as`                | set     | 특정 AS 번호를 사용하는 장비 목록     |
| `interfaces_in_vrf`            | number  | 특정 VRF에 속한 전체 인터페이스 수    |

---

### 3.3 L3: 장비 간 정합성 비교 (Cross-Device Consistency)

> **구현**: `rule_based_generator.py`에서 장비 쌍(`DEVICE_PAIR`) 또는 프로토콜 정합성 로직 수행

#### Consistency Checks

| 메트릭 ID                    | 타입    | 설명                                        |
| ---------------------------- | ------- | ------------------------------------------- |
| `ibgp_fullmesh_ok`           | text    | AS 내 iBGP Full-Mesh 구성 검증 (OK/Missing) |
| `ibgp_missing_pairs`         | set     | iBGP Full-Mesh 위반 링크 목록               |
| `ibgp_missing_pairs_count`   | numeric | iBGP 위반 링크 개수                         |
| `ibgp_under_peered_devices`  | set     | iBGP 피어링 개수가 부족한 장비              |
| `vrf_without_rt_pairs`       | set     | RT(Route-Target)가 누락된 VRF 목록          |
| `vrf_without_rt_count`       | numeric | RT 누락 VRF 개수                            |
| `l2vpn_unidirectional_pairs` | set     | 단방향으로만 설정된(설정 오류) L2VPN 목록   |
| `l2vpn_unidir_count`         | numeric | 단방향 L2VPN 개수                           |
| `l2vpn_pwid_mismatch_pairs`  | set     | 양측 PW-ID가 다른 L2VPN 목록                |
| `l2vpn_mismatch_count`       | numeric | PW-ID 불일치 L2VPN 개수                     |

#### Comparative Analysis

| 메트릭 ID                    | 타입 | 설명                                    |
| ---------------------------- | ---- | --------------------------------------- |
| `compare_bgp_neighbor_count` | text | 두 장비의 BGP Neighbor 수 비교          |
| `compare_interface_count`    | text | 두 장비의 인터페이스 수 비교            |
| `compare_vrf_count`          | text | 두 장비의 VRF 수 비교                   |
| `compare_bgp_as`             | text | 두 장비의 AS 번호 비교                  |
| `compare_ospf_areas`         | text | 두 장비의 OSPF Area 참여 현황 비교      |
| `max_interface_device`       | text | 망 내에서 인터페이스가 가장 많은 장비   |
| `max_bgp_peer_device`        | text | 망 내에서 BGP Neighbor가 가장 많은 장비 |
| `min_interface_device`       | text | 망 내에서 인터페이스가 가장 적은 장비   |
| `all_devices_same_as`        | text | 모든 장비가 동일 AS인지 여부 확인       |
| `bgp_as_distribution`        | text | AS 번호별 장비 분포 통계                |
| `vrf_usage_statistics`       | text | 장비별 VRF 사용 개수 통계               |

---

### 3.4 L4: 네트워크 도달성 분석 (Network Reachability)

> **구현**: `l4_analyzer.py` (L4AnalyzerMixin) - Batfish Traceroute/Reachability API 활용

| 메트릭 ID                      | Batfish API      | 설명 및 반환 형태                                                   |
| ------------------------------ | ---------------- | ------------------------------------------------------------------- |
| `traceroute_path`              | `traceroute`     | 출발지에서 목적지까지의 경로 (홉-바이-홉)                           |
| `reachability_status`          | `traceroute`     | 도달 가능 여부 (Reachable/Unreachable) 및 경로                      |
| `acl_blocking_point`           | `reachability`   | 트래픽 차단 시 ACL에 의해 드랍된 장비 위치                          |
| `loop_detection`               | `detectLoops`    | 포워딩 루프(Loop) 존재 여부 및 경로                                 |
| `blackhole_detection`          | `reachability`   | 트래픽이 소멸(Drop/Null)되는 블랙홀 지점 탐지                       |
| `waypoint_check`               | `traceroute`     | 트래픽이 특정 보안 장비(방화벽 등)를 경유하는지 검증                |
| `bounded_path_length`          | `traceroute`     | 경로의 길이(Hop Count) 계산                                         |
| `isolation_check`              | `interfaceProps` | VRF/테넌트 간 트래픽 누수(Leak) 여부 확인                           |
| `asymmetric_path_check`        | `traceroute`     | 순방향(Forward)과 역방향(Reverse) 경로 일치 여부                    |
| `mtu_mismatch_check`           | `layer3Edges`    | L3 링크 간 MTU 설정 불일치 검사                                     |
| `ospf_compatibility_check`     | `ospfConfig`     | **[Advanced]** OSPF 네이버 형성 실패 원인(Area, Hello/Dead 등) 분석 |
| `security_policy_bypass_check` | `traceroute`     | **[Advanced]** 보안 장비 우회 가능 경로 존재 여부 탐지              |
| `acl_rule_blocking`            | `testFilters`    | 특정 트래픽을 차단하는 ACL 규칙(Rule) 및 라인 번호 식별             |

---

### 3.5 L5: What-If 및 장애 영향 분석 (Failure Impact)

> **구현**: `l5_analyzer.py` (L5AnalyzerMixin) - Snapshot Fork & Differential Reachability 활용

| 메트릭 ID                     | Batfish API      | 설명 및 반환 형태                                                      |
| ----------------------------- | ---------------- | ---------------------------------------------------------------------- |
| `link_failure_impact`         | `fork_snapshot`  | 특정 링크 다운 시 트래픽 경로 변화(Rerouted/Disconnected)              |
| `config_change_impact`        | `differential`   | 설정 변경 전/후의 트래픽 흐름 변화 자동 탐지                           |
| `policy_compliance_check`     | `reachability`   | 특정 보안 정책(Waypointing 등) 위반 흐름 전수 조사                     |
| `k_failure_tolerance`         | `traceroute`     | 다중 경로(Multipath) 가용성 및 k-failure 내성 검증                     |
| `spof_detection`              | `traceroute`     | 단일 장애점(SPOF)이 되는 노드 식별                                     |
| `root_cause_analysis`         | `traceroute`     | **[Advanced]** 통신 단절의 근본 원인(ACL, No Route, Loop 등) 상세 분석 |
| `blast_radius_estimation`     | `layer3Edges`    | **[Advanced]** 노드 장애 시 영향받는 인접 장비 및 범위 추정            |
| `multi_link_failure_analysis` | `traceroute`     | **[Advanced]** 2개 이상의 링크 동시 장애 시 고립 여부 분석             |
| `ip_conflict_check`           | `interfaceProps` | **[Static]** 망 전체에서의 IP 주소 중복 할당 검사                      |

---

## 4. 데이터셋 생성 로직 (Logic)

1.  **Rule-based Generation (L1~L3)**:

    - `batfish_parser.py`가 Config 파일을 1차 파싱하여 `facts` 딕셔너리 생성.
    - `rule_based_generator.py`가 `GOAL2METRICS` 매핑 테이블을 사용하여 `facts`에서 정답을 추출함.
    - Regex로 추출한 정보(OS 버전, SSH 등)와 Batfish가 추출한 정보(BGP, OSPF)가 결합됨.

2.  **Batfish Analysis (L4~L5)**:
    - 질문 생성 시점에 실시간으로 Batfish 쿼리를 수행하여 정답(Ground Truth)을 계산함 (`AnswerResult` 객체).
    - L5의 경우 `fork_snapshot`을 통해 가상의 장애 상황 스냅샷을 생성하고 비교 분석 수행.

---

## 5. 참고 사항

- **하이브리드 파싱**: Batfish는 표준 라우팅 설정 파싱에 강점이 있으나, `logging`, `user`, `ntp` 등의 시스템 설정 파싱은 제한적일 수 있어 Regex 기반 파서를 병행 사용함.
- **답변 타입**: 모든 답변은 명확한 채점을 위해 `set`, `numeric`, `text`, `boolean`, `map` 등의 타입으로 정규화(`canonicalize`)되어 JSON 형태로 저장됨.
