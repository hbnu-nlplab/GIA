# NetConfigQA 메트릭 레벨 분석 및 분류 체계

> **버전**: 3.0  
> **최종 수정일**: 2024-11  
> **작성자**: HBNU-KILAB

---

## 1. 개요

본 문서는 NetConfigQA 데이터셋 생성에 사용되는 메트릭의 레벨 분류 체계와 구현 현황을 정리합니다. 메트릭은 복잡도와 분석 방식에 따라 L1부터 L5까지 5단계로 분류됩니다.

---

## 2. 레벨 정의

| Level | 정의 | 분석 엔진 | 복잡도 |
|-------|------|----------|--------|
| **L1** | 단일 장비 설정값 조회 | JSON 파싱 | ⭐ |
| **L2** | 복수 장비 설정값 집계 | JSON 파싱 | ⭐⭐ |
| **L3** | 복수 장비 + 계산/비교 | JSON 파싱 | ⭐⭐⭐ |
| **L4** | 네트워크 도달성 분석 | Batfish | ⭐⭐⭐⭐ |
| **L5** | What-If / Differential 분석 | Batfish | ⭐⭐⭐⭐⭐ |

---

## 3. 학술적 근거

L4/L5 메트릭은 다음 학술 논문에 기반하여 설계되었습니다.

| 논문 | 학회 | 인용수 | 주요 기여 |
|------|------|--------|----------|
| **HSA** (Header Space Analysis) | NSDI 2012 | 1,000+ | Reachability, Loop-freedom, Isolation 정의 |
| **VeriFlow** | NSDI 2013 | 1,300+ | 실시간 Network-wide Invariant 검증 |
| **Batfish** | NSDI 2015 | 400+ | Config → Data Plane 분석 파이프라인 |
| **Minesweeper** | SIGCOMM 2017 | 300+ | 8가지 핵심 속성 정의 |
| **Config2Spec** | NSDI 2020 | 70+ | 정책 기반 Specification Mining |
| **DNA** | NSDI 2022 | 50+ | Differential Reachability, What-If 분석 |

---

## 4. 메트릭 목록

### 4.1 L1: 단일 장비 설정값 조회 (31개)

#### System_Inventory (9개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `system_hostname_text` | text | 장비 호스트네임 |
| `system_version_text` | text | OS 버전 |
| `system_timezone_text` | text | 시간대 설정 |
| `system_user_list` | set | 로컬 사용자 목록 |
| `system_user_count` | numeric | 로컬 사용자 수 |
| `logging_buffered_severity_text` | text | 로깅 레벨 |
| `ntp_server_list` | set | NTP 서버 목록 |
| `snmp_community_list` | set | SNMP 커뮤니티 목록 |
| `syslog_server_list` | set | Syslog 서버 목록 |

#### Security_Inventory (5개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `ssh_present_bool` | boolean | SSH 활성화 여부 |
| `ssh_version_text` | text | SSH 버전 |
| `aaa_present_bool` | boolean | AAA 설정 여부 |
| `vty_transport_input_text` | text | VTY 접속 프로토콜 |
| `vty_login_mode_text` | text | VTY 인증 방식 |

#### Interface_Inventory (4개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `interface_count` | numeric | 인터페이스 수 |
| `interface_ip_map` | map | 인터페이스별 IP |
| `subinterface_count` | numeric | 서브인터페이스 수 |
| `vrf_bind_map` | map | 인터페이스별 VRF 바인딩 |

#### Routing_Inventory (7개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `bgp_local_as_numeric` | numeric | BGP Local-AS |
| `bgp_neighbor_count` | numeric | BGP 피어 수 |
| `neighbor_list_ibgp` | set | iBGP 피어 목록 |
| `neighbor_list_ebgp` | set | eBGP 피어 목록 |
| `ospf_process_ids_set` | set | OSPF 프로세스 ID 목록 |
| `ospf_area_set` | set | OSPF Area 목록 |
| `ospf_area0_if_list` | set | Area 0 인터페이스 목록 |

#### Services_Inventory (6개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `vrf_names_set` | set | VRF 이름 목록 |
| `vrf_count` | numeric | VRF 수 |
| `vrf_rd_map` | map | VRF별 RD 값 |
| `rt_import_count` | numeric | RT Import 수 |
| `rt_export_count` | numeric | RT Export 수 |
| `mpls_ldp_present_bool` | boolean | MPLS LDP 설정 여부 |

---

### 4.2 L2: 복수 장비 설정값 집계 (9개)

#### Security_Policy (6개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `ssh_enabled_devices` | set | SSH 활성화 장비 목록 |
| `ssh_missing_devices` | set | SSH 미설정 장비 목록 |
| `ssh_missing_count` | numeric | SSH 미설정 장비 수 |
| `aaa_enabled_devices` | set | AAA 활성화 장비 목록 |
| `aaa_missing_devices` | set | AAA 미설정 장비 목록 |
| `devices_with_same_vrf` | set | 동일 VRF 사용 장비 목록 |

#### OSPF_Consistency (2개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `ospf_area_membership` | set | 특정 Area 소속 장비 목록 |
| `ospf_area0_if_count` | numeric | Area 0 인터페이스 수 |

#### L2VPN_Consistency (1개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `l2vpn_pairs` | set | L2VPN 회선 목록 |

---

### 4.3 L3: 복수 장비 + 계산/비교 (17개)

#### BGP_Consistency (5개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `ibgp_fullmesh_ok` | boolean | iBGP Full-Mesh 완성 여부 |
| `ibgp_missing_pairs` | set | iBGP 누락 쌍 목록 |
| `ibgp_missing_pairs_count` | numeric | iBGP 누락 쌍 수 |
| `ibgp_under_peered_devices` | set | 피어 부족 장비 목록 |
| `ibgp_under_peered_count` | numeric | 피어 부족 장비 수 |

#### VRF_Consistency (4개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `vrf_without_rt_pairs` | set | RT 미설정 VRF 목록 |
| `vrf_without_rt_count` | numeric | RT 미설정 VRF 수 |
| `vrf_interface_bind_count` | numeric | VRF별 인터페이스 바인딩 수 |
| `vrf_rt_list_per_device` | set | 장비별 RT 목록 |

#### L2VPN_Consistency (4개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `l2vpn_unidirectional_pairs` | set | 단방향 L2VPN 목록 |
| `l2vpn_unidir_count` | numeric | 단방향 L2VPN 수 |
| `l2vpn_pwid_mismatch_pairs` | set | PW-ID 불일치 목록 |
| `l2vpn_mismatch_count` | numeric | L2VPN 불일치 수 |

#### Comparison_Analysis (8개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `compare_bgp_neighbor_count` | text | 두 장비의 BGP 피어 수 비교 |
| `compare_interface_count` | text | 두 장비의 인터페이스 수 비교 |
| `compare_vrf_count` | text | 두 장비의 VRF 수 비교 |
| `compare_bgp_as` | boolean | 두 장비가 같은 AS 소속인지 확인 |
| `compare_ospf_areas` | boolean | 두 장비의 OSPF Area 참여 비교 |
| `max_interface_device` | text | 인터페이스 수가 가장 많은 장비 |
| `max_bgp_peer_device` | text | BGP 피어가 가장 많은 장비 |
| `all_devices_same_as` | boolean | 모든 장비가 같은 AS 소속인지 확인 |

---

### 4.4 L4: 네트워크 도달성 분석 (Batfish 기반, 14개)

#### 학술 기반 메트릭 (8개)
| 메트릭 | 타입 | Batfish API | 출처 논문 |
|--------|------|-------------|----------|
| `traceroute_path` | set | `bf.q.traceroute()` | Batfish |
| `reachability_status` | boolean | `bf.q.reachability()` | HSA, VeriFlow |
| `acl_blocking_point` | text | `bf.q.reachability()` | HSA |
| `loop_detection` | set | `bf.q.detectLoops()` | HSA, VeriFlow |
| `blackhole_detection` | set | `bf.q.reachability()` | HSA, Minesweeper |
| `waypoint_check` | set | `bf.q.traceroute()` | Minesweeper, Config2Spec |
| `bounded_path_length` | number | `bf.q.traceroute()` | Minesweeper |
| `isolation_check` | set | `bf.q.routes()` | HSA, Config2Spec |

#### 현업 실무 메트릭 (6개)
| 메트릭 | 타입 | 설명 | 현업 중요도 |
|--------|------|------|------------|
| `asymmetric_path_check` | boolean | 비대칭 경로 검사 | 매우 높음 |
| `mtu_mismatch_check` | set | MTU 불일치 검사 | 높음 |
| `ip_conflict_check` | set | IP 충돌 검사 | 높음 |
| `acl_rule_blocking` | text | ACL 차단 규칙 상세 분석 | 최고 |
| `waypoint_pass_check` | boolean | 웨이포인트(방화벽) 경유 여부 | 높음 |

---

### 4.5 L5: What-If / Differential 분석 (Batfish 기반, 7개)

> **참고**: L5 분석의 완전한 구현은 변경 전/후 **2개의 스냅샷**이 필요합니다.  
> 현재 버전에서는 단일 스냅샷 기반의 휴리스틱 분석을 제공합니다.

#### 학술 기반 메트릭 (5개)
| 메트릭 | 타입 | Batfish API | 출처 논문 |
|--------|------|-------------|----------|
| `link_failure_impact` | selection | 경로 분석 기반 추정 | DNA, Minesweeper |
| `k_failure_tolerance` | number | `bf.q.traceroute()` | Minesweeper |
| `config_change_impact` | set | `bf.q.differentialReachability()` | DNA |
| `differential_reachability` | text | `bf.q.differentialReachability()` | DNA |
| `policy_compliance_check` | boolean | `bf.q.reachability()` | Config2Spec |

#### 현업 실무 메트릭 (2개)
| 메트릭 | 타입 | 설명 | 현업 중요도 |
|--------|------|------|------------|
| `spof_detection` | set | 단일 장애점(SPOF) 탐지 | 매우 높음 |
| `backbone_continuity` | boolean | OSPF 백본 연속성 검증 | 높음 |

---

## 5. 링크 장애 영향 분석 (L5) 답변 형식

`link_failure_impact` 메트릭은 채점 정확도를 위해 **분류형(Selection)** 답변을 사용합니다.

| 답변 | 설명 |
|------|------|
| **영향 없음** | 현재 경로가 장애 링크를 경유하지 않음 |
| **경로 변경** | 장애 링크 사용하지만 대체 경로 존재 |
| **통신 단절** | 모든 경로가 장애 링크에 의존, 대체 경로 없음 |

---

## 6. 데이터셋 품질 개선 전략

### 6.1 L1 샘플링
- **문제점**: 모든 장비 × L1 메트릭 = 과도한 반복 질문
- **해결**: 랜덤 샘플링으로 장비 90% 선택 (기본값)
- **CLI 옵션**: `--l1-sample-ratio 0.9`

### 6.2 L3 비교 질문
- **목적**: LLM의 추론 능력 테스트
- **방식**: 장비 쌍 조합 비교
- **Scope**: `DEVICE_PAIR` (host1, host2)

### 6.3 랜덤 셔플
- **목적**: 질문 다양성 확보
- **방식**: 노드 쌍 순서 랜덤화
- **효과**: 매번 다른 순서로 질문 생성

---
