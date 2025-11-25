# 네트워크 설정 검증 메트릭 분석 및 레벨 분류

## 📊 레벨 정의

| Level | 정의 | Engine | 복잡도 |
|-------|------|--------|--------|
| **L1** | 단일 장비 설정값 조회 | JSON 파싱 | ⭐ |
| **L2** | 복수 장비 설정값 집계 | JSON 파싱 | ⭐⭐ |
| **L3** | 복수 장비 + 계산/비교 | JSON 파싱 | ⭐⭐⭐ |
| **L4** | 네트워크 흐름 도달성 | Batfish | ⭐⭐⭐⭐ |
| **L5** | What-If / Differential | Batfish | ⭐⭐⭐⭐⭐ |

---

## 🎯 데이터셋 품질 개선 전략

### L1 샘플링
- **문제점**: 모든 장비 × L1 메트릭 = 과도한 반복 질문
- **해결**: 랜덤 샘플링으로 장비 30%만 선택 (기본값)
- **CLI 옵션**: `--l1-sample-ratio 0.3`

### L3 비교 질문 추가
- **목적**: LLM의 추론 능력 테스트
- **방식**: 모든 장비 쌍 조합 (CE-PE 포함)
- **Scope**: `DEVICE_PAIR` (host1, host2)

---

## 📋 최종 메트릭 목록 (총 55개)

### 🔹 L1: 단일 장비 설정값 조회 (31개)

#### System_Inventory (9개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `system_hostname_text` | text | 장비 호스트네임 |
| `system_version_text` | text | OS 버전 |
| `system_timezone_text` | text | 시간대 설정 |
| `system_user_list` | set | 로컬 사용자 목록 |
| `system_user_count` | numeric | 로컬 사용자 수 |
| `logging_buffered_severity_text` | text | 로깅 레벨 |
| `ntp_server_list` | set | NTP 서버 목록 ✨신규 |
| `snmp_community_list` | set | SNMP 커뮤니티 목록 ✨신규 |
| `syslog_server_list` | set | Syslog 서버 목록 ✨신규 |

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

#### Services_Inventory (7개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `vrf_names_set` | set | VRF 이름 목록 |
| `vrf_count` | numeric | VRF 수 |
| `vrf_rd_map` | map | VRF별 RD 값 |
| `rt_import_count` | numeric | RT Import 수 |
| `rt_export_count` | numeric | RT Export 수 |
| `mpls_ldp_present_bool` | boolean | MPLS LDP 설정 여부 |
| `l2vpn_pw_id_set` | set | L2VPN PW-ID 목록 |

---

### 🔹 L2: 복수 장비 설정값 집계 (9개)

#### Security_Policy (6개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `ssh_enabled_devices` | set | SSH 활성화 장비 목록 |
| `ssh_missing_devices` | set | SSH 미설정 장비 목록 |
| `ssh_missing_count` | numeric | SSH 미설정 장비 수 |
| `aaa_enabled_devices` | set | AAA 활성화 장비 목록 |
| `aaa_missing_devices` | set | AAA 미설정 장비 목록 |
| `devices_with_same_vrf` | set | 동일 VRF 사용 장비 목록 ✨신규 |

#### OSPF_Consistency (2개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `ospf_area_membership` | set | 특정 Area 소속 장비 목록 ✨신규 |
| `ospf_area0_if_count` | numeric | Area 0 인터페이스 수 |

#### L2VPN_Consistency (1개)
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `l2vpn_pairs` | set | L2VPN 회선 목록 |

---

### 🔹 L3: 복수 장비 + 계산/검증 (17개)

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

#### Comparison_Analysis (8개) ✨신규
| 메트릭 | 타입 | 설명 |
|--------|------|------|
| `compare_bgp_neighbor_count` | boolean | 두 장비의 BGP 피어 수 비교 |
| `compare_interface_count` | boolean | 두 장비의 인터페이스 수 비교 |
| `compare_vrf_count` | boolean | 두 장비의 VRF 수 비교 |
| `compare_bgp_as` | boolean | 두 장비가 같은 AS 소속인지 확인 |
| `compare_ospf_areas` | boolean | 두 장비의 OSPF Area 참여 비교 |
| `max_interface_device` | text | 인터페이스 수가 가장 많은 장비 |
| `max_bgp_peer_device` | text | BGP 피어가 가장 많은 장비 |
| `all_devices_same_as` | boolean | 모든 장비가 같은 AS 소속인지 확인 |

---

### 🔹 L4: 네트워크 도달성 분석 (Batfish) - 3개

| 메트릭 | 타입 | 설명 | Batfish API |
|--------|------|------|-------------|
| `traceroute_path` | set | 네트워크 경로 | `bf.q.traceroute()` |
| `reachability_status` | boolean | 도달 가능 여부 | `bf.q.reachability()` |
| `acl_blocking_point` | text | ACL 차단 지점 | `bf.q.reachability()` |

---

### 🔹 L5: What-If / Differential 분석 (Batfish) - 3개

| 메트릭 | 타입 | 설명 | Batfish API |
|--------|------|------|-------------|
| `link_failure_impact` | boolean | 링크 장애 영향 | `bf.q.differentialReachability()` |
| `config_change_impact` | boolean | 설정 변경 영향 | `bf.q.differentialReachability()` |
| `policy_compliance_check` | boolean | 정책 준수 검증 | `bf.q.searchFilters()` |

---

## ❌ 삭제된 메트릭 (13개)

| 메트릭 | 삭제 이유 |
|--------|----------|
| `vty_password_secret_text` | 보안 민감 정보 노출 위험 |
| `vty_first_last_text` | 실용성 낮음 |
| `ios_config_register_text` | 부팅 설정, 일반 운영에 불필요 |
| `system_mgmt_address_text` | hostname으로 충분 |
| `http_server_enabled_bool` | 보안 스캔 수준, 중요도 낮음 |
| `ip_forward_protocol_nd_bool` | 너무 세부적 |
| `ip_cef_enabled_bool` | 기본 활성화, 검증 불필요 |
| `interface_mop_xenabled_bool` | 레거시 설정 |
| `system_users_detail_map` | 과도한 정보, user_list로 충분 |
| `password_policy_present_bool` | 구현 복잡, 실용성 낮음 |
| `interface_vlan_set` | 서브인터페이스로 대체 가능 |
| `ebgp_remote_as_map` | neighbor_list_ebgp로 충분 |
| `ibgp_update_source_missing_set` | 실용성 낮음 |

---

## 📚 참고 표준

### CIS Benchmarks (Center for Internet Security)
- ✅ SSH 활성화 여부
- ✅ AAA 인증 설정
- ✅ VTY 라인 보안 (transport input ssh)
- ✅ 로깅 설정
- ✅ NTP 동기화

### NIST SP 800-53
- **AC (Access Control)**: SSH, AAA, VTY 설정
- **AU (Audit)**: 로깅 설정 (logging buffered)
- **CM (Configuration Management)**: 시스템 버전, 호스트네임

### Cisco SAFE Architecture
- SSH v2 사용
- AAA 인증 필수
- 적절한 로깅 레벨
- NTP 시간 동기화

---

---

## 📊 예상 문제 수 (10장비 토폴로지 기준)

### 기본 설정 (L1 샘플링 30%)
| 레벨 | 메트릭 수 | 확장 방식 | 예상 문제 수 |
|------|----------|----------|-------------|
| L1 | 31 | 3장비 × 31 | ~93개 |
| L2 | 9 | GLOBAL | ~9개 |
| L3 | 17 | AS/GLOBAL/DEVICE_PAIR | ~60개 |
| **합계** | | | **~162개** |

### L3 비교 질문 상세
- `DEVICE_PAIR` scope: C(10,2) = 45개 조합
- 비교 메트릭 5개 × 45쌍 = 225개 (필터링 후 ~50개)

---

## 🔄 변경 이력

| 버전 | 날짜 | 변경 내용 |
|------|------|----------|
| 2.1 | 2024-11 | L1 랜덤 샘플링, L3 비교 질문 추가 |
| 2.0 | 2024-11 | L1-L5 레벨 체계 정립, 불필요한 메트릭 삭제 |
| 1.0 | 2024-10 | 초기 버전 |
