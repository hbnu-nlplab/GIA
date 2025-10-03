# Metrics Reference

각 메트릭은 XML facts에서 특정 정보를 계산해 질문과 정답을 생성할 때 사용됩니다. 아래 표는 현재 파이프라인에서 지원하는 메트릭과 의미, 반환 타입, 대표 질문 예시를 정리한 것입니다. 범주는 `policies.json`에서 정의한 카테고리를 기준으로 묶었습니다.

## BGP_Consistency
| Metric | Type | 질문 예시 | 설명 |
| --- | --- | --- | --- |
| `ibgp_fullmesh_ok` | boolean | "AS 65000의 iBGP 풀메시 구성은 완벽합니까?" | AS 내부 모든 장비가 서로 iBGP로 연결돼 있는지 검사합니다. 누락된 피어가 있으면 `false`입니다. |
| `ibgp_missing_pairs` | set | "AS 65000의 iBGP 풀메시에서 누락된 장비쌍을 알려주세요." | 풀메시에서 빠진 장비쌍을 `장비A↔장비B` 형식으로 나열합니다. |
| `ibgp_missing_pairs_count` | numeric | 위 질문의 개수 버전 | 누락된 장비쌍의 총 개수를 반환합니다. |
| `ibgp_under_peered_devices` | set | "AS 65000에서 iBGP 피어 수가 부족한 장비는?" | 기대되는 피어 수에 미치지 못한 장비명을 반환합니다. |
| `ibgp_under_peered_count` | numeric | 위 질문의 개수 버전 | 피어가 부족한 장비 수를 제공합니다. |
| `neighbor_list_ibgp` / `neighbor_list_ebgp` | set | "CE1 장비의 iBGP/eBGP 피어 목록은?" | 장비의 iBGP/eBGP 피어 IP 또는 호스트명을 모두 나열합니다. |
| `ebgp_remote_as_map` | map | "CE1 장비의 eBGP 피어와 원격 AS 번호는?" | eBGP 피어별 원격 AS를 `피어=AS` 형식으로 제공합니다. |
| `ibgp_update_source_missing_set` | set | "update-source 설정이 빠진 iBGP 피어는?" | update-source가 비어 있는 iBGP 피어를 `장비~피어`로 표기합니다. |

## VRF_Consistency
| Metric | Type | 설명 |
| --- | --- | --- |
| `vrf_rd_map` | map | VRF 이름과 RD(Route Distinguisher)를 `VRF=RD` 형식으로 제공합니다. |
| `vrf_rt_list_per_device` | set | 장비 전체의 Route-Target 목록을 중복 없이 정리합니다. |
| `vrf_without_rt_pairs` / `vrf_without_rt_count` | set / numeric | RT 설정이 없는 `(장비, VRF)` 쌍과 그 개수입니다. |
| `vrf_interface_bind_count` | numeric | 특정 장비·VRF에 바인딩된 인터페이스 수입니다. |
| `vrf_rd_format_invalid_set` | set | RD 문자열이 `ASN:번호` 또는 `IP:번호` 형식이 아닌 VRF 목록입니다. |

## L2VPN_Consistency
| Metric | Type | 설명 |
| --- | --- | --- |
| `l2vpn_pairs` | set | 구성된 L2VPN 회선을 `장비A↔장비B`로 표시합니다. |
| `l2vpn_unidirectional_pairs` / `l2vpn_unidir_count` | set / numeric | 단방향으로만 연결된 회선 목록/개수입니다. |
| `l2vpn_pwid_mismatch_pairs` / `l2vpn_mismatch_count` | set / numeric | PW-ID가 일치하지 않는 회선 목록/개수입니다. |

## OSPF_Consistency
| Metric | Type | 설명 |
| --- | --- | --- |
| `ospf_proc_ids` | text | 장비의 대표 OSPF 프로세스 ID (첫 번째 ID) |
| `ospf_area0_if_list` / `ospf_area0_if_count` | set / numeric | Area 0에 속한 인터페이스 목록/개수 |
| `ospf_area_set` | set | 장비가 참여하는 모든 OSPF Area ID |

## Interface_Inventory
| Metric | Type | 설명 |
| --- | --- | --- |
| `interface_count` | numeric | 장비의 인터페이스 개수 |
| `interface_ip_map` | map | 인터페이스별 IPv4 주소 (`인터페이스=IP`) |
| `interface_vlan_set` | set | 인터페이스에 설정된 VLAN ID 목록 |
| `subinterface_count` | numeric | 서브인터페이스 개수 (`인터페이스 이름에 '.' 포함`) |
| `vrf_bind_map` | map | 인터페이스별 VRF 바인딩을 `인터페이스=VRF`로 표기합니다. VRF가 없으면 `default`로 채웁니다. |

## Routing_Inventory
| Metric | Type | 설명 |
| --- | --- | --- |
| `bgp_local_as_numeric` | numeric | 장비의 로컬 BGP AS 번호 |
| `bgp_neighbor_count` | numeric | BGP 피어 수 (글로벌 + 각 VRF) |
| `ospf_process_ids_set` | set | 설정된 OSPF 프로세스 ID 집합 |
| `ospf_area_set` | set | 장비가 가입한 OSPF Area 집합 |

## Security_Policy & Security_Inventory
| Metric | Type | 설명 |
| --- | --- | --- |
| `ssh_enabled_devices` / `ssh_missing_devices` / `ssh_missing_count` | set / set / numeric | SSH가 활성화된 장비 목록, 비활성 목록, 비활성 개수를 반환합니다. |
| `ssh_present_bool` / `ssh_version_text` | boolean / text | 특정 장비의 SSH 활성 여부와 버전 문자열 |
| `aaa_present_bool` | boolean | AAA 설정 여부 |
| `aaa_enabled_devices` / `aaa_missing_devices` | set | AAA가 설정/미설정된 장비 목록 |
| `password_policy_present_bool` | boolean | 패스워드 정책 설정 여부 |
| `ssh_acl_applied_check` | boolean | VTY 라인에 SSH ACL이 적용됐는지 판단합니다. |

## Services_Inventory
| Metric | Type | 설명 |
| --- | --- | --- |
| `vrf_names_set` / `vrf_count` | set / numeric | 장비가 보유한 VRF 이름 목록과 개수 |
| `mpls_ldp_present_bool` | boolean | MPLS LDP가 활성화됐는지 |
| `l2vpn_pw_id_set` | set | L2VPN에서 사용되는 PW-ID 목록 |
| `rt_import_count` / `rt_export_count` | numeric | VRF에서 import/export하는 Route-Target 개수 |

## System_Inventory & Basic_Info
| Metric | Type | 설명 |
| --- | --- | --- |
| `system_hostname_text` / `system_mgmt_address_text` | text | 장비 호스트명, 관리 IP |
| `system_version_text` / `system_timezone_text` | text | OS 버전, 시스템 시간대 |
| `system_user_list` / `system_users_detail_map` | set / map | 사용자 계정 목록 / 상세정보 (UID, 홈 디렉터리 등) |
| `system_user_count` | numeric | 사용자 수 |
| `ios_config_register_text` | text | IOS config-register 설정 |
| `logging_buffered_severity_text` | text | logging buffered severity 수준 |
| `http_server_enabled_bool` | boolean | HTTP 서버 활성 여부 |
| `ip_forward_protocol_nd_bool` / `ip_cef_enabled_bool` | boolean | ip forward-protocol nd / CEF 사용 여부 |
| `vty_first_last_text`, `vty_login_mode_text`, `vty_password_secret_text`, `vty_transport_input_text` | text | VTY 라인 범위, 로그인 모드, 암호, transport 입력 설정을 문자열로 요약합니다. |
| `interface_mop_xenabled_bool` | boolean | 인터페이스에 MOP xenabled 옵션이 설정됐는지 |

## Command_Generation (명령어 질문)
CLI 명령을 묻는 메트릭입니다. 질문에는 장비 이름을 제공하고 정답에는 실제 명령 문자열이 포함됩니다. scope에는 관리 IP가 유지되므로 평가 시 추가 추론이 가능합니다.
- `cmd_show_*`: 조회 명령 (`show bgp summary`, `show ip ospf neighbor` 등)
- `cmd_set_*`: 설정 명령 (`router bgp ...`, `line vty ...` 등)
- `cmd_ssh_*`: SSH 접속 명령 (`ssh admin@장비`, `ssh -J ...`)

## 기타 카테고리
- **Routing_Policy_Inspection**: `bgp_advertised_prefixes_list` (광고 중인 prefix 목록)
- **QoS_Verification**: `qos_policer_applied_interfaces_list` (QoS policer가 적용된 인터페이스 목록)
- **Security_Compliance**: `ssh_acl_applied_check` (SSH ACL 적용 여부)

## 새로운 메트릭을 추가하려면?
1. `Make_Dataset/src/core/builder_core.py`의 `_answer_for_metric`에 계산 로직을 구현합니다.
2. `policies.json`에서 사용할 카테고리/level에 `primary_metric` 또는 `goal`을 추가합니다.
3. 질문 후처리(`Make_Dataset/src/main.py`)에 추가 포맷 필요 여부를 확인합니다.

---

## 참고 문서
- 파이프라인 개요: [../README.md](../README.md)
- 실행 방법: [Getting Started](Getting_Started.md)
- 정책 구조: [Policies](Policies.md)
- 데이터 포맷: [Dataset Format](Dataset_Format.md)
