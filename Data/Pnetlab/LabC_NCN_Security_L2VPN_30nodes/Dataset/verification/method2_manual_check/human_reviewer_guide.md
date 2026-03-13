# Method 2 — Human Reviewer Guide

> **목적**: 데이터셋 정답(Ground Truth)의 신뢰성을 사람이 직접 검증
> **대상**: L1-L3 계층화 표본 43개 QA
> **소요 시간**: 약 2-3시간 (QA당 3-5분)
> **필요 도구**: 텍스트 에디터 (VS Code 권장)

---

## 사전 준비

### 1. Config 파일 위치
```
Pnetlab/LabC_NCN_Security_L2VPN_30nodes/configs/
  ASBR1.cfg  ASBR2.cfg  Leaf1.cfg  Leaf10.cfg  Leaf11.cfg  Leaf12.cfg  Leaf2.cfg  Leaf3.cfg  Leaf4.cfg  Leaf5.cfg  Leaf6.cfg  Leaf7.cfg  Leaf8.cfg  Leaf9.cfg  P1.cfg  P10.cfg  P2.cfg  P3.cfg  P4.cfg  P5.cfg  P6.cfg  P7.cfg  P8.cfg  P9.cfg  PE1.cfg  PE2.cfg  PE3.cfg  PE4.cfg  PE5.cfg  PE6.cfg
```

### 2. 검증 순서
1. 아래 체크리스트의 각 QA를 순서대로 진행
2. 해당 .cfg 파일을 열고 **검증 절차**를 따라 직접 답을 도출
3. 도출한 답과 **데이터셋 정답**을 비교
4. `blank_checklist.csv`에 결과 기입

### 3. 판정 기준
| 판정 | 조건 |
|------|------|
| **AGREE** | 내가 구한 답 = 데이터셋 정답 |
| **DISAGREE** | 내가 구한 답 ≠ 데이터셋 정답 |

DISAGREE인 경우 분류:
| 분류 | 의미 |
|------|------|
| DATA_ERROR | 데이터셋 정답이 틀림 |
| REVIEWER_ERROR | 내 검증이 틀림 (재확인 필요) |
| AMBIGUITY | 질문이나 답 정의가 모호함 |
| FORMAT_MISMATCH | 값은 같은데 표기가 다름 |

### 4. 비교 규칙 (answer_type별)
| Type | 비교 방법 | 예시 |
|------|-----------|------|
| text | 대소문자 무시, 앞뒤 공백 제거 후 일치 | "PE1" = "pe1" |
| number | 숫자 변환 후 값 비교 | "3" = "3.0" |
| set | 순서 무관, 원소 일치 | ["a","b"] = ["b","a"] |
| map | 키-값 쌍 완전 일치 | {"a":1} = {"a":1} |

---

## 검증 체크리스트 (43개 QA)

### 1. BGP_LOCAL_AS_NUMERIC_leaf4
- **Level**: L1 | **Type**: number
- **질문**: leaf4 장비의 BGP Local-AS 번호는 무엇입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) Config에서 'router bgp' 명령을 찾습니다. 2) 'router bgp 65001' 형식에서 'bgp' 다음의 integer가 AS 번호입니다. 3) 하나의 장비에 여러 BGP 프로세스가 있을 수 있지만 일반적으로 하나만 설정됩니다. 4) AS 번호는 정수로 반환합니다(예: 65001). 5) BGP 설정이 없으면 null 또는 빈 값을 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 2. BGP_NEIGHBOR_COUNT_leaf7
- **Level**: L1 | **Type**: number
- **질문**: leaf7 장비의 BGP 피어(이웃)는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'router bgp' 블록을 찾습니다. 2) 블록 내에서 'neighbor <IP> remote-as <ASN>' 패턴의 라인을 모두 찾습니다. 3) IPv4와 IPv6 neighbor 모두 카운트합니다. 4) address-family별 neighbor 설정도 포함합니다. 5) peer-group 정의는 제외하고, 실제 neighbor IP만 카운트합니다. 6) 중복 제거 후 총 개수를 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 3. INTERFACE_STATUS_MAP_leaf4
- **Level**: L1 | **Type**: map
- **질문**: leaf4 장비의 각 인터페이스 상태를 알려주세요. [답변 형식: {{'인터페이스명': '상태'}}]
- **데이터셋 정답**: `{"GigabitEthernet0/0": "up", "GigabitEthernet0/7": "up"}`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) Config에서 모든 'interface'로 시작하는 블록을 찾습니다. 2) 각 interface 블록 내에서 'shutdown' 명령이 있는지 확인합니다. 3) 'shutdown' 명령이 있으면 'down', 없으면 'up'입니다(기본값은 up). 4) 'no shutdown'은 명시적으로 up 상태를 의미합니다. 5) 모든 인터페이스와 상태를 {{'interface_name': 'status'}} 형식의 딕셔너리로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 4. NEIGHBOR_LIST_IBGP_p8
- **Level**: L1 | **Type**: set
- **질문**: p8 장비와 iBGP로 연결된 피어들의 IP 주소 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'router bgp <LOCAL_AS>' 명령에서 로컬 AS 번호를 확인합니다. 2) 'neighbor <IP> remote-as <REMOTE_AS>' 라인들을 수집합니다. 3) REMOTE_AS가 LOCAL_AS와 같은 neighbor IP만 필터링합니다. 4) 예: 로컬 AS가 65001이고, 'neighbor 10.0.0.2 remote-as 65001'이면 10.0.0.2는 iBGP입니다. 5) 모든 iBGP neighbor IP를 JSON array로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 5. SNMP_COMMUNITY_LIST_leaf3
- **Level**: L1 | **Type**: set
- **질문**: leaf3 장비에 설정된 SNMP 커뮤니티 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) Config에서 'snmp-server community'로 시작하는 라인을 모두 찾습니다. 2) 'snmp-server community myString RO' 형식에서 'community' 다음의 문자열(myString)을 추출합니다. 3) 'RO'(read-only), 'RW'(read-write) 같은 권한 설정은 무시합니다. 4) ACL 번호(예: 'community public RO 10')도 무시합니다. 5) 모든 커뮤니티 문자열을 중복 제거하여 JSON array로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 6. SUBINTERFACE_COUNT_p10
- **Level**: L1 | **Type**: number
- **질문**: p10 장비에 설정된 서브인터페이스는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 'interface' 블록의 인터페이스 이름을 수집합니다. 2) 이름에 점(.)이 포함된 인터페이스만 필터링합니다(예: 'GigabitEthernet0/0.10'은 포함, 'GigabitEthernet0/0'은 제외). 3) 필터링된 인터페이스 수를 셉니다. 4) 예: 'Gi0/0.10', 'Gi0/0.20', 'Gi1/0.30' 3개가 있으면 정답은 '3'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 7. AAA_ENABLED_DEVICES
- **Level**: L2 | **Type**: set
- **질문**: AAA 기능이 활성화된 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["asbr1", "asbr2", "pe1", "pe2", "pe3", "pe4", "pe5", "pe6"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 설정을 확인합니다. 2) 'aaa new-model'이라는 정확한 설정 명령이 포함된 장비들을 찾습니다. 3) 해당 장비들의 이름을 JSON array로 수집하여 반환합니다. 설정이 되어 있어도 'no aaa new-model'로 비활성화된 경우는 제외해야 합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 8. AAA_MISSING_DEVICES
- **Level**: L2 | **Type**: set
- **질문**: AAA 기능이 비활성화된 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["leaf1", "leaf10", "leaf11", "leaf12", "leaf2", "leaf3", "leaf4", "leaf5", "leaf6", "leaf7", "leaf8", "leaf9", "p1", "p10", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 전체 장비 중 'aaa new-model' 설정이 없는 장비들을 필터링합니다. 2) 'aaa_enabled_devices' 목록에 포함되지 않은 나머지 장비들을 JSON array로 모아 반환합니다. 모든 장비가 AAA를 사용 중이라면 빈 JSON array를 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 9. DEVICES_WITH_SAME_VRF_VRF_RND
- **Level**: L2 | **Type**: set
- **질문**: VRF_RND VRF를 사용하는 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["pe1", "pe2", "pe3", "pe4"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 사용자로부터 {vrf} 이름을 입력받습니다. 2) 모든 장비의 설정을 순회하며 'ip vrf {vrf}' 또는 'vrf definition {vrf}' 명령이 존재하는지 검색합니다. 3) 해당 설정을 가진 hostname들을 중복 없이 JSON array로 추출하여 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 10. L2VPN_PAIRS
- **Level**: L2 | **Type**: set
- **질문**: 구성된 L2VPN pseudowire 회선(장비쌍) 목록을 알려주세요. [답변 형식: ['A<->B', ...]]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비에서 'xconnect <PEER_IP> <PWID>' 설정을 추출합니다. 2) PEER_IP 주소를 해당 IP를 보유한 장비 이름으로 매핑합니다. 3) (자신, 상대방) 장비 쌍을 '장비A<->장비B' 형식의 문자열로 변환합니다. 4) 중복된 쌍(A->B와 B->A)을 하나로 합쳐 전체 목록을 JSON array로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 11. OSPF_AREA0_IF_COUNT_p8
- **Level**: L2 | **Type**: number
- **질문**: p8 장비의 OSPF Area 0에 연결된 인터페이스는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `4`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 지정된 장비({host})의 OSPF 설정을 분석합니다. 2) 'network ... area 0' 범위에 포함되는 IP를 가진 인터페이스들을 식별하거나, 인터페이스 직접 설정 방식을 확인합니다. 3) 식별된 인터페이스의 총 개수를 카운트하여 반환합니다. Loopback 인터페이스가 포함되었는지도 확인이 필요합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 12. OSPF_AREA_MEMBERSHIP_1
- **Level**: L2 | **Type**: set
- **질문**: OSPF Area 1에 속한 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["asbr1", "asbr2", "p10", "p9", "pe5", "pe6"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 사용자에게 {area} 번호를 요청합니다. 2) 각 장비의 'router ospf' 블록 내부를 검사합니다. 3) 'network' 명령이나 인터페이스 설정에서 해당 {area} 번호가 명시된 경우를 찾습니다. 4) 매칭되는 설정을 가진 장비 이름들을 JSON array로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 13. OSPF_NEIGHBOR_COUNT_PER_AREA_1
- **Level**: L2 | **Type**: number
- **질문**: OSPF Area 1의 이웃 관계는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 해당 {area}에 참여하는 모든 장비와 인터페이스 정보를 수집합니다. 2) L1/L2 토폴로지 정보를 결합하여, 같은 Area 내에서 서로 연결된 인터페이스 쌍을 찾습니다. 3) 형성된 물리/논리적 링크 베이스로 네이버 관계 수를 합산하여 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 14. SSH_ENABLED_DEVICES
- **Level**: L2 | **Type**: set
- **질문**: SSH 접속이 가능한 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["asbr1", "asbr2", "leaf1", "leaf10", "leaf11", "leaf12", "leaf2", "leaf3", "leaf4", "leaf5", "leaf6", "leaf7", "leaf8", "leaf9", "p1", "p10", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "pe1", "pe2", "pe3", "pe4", "pe5", "pe6"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 설정을 순회합니다. 2) 각 장비에서 'ip ssh version 2' 명령이나 RSA 키 생성을 나타내는 'crypto key generate rsa' 등의 설정이 있는지 확인합니다. 3) VTY 라인 설정에서 'transport input ssh'가 포함되어 있는지도 체크합니다. 4) 위 조건들을 만족하여 SSH 접속이 준비된 장비들의 이름을 JSON array로 모아 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 15. SSH_MISSING_COUNT
- **Level**: L2 | **Type**: number
- **질문**: SSH 접속이 불가능한 장비는 총 몇 대입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'ssh_missing_devices' 메트릭을 통해 도출된 장비 목록의 개수를 셉니다. 2) 중복된 장비가 없는지 확인하고 정수(Integer) 값을 반환합니다. 예: 3대의 장비에 설정이 누락되었다면 정답은 '3'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 16. SSH_MISSING_DEVICES
- **Level**: L2 | **Type**: set
- **질문**: SSH 접속이 불가능한 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 전체 장비 목록 중 'ssh_enabled_devices'에 포함되지 않은 장비들을 필터링합니다. 2) 구체적으로는 'ip ssh' 관련 설정이 전혀 없거나, 'transport input'에서 ssh가 명시적으로 제외된 장비들을 찾습니다. 3) 해당 장비들의 이름을 JSON array로 반환합니다. 결과가 빈 JSON array라면 모든 장비가 안전함을 의미합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 17. ALL_DEVICES_SAME_AS
- **Level**: L3 | **Type**: text
- **질문**: 모든 장비의 BGP AS 번호를 나열해주세요. BGP가 미설정된 장비는 'AS None'으로 표시하세요. [답변 형식: '장비1: AS X, 장비2: AS None, ...']
- **데이터셋 정답**: `"asbr1: AS 65001, asbr2: AS 65001, leaf1: AS N/A, leaf10: AS N/A, leaf11: AS N/A, leaf12: AS N/A, leaf2: AS N/A, leaf3: AS N/A, leaf4: AS N/A, leaf5: AS N/A, leaf6: AS N/A, leaf7: AS N/A, leaf8: AS N/A, leaf9: AS N/A, p1: AS N/A, p10: AS N/A, p2: AS N/A, p3: AS N/A, p4: AS N/A, p5: AS N/A, p6: AS N/A, p7: AS 65000, p8: AS 65000, p9: AS N/A, pe1: AS 65000, pe2: AS 65000, pe3: AS 65000, pe4: AS 65000, pe5: AS 65001, pe6: AS 65001"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 전체 장비 목록을 순회하며 각 장비의 Config를 스캔합니다. 2) 'router bgp <AS_NUMBER>' 명령이 있으면 해당 AS 번호를 추출합니다. 3) BGP가 설정되지 않은 장비는 'AS None'으로 표시합니다. 4) 각 hostname과 AS 값을 'hostname: AS 값' 형식으로 만듭니다. 5) 모든 쌍을 쉼표와 공백(', ')으로 연결하여 하나의 문자열로 반환합니다. 예: 'PE1: AS 65000, PE2: AS 65000, ASBR1: AS 65001, SW1: AS None'.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 18. BGP_AS_DISTRIBUTION
- **Level**: L3 | **Type**: text
- **질문**: 각 AS별 장비 수 분포를 알려주세요. [답변 형식: 'AS X: N대, AS Y: M대']
- **데이터셋 정답**: `"AS 65000: 6 devices, AS 65001: 4 devices"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 AS 번호를 수집합니다. 2) 동일한 AS 번호를 가진 장비들의 대수를 카운트합니다. 3) 'AS 번호: 대수' 형식으로 나열하여 결과를 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 19. COMPARE_BGP_AS_leaf7_p7
- **Level**: L3 | **Type**: text
- **질문**: leaf7과 p7의 BGP Local AS 번호를 각각 알려주세요. [답변 형식: 'leaf7: AS X, p7: AS Y']
- **데이터셋 정답**: `"leaf7: AS N/A, p7: AS 65000"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) {host1}의 설정 파일에서 'router bgp <AS_NUMBER>' 라인을 찾습니다 (예: 'router bgp 65000'). 2) 해당 라인에서 AS 번호 X를 추출합니다. 3) {host2}에 대해 동일한 1~2 과정을 반복하여 AS 번호 Y를 추출합니다. 4) '{host1}: AS X, {host2}: AS Y' 형식으로 문자열을 조합하여 반환합니다. 예: 'PE1: AS 65000, PE2: AS 65000' 또는 'PE1: AS 65000, ASBR1: AS 65001'. 주의: BGP 설정이 없는 장비는 'AS None' 또는 '설정 없음'으로 표시합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 20. COMPARE_BGP_NEIGHBOR_COUNT_p1_p4
- **Level**: L3 | **Type**: map_str_int
- **질문**: p1과 p4의 BGP 피어 수를 비교하세요. [답변 형식: JSON {{"host1_count": <int>, "host2_count": <int>, "difference": <int>}}]
- **데이터셋 정답**: `{"difference": 0, "host1_count": 0, "host2_count": 0}`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) {host1}/{host2}의 BGP neighbor 수를 각각 계산합니다. 2) difference = |host1_count - host2_count|를 계산합니다. 3) 반드시 JSON 객체 한 개로만 반환합니다. 출력 계약: {{"host1_count": N, "host2_count": M, "difference": K}}. 예시: {{"host1_count": 10, "host2_count": 8, "difference": 2}}
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 21. COMPARE_INTERFACE_COUNT_leaf5_pe3
- **Level**: L3 | **Type**: map_str_int
- **질문**: leaf5와 pe3의 인터페이스 수를 비교하세요. [답변 형식: JSON {{"host1_count": <int>, "host2_count": <int>, "difference": <int>}}]
- **데이터셋 정답**: `{"difference": 4, "host1_count": 2, "host2_count": 6}`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) {host1}/{host2}의 인터페이스 수를 각각 계산합니다. 2) difference = |host1_count - host2_count|를 계산합니다. 3) 반드시 JSON 객체 한 개로만 반환합니다. 출력 계약: {{"host1_count": N, "host2_count": M, "difference": K}}. 예시: {{"host1_count": 50, "host2_count": 48, "difference": 2}}
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 22. COMPARE_OSPF_AREAS_leaf7_p5
- **Level**: L3 | **Type**: text
- **질문**: leaf7과 p5가 참여하는 OSPF Area 목록을 각각 알려주세요. [답변 형식: 'leaf7: Area 0, 1, p5: Area 0, 2']
- **데이터셋 정답**: `"leaf7: Area None, p5: Area 0"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) {host1}의 설정에서 'router ospf' 섹션을 찾습니다. 2) 해당 섹션 내의 'network <IP> <WILDCARD> area <AREA_ID>' 명령들을 모두 찾아 Area ID를 추출합니다 (예: 'network 10.0.0.0 0.0.0.255 area 0', 'network 192.168.1.0 0.0.0.255 area 1'). 3) 또는 인터페이스별 OSPF 설정 방식('ip ospf <PID> area <AREA_ID>')도 확인합니다. 4) 추출 한 모든 Area ID를 중복 제거하고 정렬합니다. 5) {host2}에 대해 동일한 1~4 과정을 반복합니다. 6) 결과를 '{host1}: Area A, B, ..., {host2}: Area X, Y, ...' 형식으로 조합합니다. 예: 'ABR1: Area 0, 1, 2, ABR2: Area 0, 2, 3'. 주의: Area ID는 integer(0, 1, 2) 또는 IP 형식(0.0.0.0, 0.0.0.1) 둘 다 가능합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 23. COMPARE_VRF_COUNT_leaf8_p9
- **Level**: L3 | **Type**: map_str_int
- **질문**: leaf8과 p9의 VRF 수를 비교하세요. [답변 형식: JSON {{"host1_count": <int>, "host2_count": <int>, "difference": <int>}}]
- **데이터셋 정답**: `{"difference": 0, "host1_count": 0, "host2_count": 0}`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) {host1}/{host2}의 고유 VRF 개수를 각각 계산합니다. 2) difference = |host1_count - host2_count|를 계산합니다. 3) 반드시 JSON 객체 한 개로만 반환합니다. 출력 계약: {{"host1_count": N, "host2_count": M, "difference": K}}. 예시: {{"host1_count": 15, "host2_count": 12, "difference": 3}}
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 24. IBGP_MISSING_PAIRS_65000
- **Level**: L3 | **Type**: set
- **질문**: AS 65000의 iBGP Full-Mesh에서 누락된 장비쌍 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["p7<->p8", "p7<->pe1", "p7<->pe2", "p7<->pe3", "p7<->pe4", "p8<->pe1", "p8<->pe2", "p8<->pe3", "p8<->pe4", "pe1<->pe4", "pe2<->pe3"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) AS {asn}에 소속된 모든 BGP 라우터 목록을 작성합니다(N대). 2) 이론적으로 필요한 모든 쌍(N*(N-1)/2개)을 생성합니다. 3) 실제 Config 내 'neighbor' 설정과 비교하여 없는 쌍을 찾아냅니다. 4) 누락된 쌍들을 'A<->B' 형식의 JSON array로 만들어 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 25. IBGP_MISSING_PAIRS_65001
- **Level**: L3 | **Type**: set
- **질문**: AS 65001의 iBGP Full-Mesh에서 누락된 장비쌍 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) AS {asn}에 소속된 모든 BGP 라우터 목록을 작성합니다(N대). 2) 이론적으로 필요한 모든 쌍(N*(N-1)/2개)을 생성합니다. 3) 실제 Config 내 'neighbor' 설정과 비교하여 없는 쌍을 찾아냅니다. 4) 누락된 쌍들을 'A<->B' 형식의 JSON array로 만들어 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 26. IBGP_MISSING_PAIRS_COUNT_65000
- **Level**: L3 | **Type**: number
- **질문**: AS 65000의 iBGP Full-Mesh에서 누락된 링크는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `11`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'ibgp_missing_pairs' 메트릭 작업을 통해 도출된 누락 목록의 개수를 셉니다. 2) 정수 값을 반환합니다. 이미 완벽한 Full-Mesh라면 '0'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 27. IBGP_MISSING_PAIRS_COUNT_65001
- **Level**: L3 | **Type**: number
- **질문**: AS 65001의 iBGP Full-Mesh에서 누락된 링크는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'ibgp_missing_pairs' 메트릭 작업을 통해 도출된 누락 목록의 개수를 셉니다. 2) 정수 값을 반환합니다. 이미 완벽한 Full-Mesh라면 '0'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 28. IBGP_UNDER_PEERED_COUNT_65000
- **Level**: L3 | **Type**: number
- **질문**: AS 65000에서 iBGP 피어 수가 부족한 장비는 총 몇 대입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `6`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'ibgp_under_peered_devices'를 통해 찾은 장비들의 총 대수를 셉니다. 2) integer로 반환합니다. 모든 라우터가 충실히 Peering을 맺고 있다면 '0'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 29. IBGP_UNDER_PEERED_COUNT_65001
- **Level**: L3 | **Type**: number
- **질문**: AS 65001에서 iBGP 피어 수가 부족한 장비는 총 몇 대입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'ibgp_under_peered_devices'를 통해 찾은 장비들의 총 대수를 셉니다. 2) integer로 반환합니다. 모든 라우터가 충실히 Peering을 맺고 있다면 '0'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 30. IBGP_UNDER_PEERED_DEVICES_65000
- **Level**: L3 | **Type**: set
- **질문**: AS 65000에서 iBGP 피어 수가 부족한 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) AS {asn}의 전체 BGP 라우터 수 N을 계산합니다. 2) 각 장비별로 맺고 있는 iBGP Neighbor의 수 M을 카운트합니다. 3) M < (N-1)인 조건의 장비들을 선별합니다. 4) 해당 hostname들을 JSON array로 모아 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 31. IBGP_UNDER_PEERED_DEVICES_65001
- **Level**: L3 | **Type**: set
- **질문**: AS 65001에서 iBGP 피어 수가 부족한 장비 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) AS {asn}의 전체 BGP 라우터 수 N을 계산합니다. 2) 각 장비별로 맺고 있는 iBGP Neighbor의 수 M을 카운트합니다. 3) M < (N-1)인 조건의 장비들을 선별합니다. 4) 해당 hostname들을 JSON array로 모아 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 32. L2VPN_MISMATCH_COUNT
- **Level**: L3 | **Type**: number
- **질문**: PW-ID 불일치 또는 단방향 L2VPN 회선은 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 단방향 오류 목록과 PW-ID 불일치 오류 목록을 모두 합칩니다(중복 제거). 2) 합쳐진 전체 오류 케이스의 총 개수를 집계하여 정수로 반환합니다. 모든 설정이 완벽하다면 '0'을 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 33. L2VPN_PWID_MISMATCH_PAIRS
- **Level**: L3 | **Type**: set
- **질문**: PW-ID가 불일치하는 L2VPN 회선(장비쌍) 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 'xconnect <PEER_IP> <PWID>' 설정을 수집합니다. 2) PEER_IP를 hostname으로 변환하여 (장비A, 장비B) 쌍을 만듭니다. 3) 장비A에서 지정한 PWID와 장비B에서 지정한 PWID가 서로 다른 경우를 필터링합니다. 4) 해당되는 쌍들을 'pe1<->pe2 (ID 100 vs 200)'와 같이 상세 정보와 함께 JSON array로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 34. L2VPN_UNIDIRECTIONAL_PAIRS
- **Level**: L3 | **Type**: set
- **질문**: 단방향으로만 설정된 L2VPN 회선(장비쌍) 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 Config에서 'xconnect <PEER_IP> <PWID> encapsulation mpls' 설정을 수집합니다. 2) 각 xconnect에 대해 (출발지 장비, PEER_IP가 가리키는 도착지 장비, PWID)를 기록합니다. 3) PEER_IP를 해당 IP를 가진 hostname으로 변환합니다(예: 10.0.0.2 → pe2). 4) 역방향 연결을 확인합니다: pe1→pe2(PWID:100)이 있다면, pe2→pe1(PWID:100)도 있어야 합니다. 5) 역방향이 없으면 'pe1<->pe2 (PWID:100)' 형식으로 단방향 쌍 목록에 추가합니다. 6) 모든 단방향 쌍의 목록이 정답입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 35. L2VPN_UNIDIR_COUNT
- **Level**: L3 | **Type**: number
- **질문**: 단방향으로만 설정된 L2VPN 회선은 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'l2vpn_unidirectional_pairs' 메트릭의 결과 JSON array를 가져옵니다. 2) JSON array에 포함된 단방향 오류 쌍의 개수를 셉니다. 3) 정수 값으로 반환합니다. 예: 2개의 회선이 단방향으로 설정되어 있다면 정답은 '2'입니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 36. MAX_BGP_PEER_DEVICE
- **Level**: L3 | **Type**: text
- **질문**: BGP 피어가 가장 많은 장비와 그 개수를 알려주세요. [답변 형식: '장비명: N개']
- **데이터셋 정답**: `"asbr1: 4"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 BGP 활성화 장비에서 'router bgp' 블록을 스캔합니다. 2) 각 장비별로 'neighbor <IP> remote-as' 명령의 총 개수를 카운트합니다. 3) VRF별 BGP neighbor도 포함하여 전체 neighbor 수를 집계합니다. 4) 카운트 결과를 내림차순 정렬하여 최댓값을 찾습니다. 5) 가장 많은 neighbor를 가진 장비의 이름과 개수를 'hostname: N개' 형식으로 반환합니다. 동률인 경우 알파벳 순으로 첫 번째 장비를 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 37. MAX_INTERFACE_DEVICE
- **Level**: L3 | **Type**: text
- **질문**: 인터페이스 수가 가장 많은 장비와 그 개수를 알려주세요. [답변 형식: '장비명: N개']
- **데이터셋 정답**: `"pe6: 8"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 총 인터페이스 수를 계산합니다. 2) 가장 큰 integer를 가진 장비를 선별합니다. 3) 'hostname: N개' 형식으로 반환합니다. 동률이 있을 경우 그중 하나를 반환하거나 모두 나열합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 38. MIN_INTERFACE_DEVICE
- **Level**: L3 | **Type**: text
- **질문**: 인터페이스 수가 가장 적은 장비와 그 개수를 알려주세요. [답변 형식: '장비명: N개']
- **데이터셋 정답**: `"leaf1: 2"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비의 인터페이스 개수를 계산합니다. 2) 0보다 큰 인터페이스 수 중 최소값을 찾습니다. 3) 'hostname: N개' 형식으로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 39. VRF_RT_LIST_PER_DEVICE_asbr2
- **Level**: L3 | **Type**: set
- **질문**: asbr2 장비에 설정된 route-target(중복 제거) 전체 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 지정된 장비 {host}의 모든 VRF 설정을 스캔합니다. 2) 각 VRF에 설정된 모든 'route-target' (import, export, both 모두 포함) 값들을 수집합니다. 3) 중복된 값을 제거하고 'ASN:NN' 또는 'IP:NN' 형식의 JSON array로 정렬하여 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 40. VRF_RT_LIST_PER_DEVICE_pe5
- **Level**: L3 | **Type**: set
- **질문**: pe5 장비에 설정된 route-target(중복 제거) 전체 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `["65001:400", "65001:500"]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 지정된 장비 {host}의 모든 VRF 설정을 스캔합니다. 2) 각 VRF에 설정된 모든 'route-target' (import, export, both 모두 포함) 값들을 수집합니다. 3) 중복된 값을 제거하고 'ASN:NN' 또는 'IP:NN' 형식의 JSON array로 정렬하여 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 41. VRF_USAGE_STATISTICS
- **Level**: L3 | **Type**: text
- **질문**: VRF 사용중인 장비 중에서 각 장비별 VRF 사용 수를 알려주세요. [답변 형식: '장비1: N개, 장비2: M개']
- **데이터셋 정답**: `"asbr1: 0, asbr2: 0, leaf1: 0, leaf10: 0, leaf11: 0, leaf12: 0, leaf2: 0, leaf3: 0, leaf4: 0, leaf5: 0, leaf6: 0, leaf7: 0, leaf8: 0, leaf9: 0, p1: 0, p10: 0, p2: 0, p3: 0, p4: 0, p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, pe1: 3, pe2: 3, pe3: 3, pe4: 3, pe5: 2, pe6: 2"`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비를 순회하며 각 장비에서 'ip vrf' 또는 'vrf definition' 명령을 카운트합니다. 2) 장비별로 중복 제거한 고유 VRF 이름의 개수를 계산합니다. 3) 각 hostname과 VRF 개수를 'hostname: N개' 형식으로 쌍을 만듭니다. 4) 모든 장비의 쌍을 쉼표와 공백으로 연결하여 문자열로 반환합니다. 예: 'PE1: 15개, PE2: 12개, P1: 0개'. VRF가 하나도 없는 장비도 '0개'로 명시하여 포함합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 42. VRF_WITHOUT_RT_COUNT
- **Level**: L3 | **Type**: number
- **질문**: route-target이 없는 VRF(장비/VRF)는 총 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 'vrf_without_rt_pairs' 메트릭으로 도출된 목록의 총 개수를 셉니다. 2) 정수 값을 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 

### 43. VRF_WITHOUT_RT_PAIRS
- **Level**: L3 | **Type**: set
- **질문**: route-target이 없는 VRF(장비/VRF) 목록을 알려주세요. [답변 형식: 리스트]
- **데이터셋 정답**: `[]`
- **확인할 파일**: 전체 configs/*.cfg
- **검증 절차**:
  > 검증 방법: 1) 모든 장비와 그 내부의 VRF 목록을 스캔합니다. 2) 각 VRF 블록 내에 'route-target import'와 'route-target export'(또는 both) 명령이 모두 혹은 하나라도 있는지 확인합니다. 3) RT 명령이 전혀 없는 VRF인 경우 'hostname/VRF명' 형식으로 기록합니다. 4) 해당 목록을 JSON array로 반환합니다.
- **내 답**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE → 분류: ____________
- **메모**: 
