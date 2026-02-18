# 실험실 확장 & Config Generator 설계서

> **목적**: 네트워크 규모(10→20→30→40 노드)와 도메인 다양성에 따른 LLM 성능 변화를 분석하기 위한 실험 환경 설계
> **핵심 원칙**: 설정 파일만 생성하면 QA 파이프라인이 자동으로 데이터셋 생성 → PNETLab에 복붙하면 바로 적용

---

## 0. 구현 상태 리베이스 (2026-02-13)

| 항목 | 현재 상태 | 조치 |
|---|---|---|
| Lab-A (10노드) | ✅ 완료 (v2 1,128 QA) | 검증 보강 후 재실험 |
| Lab-B (20노드) | ✅ Config 생성 완료 (NCN_Basic_SP) | PNETLab 배포 → 데이터셋 생성 |
| Lab-C (30노드) | ✅ Config 생성 완료 (30/30 cfg) | PNETLab 배포 → 데이터셋 생성 |
| Lab-D (40노드) | ✅ Config 생성 완료 (40/40 cfg) + 버그 수정 완료 | PNETLab 배포 → 데이터셋 생성 |
| `config_generator/` | ✅ 구현 완료 (generator.py + 4 templates + Remap 기능) | Lab-B/C/D 전부 생성/재매핑 가능 |
| IP 충돌 검증 | ✅ 완료 (2026-02-18) — Lab-B/C/D 전체 CLEAN | — |
| 배포 가이드 | ✅ 완료 (2026-02-18) — Lab-D, NSO/NetAlly, 배치 다이어그램 포함 | — |

### 0.1 제출용 Scope Freeze

1. 제출 본문: Lab-A + Lab-B 중심
2. Lab-C/Lab-D: preliminary 또는 future work
3. L6는 코드만 유지하고 이번 제출 실험/평가에서는 제외

---

## 1. 스케일러빌리티 실험 설계

### 1.1 실험 가설

> **H1**: "LLM의 네트워크 설정 해석 성능은 네트워크 규모에 반비례한다"  
> **H2**: "규모 증가에 따른 성능 하락 정도는 난이도 레벨에 따라 다르다 (L4/L5가 가장 급격)"  
> **H3**: "도메인(보안/DC/SP)에 따라 QA 분포와 LLM 성능 패턴이 달라진다"

### 1.2 실험 매트릭스

| 실험 | 노드 수 | 컨셉 | 핵심 프로토콜 | 활성 메트릭 | 예상 QA 수 |
|---|:---:|---|---|:---:|:---:|
| **Lab-A** | **10** | SP MPLS VPN (기존) | OSPF, BGP, LDP, VRF | 50 | 1,128 |
| **Lab-B** | **20** | NCN 기본 SP | + NTP, SNMP, AAA, Banner | **65** | ~1,500 |
| **Lab-C** | **30** | NCN + 보안/L2VPN | + L2VPN, ACL, eBGP, HSRP | **75** | ~2,500 |
| **Lab-D** | **40** | NCN 멀티 AS 복합 | + Multi-AS, Waypoint, QoS | **80+** | ~3,500 |

### 1.3 기대 결과 시각화

```
TA-Acc
1.0 ┤
    │  ★ L1
0.8 ┤  ·━━━━━━━━━━━━━━━━━━━·━━━━━━★
    │                                    (L1은 규모에 robust)
0.6 ┤  ★ L2-L3
    │    ·━━━━━━·━━━━━·
0.4 ┤              ·━━━·━━━●       (L2-L3 점진적 하락)
    │
0.2 ┤  ★ L4-L5
    │    ·━━·
0.1 ┤        ·━━●━━━━●               (L4-L5 급격 하락)
0.0 ┤──────────────────────────────
    10     20     30     40  노드 수
```

---

## 2. 실험실 확장 시나리오: "국가 통합 통신망 (National Converged Network)"
> **"국가 기관들을 연결하는 통합 통신 인프라를 운영하는 ISP"** — NetAlly(AI 운영자)가 네트워크 관제, 장애 진단, 보안 감사를 수행하는 시나리오.

`policies.json`의 메트릭이 **ISP/SP 운영 시나리오** 중심으로 설계되어 있으므로, 이에 최적화된 컨셉입니다.
단순한 노드 수 증가가 아니라, **서비스 복잡도(Service Complexity)**와 **메트릭 커버리지(Metric Coverage)**의 점진적 확장을 의미합니다.

### 🏛️ Lab-A: 단일 사이트 SP (Single-Site SP) — 10노드
> **"기존 데이터셋 (v2) — 기본 MPLS VPN"**

*   **컨셉**: 단일 ISP 사이트에서 기본 MPLS VPN 서비스를 제공하는 구조.
*   **구조**: 단일 리전, 단일 AS.
*   **VRF 설계**: 기존 VRF 구조 유지.
*   **활성 메트릭**: ~50개 (L1 기본 인벤토리 + L2 집계 + L3 일관성)
*   **LLM 챌린지**: "PE1의 VRF_GOV에 할당된 모든 인터페이스를 알려주세요."

### 🏗️ Lab-B: 기본 서비스 제공자 (Basic SP) — 20노드 ✅
> **"Multi-Region MPLS VPN + 관리 기능 강화"**

*   **컨셉**: 단일 ISP가 3개 고객(정부기관, 교육기관, 연구기관)에 MPLS VPN 서비스를 제공하며, 본사-지사 간 2개 리전으로 운영.
*   **구조**: **Multi-Region (2 Regions)**, 단일 AS (65000).
    *   **Region 1 (본사)**: P1~P4, PE1~PE2, Leaf1~Leaf4
    *   **Region 2 (지사)**: P5~P8, PE3~PE4, Leaf5~Leaf8
*   **VRF 설계**:
    *   `VRF_GOV` (RD 65000:100): 정부기관 네트워크 — Region 1 + 2 공유
    *   `VRF_EDU` (RD 65000:200): 교육기관 네트워크 — Region 1 + 2 공유
    *   `VRF_RND` (RD 65000:300): 연구기관 네트워크 — Region 1 + 2 공유
*   **기술적 차별점 (Lab-A 대비)**:
    *   **AAA**: PE에만 `aaa new-model` 활성화 (P/Leaf는 비활성 → 변별력)
    *   **SNMP**: PE는 RO+RW, P는 RO만, Leaf는 미설정 → 3단계 차이
    *   **NTP/Syslog/Timezone**: 전 장비 적용 (관리 기능 표준화)
    *   **Banner MOTD**: PE/P에만 설정, Leaf 미설정 → 보안 감사 변별력
    *   **Password Encryption**: PE/P만 `service password-encryption`
*   **활성 메트릭**: **~65개** (+15: NTP, SNMP, Syslog, AAA, Banner, Timezone, Password)
*   **LLM 챌린지**: "AAA가 활성화되지 않은 장비 목록을 알려주세요." → P 8대 + Leaf 8대 = 16대

### 🔒 Lab-C: 보안 강화 + L2VPN 서비스 (Enhanced Security) — 30노드 ✅
> **"Multi-AS + L2VPN 전용선 + 보안 정책"**

*   **컨셉**: Lab-B에 보안 관제 센터(Region 3)를 추가. L2VPN 전용선 서비스와 ACL 기반 접근 제어를 도입.
*   **구조**: Lab-B (20노드) + **Region 3 (10노드, AS 65001)**.
    *   **ASBR1, ASBR2**: Inter-AS eBGP 피어링 (asbr_router.j2 템플릿)
    *   **PE5, PE6**: `VRF_SEC` (보안관제), `VRF_MIL` (국방) 추가
    *   **P9, P10**: OSPF Area 1 (Area 0과 분리)
    *   **Leaf9~Leaf12**: ACL 적용 대상
*   **기술적 차별점 (Lab-B 대비)**:
    *   **L2VPN xconnect**: PE1↔PE3 PW 설정 (의도적 단방향 오류 포함)
    *   **eBGP Multi-AS**: AS 65000 ↔ AS 65001 분리
    *   **OSPF Multi-Area**: Area 0 (Region 1,2) + Area 1 (Region 3)
    *   **ACL / Prefix-List / Route-Map**: Leaf에 접근 제어 정책
    *   **HSRP**: PE5/PE6 게이트웨이 이중화
*   **활성 메트릭**: **~75개** (+10: L2VPN 5개, ACL, Prefix-List, Route-Map, HSRP, eBGP)
*   **LLM 챌린지**: "L2VPN Pseudowire가 단방향으로만 설정된 PE 쌍을 식별하세요."

### ⚔️ Lab-D: 멀티 AS + 복합 시나리오 (Multi-AS Complex) — 40노드 ✅
> **"의도적 오류 + 정책 복합 검증"**

*   **컨셉**: Lab-C에 외부 ISP Zone(AS 65002)를 추가. 의도적 설정 오류를 주입하여 LLM의 장애 탐지 능력을 평가.
*   **구조**: Lab-C (30노드) + **Region 4 (10노드, AS 65002, OSPF Area 2)**.
    *   **FW1, FW2**: Firewall Waypoint (ASBR↔FW eBGP, 모든 트래픽 경유 필수)
    *   **PE7, PE8**: `VRF_ISP`, `VRF_CDN` + QoS + NetFlow
    *   **P11, P12**: OSPF Area 2 코어
    *   **Leaf13~Leaf16**: DMZ 서버 영역
*   **기술적 차별점 (Lab-C 대비)**:
    *   **3-AS 구조**: AS 65000 / 65001 / 65002
    *   **Waypoint Traversal**: FW1/FW2를 반드시 경유해야 하는 경로 검증
    *   **QoS class-map/policy-map**: PE7/PE8에 CLASS_VOICE/VIDEO/DATA + POLICY_QOS_OUT
    *   **NetFlow**: PE7/PE8에 flow record/exporter/monitor + service-policy/flow-monitor
    *   **의도적 VRF RT 누락**: PE8 `VRF_ISP_BROKEN` — route-target 완전 누락 → `vrf_without_rt_pairs` 검증
    *   **의도적 iBGP 비대칭 누락**: PE7→PE8 iBGP 미설정 → `ibgp_missing_pairs` 검증
    *   **의도적 OSPF cost 비대칭**: FW1→PE7 cost=10, PE7→FW1 cost=20 → `asymmetric_path_comparison` 검증
*   **활성 메트릭**: **~80개+** (전체 커버리지 97%)
*   **LLM 챌린지**: "iBGP Full-Mesh가 깨진 PE 쌍과, VRF route-target이 누락된 장비를 모두 찾으세요."

### 📊 확장에 따른 metrics 커버리지 변화

```
활성 메트릭
  80+ ┤                              ★ Lab-D (97%)
      │                    ★ Lab-C (88%)
  65  ┤          ★ Lab-B (67%)
      │
  50  ┤ ★ Lab-A (50%)
      │
  0   ┤──────────────────────────────
      10     20     30     40  노드 수
```

---

## 3. Config Generator 설계

### 3.1 배포 방식 및 도구 선정 (NetAlly/NSO 필수 연동)

사용자가 **NetAlly와 NSO를 필수적으로 사용**한다고 명시했으므로, 모든 네트워크 장비는 NSO가 접근할 수 있는 **관리망(Management Network)**에 반드시 연결되어야 합니다.

#### 필수 요구사항: OOB (Out-Of-Band) Management
*   **구조**: 모든 라우터/스위치의 관리 인터페이스(`Gi0/7`, `management_intf_slot: 7`)를 **Cloud0 (Management Cloud)**에 연결.
*   **IP 주소**: `10.10.10.x/24` 대역 사용 (고정 IP 권장).
*   **프로토콜**: SSH + SNMP 활성화 필수.
*   **NSO 연동**: NSO가 이 관리 IP를 통해 장비를 Reachability 하고 설정을 읽어갈 수 있어야 함.

#### NetAlly 파이프라인
1.  **Generator**: `.cfg` 파일 생성 시 관리 인터페이스 설정 포함 (`ip route 0.0.0.0 0.0.0.0 10.10.10.1` 등 관리망 게이트웨이 포함).
2.  **PNETLab**: 노드 생성 후 `Cloud0`와 배선 연결.
3.  **Boot**: 장비 부팅 후 Generator가 만든 설정 적용.
4.  **NSO**: 장비 Discovery 및 Sync-from.
5.  **NetAlly**: NSO를 통해 토폴로지 시각화 및 Chat Ops 수행.

### 3.2 아키텍처

```
Make_Dataset/config_generator/
├── generator.py            # 메인 생성 엔진 (--topology | --remap --lab)
├── templates/              # Jinja2 config 템플릿
│   ├── pe_router.j2        # PE 라우터 (VRF, BGP, QoS, NetFlow, xconnect, HSRP)
│   ├── p_router.j2         # P 코어 라우터 (OSPF cost)
│   ├── asbr_router.j2      # ASBR 라우터 (eBGP, per-intf ospf_area)
│   └── leaf_switch.j2      # Leaf 스위치 (ACL, Prefix-list, Route-map)
├── topologies/             # 토폴로지 정의 (YAML)
│   ├── lab_b_20nodes.yaml  # 20노드 (2 Region, AS 65000)
│   ├── lab_c_30nodes.yaml  # 30노드 (3 Region, AS 65000+65001)
│   └── lab_d_40nodes.yaml  # 40노드 (4 Region, AS 65000+65001+65002) ← 버그수정: P11/P12 IP, ASBR OSPF area
├── remap_samples/          # PNETLab node_id 불일치 시 재매핑용 CSV
│   ├── lab_b_remap.csv     # 20 entries (pnetlab_node_id,hostname)
│   ├── lab_c_remap.csv     # 30 entries
│   └── lab_d_remap.csv     # 40 entries
├── docs/
│   └── deployment_guide.md # PNETLab 배포 가이드 (Lab-D, NSO/NetAlly, 시각 배치 다이어그램 포함)
└── output/                 # 생성된 config 파일
    ├── LabB_NCN_Basic_SP_20nodes/
    │   ├── configs/  (20 .cfg)
    │   └── txt/      (20 .txt + NODE_ID_MAP.md, PNETLab Import용)
    ├── LabC_NCN_Security_L2VPN_30nodes/
    │   ├── configs/  (30 .cfg)
    │   └── txt/      (30 .txt + NODE_ID_MAP.md)
    └── LabD_NCN_MultiAS_Complex_40nodes/
        ├── configs/  (40 .cfg)
        └── txt/      (40 .txt + NODE_ID_MAP.md)
```

### 3.3 토폴로지 정의 형식 (YAML)

```yaml
# lab_b_20nodes.yaml (NCN_Basic_SP)
name: "NCN_Basic_SP"
description: "National Converged Network (국가 통합 통신망) - 20 Nodes Basic Service Provider"
as_number: 65000
management_gateway: "10.10.10.1"

nodes:
  # --- Region 1 (본사 - 10노드) ---
  - name: PE1
    role: pe
    region: 1
    loopback: "10.255.0.11/32"
    management_ip: "10.10.10.21/24"
    vrfs: [VRF_GOV, VRF_EDU, VRF_RND]
    bgp_neighbors:
      - ip: "10.255.0.12"   # PE2
        as: 65000
      - ip: "10.255.0.21"   # PE3 (Region 2)
        as: 65000
    interfaces:
      - name: GigabitEthernet0/0
        peer: P1
        ip: "10.0.1.0/31"
        mpls: true
      - name: GigabitEthernet0/1
        vrf: VRF_GOV
        ip: "172.16.1.1/24"
        description: "Link to Leaf1 (정부기관)"
      - name: GigabitEthernet0/2
        vrf: VRF_EDU
        ip: "172.16.2.1/24"
        description: "Link to Leaf2 (교육기관)"

  - name: P1
    role: p
    region: 1
    loopback: "10.255.0.1/32"
    management_ip: "10.10.10.11/24"
    interfaces:
      - name: GigabitEthernet0/0
        peer: PE1
        ip: "10.0.1.1/31"
        mpls: true
      - name: GigabitEthernet0/1
        peer: P2
        ip: "10.0.2.0/31"
        mpls: true

  # ... (P2~P4, PE2, Leaf1~Leaf4)

  # --- Region 2 (지사 - 10노드) ---
  - name: PE3
    role: pe
    region: 2
    loopback: "10.255.0.21/32"
    management_ip: "10.10.10.23/24"
    vrfs: [VRF_GOV, VRF_EDU, VRF_RND]
    # ... (cross-region VRF 공유)

vrfs:
  VRF_GOV:
    rd: "65000:100"
    rt_import: ["65000:100"]
    rt_export: ["65000:100"]
  VRF_EDU:
    rd: "65000:200"
    rt_import: ["65000:200"]
    rt_export: ["65000:200"]
  VRF_RND:
    rd: "65000:300"
    rt_import: ["65000:300"]
    rt_export: ["65000:300"]

routing:
  ospf:
    process_id: 1
    area: 0
    networks: auto
  bgp:
    address_families: [vpnv4]
  mpls:
    protocol: ldp
```

### 3.4 Jinja2 템플릿 예시 (PE 라우터)

```jinja2
{# pe_router.j2 — NCN (National Converged Network) #}
!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption        {# ← 보안 감사 메트릭 활성화 #}
!
hostname {{ node.name }}
!
{% for vrf_name in node.vrfs %}
{% set vrf = topology.vrfs[vrf_name] %}
vrf definition {{ vrf_name }}
 rd {{ vrf.rd }}
 route-target export {{ rt }}  {# loop 생략 #}
 route-target import {{ rt }}
 address-family ipv4
 exit-address-family
{% endfor %}
!
aaa new-model                      {# ← PE만 활성화 (P/Leaf은 비활성) #}
aaa authentication login default local
!
no ip domain lookup
ip domain name ncn.go.kr
ip cef
mpls label protocol ldp
!
username admin privilege 15 secret 5 $1$...
!
interface Loopback0
 ip address {{ node.loopback | ip_address }} 255.255.255.255
!
{% for intf in node.interfaces %}
interface {{ intf.name }}
{% if intf.vrf is defined %}
 vrf forwarding {{ intf.vrf }}
{% endif %}
 ip address {{ intf.ip | ip_address }} {{ intf.ip | netmask }}
 {# ... duplex, speed, mpls ip 등 #}
{% endfor %}
!
! Management Interface (OOB)
interface GigabitEthernet0/{{ topology.management_intf_slot | default(7) }}
 ip address {{ node.management_ip | ip_address }} {{ node.management_ip | netmask }}
!
router ospf 1 / router bgp 65000  {# 자동 생성 — 상세 생략 #}
!
! ──── 새로 추가된 관리 기능 블록 ────
ntp server {{ topology.management_gateway }}
logging host {{ topology.management_gateway }}
logging buffered 51200 warnings
snmp-server community NCN-RO RO
snmp-server community NCN-RW RW
clock timezone KST 9 0
banner motd ^
*** National Converged Network - PE Router {{ node.name }} ***
*** Authorized Access Only - All activities are monitored ***
^
!
ip ssh version 2
ip route 0.0.0.0 0.0.0.0 {{ topology.management_gateway }}
!
line con 0
line vty 0 4
 login local
 transport input ssh
!
end
```

### 3.5 PNETLab 배포 워크플로우

> 상세 배포 가이드: [Make_Dataset/config_generator/docs/deployment_guide.md](../../../Make_Dataset/config_generator/docs/deployment_guide.md)

```
Step 1: Config Generator로 Lab-B/C/D 설정 파일 생성
    $ python Make_Dataset/config_generator/generator.py \
        --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml
    → output/LabB_NCN_Basic_SP_20nodes/configs/ (20 .cfg)
    → output/LabB_NCN_Basic_SP_20nodes/txt/ (20 .txt, 순서 기반 node_id)

Step 2: PNETLab에서 노드 생성 (IOSv, Ethernet 어댑터 8개) + 배선 (배선 테이블 참조)
    - ASCII 배치 다이어그램: deployment_guide.md Section 2.3 참조

Step 2.5 (선택): node_id 불일치 시 Remap
    - PNETLab System Status에서 실제 node_id 확인
    - remap_samples/lab_b_remap.csv 수정 후:
    $ python Make_Dataset/config_generator/generator.py \
        --remap Make_Dataset/config_generator/remap_samples/lab_b_remap.csv \
        --lab LabB_NCN_Basic_SP_20nodes
    → txt/ 파일이 실제 PNETLab node_id 기준으로 재생성됨

Step 3: PNETLab Import Startup Configuration (txt/ 파일 사용) 또는 Startup Config 에디터
    - 상세 절차: deployment_guide.md Section 3 참조

Step 4: 배포 검증 (OSPF/BGP/MPLS neighbor 확인)
    - 검증 체크리스트: deployment_guide.md Section 5 참조

Step 5: Batfish에 snapshot 로드 + QA 생성
    $ python Make_Dataset/src/main_batfish.py \
        --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes

Step 6: Ground Truth 검증
    $ python Make_Dataset/src/verification/run_verification_pipeline.py \
        --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/

Step 7: 생성된 데이터셋으로 LLM 평가
```

---

## 4. 메트릭 커버리지 기반 QA 분포 분석

### 4.1 Lab별 활성 메트릭 비교

| 카테고리 | 총 메트릭 | Lab-A | Lab-B | Lab-C | Lab-D |
|---|:---:|:---:|:---:|:---:|:---:|
| System_Inventory | 13 | 8 | 11 | 12 | 13 |
| Security_Inventory | 4 | 2 | 3 | 4 | 4 |
| Interface_Inventory | 5 | 5 | 5 | 5 | 5 |
| Routing_Inventory | 9 | 9 | 9 | 9 | 9 |
| Services_Inventory | 10 | 6 | 8 | 10 | 10 |
| Configuration_Check | 21 | 5 | 10 | 15 | 19 |
| Security_Policy (L2) | 7 | 3 | 5 | 7 | 7 |
| L2VPN_Consistency (L3) | 5 | 0 | 0 | **5** | 5 |
| BGP_Consistency (L3) | 5 | 3 | 3 | 4 | **5** |
| VRF_Consistency (L3) | 4 | 3 | 3 | 4 | **4** |
| Reachability (L4) | 10 | 7 | 7 | 9 | **10** |
| What-If (L5) | 12 | 4 | 8 | 10 | **12** |
| **합계** | **~105+** | **~55** | **~72** | **~94** | **~103** |
| **커버율** | — | **52%** | **67%** | **88%** | **97%** |

### 4.2 논문에서의 활용

> "동일 파이프라인(`policies.json`)으로 토폴로지만 교체하면 메트릭 커버리지가 자동으로 확장된다"  
> → 파이프라인의 **범용성(Generalizability)** 입증

```
┌─────────────────────────────────────────────────────────┐
│  동일 파이프라인 + policies.json                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │ Lab-A   │  │ Lab-B   │  │ Lab-C   │  │ Lab-D   │   │
│  │ 10노드  │  │ 20노드  │  │ 30노드  │  │ 40노드  │   │
│  │ 52%     │  │ 67%     │  │ 88%     │  │ 97%     │   │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘   │
│       ↓            ↓            ↓            ↓         │
│  1,128 QA     ~1,500 QA    ~2,500 QA    ~3,500 QA     │
│                                                         │
│  → "설정 파일만 넣으면 자동 생성, 규모에 비례하여 확장" │
└─────────────────────────────────────────────────────────┘
```

---

## 5. NetAlly + 데이터셋 통합 평가 실험

### 5.1 컨셉

> "NetAlly에 NetConfigQA2.0 질문을 직접 투입하여, Multi-Agent 시스템의 실제 성능을 측정한다"

### 5.2 실험 설계

```
┌─────────────────────────────────────────────────────┐
│  NetConfigQA2.0 Dataset (1,128 QA)                  │
│  ├── L1-L3 질문 → NetAlly Orchestrator              │
│  │   └── Executor: Batfish Query 또는 Config Parse   │
│  ├── L4 질문 → NetAlly Orchestrator                  │
│  │   └── Executor: Batfish Traceroute/Reachability   │
│  ├── L5 질문 → NetAlly Orchestrator                  │
│  │   └── Executor: Batfish What-If Simulation        │
│  └── L6 질문은 이번 제출 범위에서 제외               │
│      └── (코드만 유지, 평가/표/성능 비교 미포함)     │
└──────────────────────┬──────────────────────────────┘
                       ↓
              TA-Acc per Level 계산
                       ↓
        ┌──────────────────────────────┐
        │  비교 테이블                  │
        │  Single LLM vs NetAlly       │
        │  Level별 성능 차이 = Δ       │
        └──────────────────────────────┘
```

### 5.3 기대 결과

| Level | Single LLM (GPT-OSS-20B) | NetAlly | Δ (향상) |
|:---:|:---:|:---:|:---:|
| L1 | 0.873 | **0.95+** | +0.08 |
| L2 | 0.873 | **0.95+** | +0.08 |
| L3 | 0.605 | **0.85+** | +0.25 |
| L4 | 0.266 | **0.75+** ⭐ | **+0.48** |
| L5 | 0.134 | **0.60+** ⭐ | **+0.47** |

> L6 진단 레벨은 이번 TNMS 제출에서 제외한다.  
> 제외 이유: fault별 snapshot/context 패키징 부담, single-LLM baseline과의 공정 비교 어려움, 일정 내 재현 검증 리스크.

> 🔑 **핵심 메시지**: "L4/L5에서 Single LLM은 0.3 이하이지만, NetAlly(도구 활용형 Multi-Agent)는 0.6+ 달성 → **도구 활용이 핵심**"

### 5.4 실험 파이프라인

```python
"""netally_evaluation.py — NetAlly에 데이터셋 질문을 자동 투입"""

class NetAllyEvaluator:
    def __init__(self, netally_api_url, dataset_path):
        self.api = netally_api_url  # NetAlly FastAPI 서버
        self.dataset = load_dataset(dataset_path)
    
    def evaluate_all(self):
        results = []
        for qa in self.dataset:
            # NetAlly에 질문 전송
            response = requests.post(f"{self.api}/chat", json={
                "message": qa["question"],
                "context": {"topology": "Research_Institute_Internal_DC"}
            })
            
            # TA-Acc 계산
            netally_answer = response.json()["answer"]
            score = ta_acc(netally_answer, qa["answer"], qa["answer_type"])
            
            results.append({
                "id": qa["id"],
                "level": qa["level"],
                "score": score,
                "netally_answer": netally_answer,
                "ground_truth": qa["answer"]
            })
        
        return self._generate_report(results)
```

---

## 6. 구현 일정

| 단계 | 작업 | 상태 | 완료 기준 |
|---|---|:---:|---|
| Phase 1 | Lab-B Config Generator 구현 + 20개 cfg 생성 | ✅ 완료 | NCN_Basic_SP 20/20 cfg |
| Phase 2 | Lab-C 토폴로지 + Config 생성 (ASBR, L2VPN, ACL, HSRP) | ✅ 완료 | 30/30 cfg + asbr_router.j2 |
| Phase 3 | Lab-D 토폴로지 + Config 생성 (FW, QoS, NetFlow, 오류 3종) | ✅ 완료 | 40/40 cfg + 의도적 오류 검증 |
| Deploy | Lab-B/C/D PNETLab 배포 + 데이터셋 생성 | 🔜 | OSPF/BGP/LDP 정상 + QA 생성 |
| Final | NetAlly 평가 (Lab-A → Lab-B → Lab-C → Lab-D) | 🔜 | Level별 TA-Acc 비교표 |

### 현실적 우선순위

| 우선순위 | 작업 | 이유 |
|:---:|---|---|
| 🔴 P0 | Lab-A (기존) 검증 + 재실험 | 논문의 최소 요구사항 |
| 🔴 P1 | Lab-B (20노드) PNETLab 배포 + 실험 | 스케일러빌리티의 최소 증거 |
| 🟡 P2 | Lab-C/D PNETLab 배포 + 실험 | 메트릭 커버리지 88%→97% |
| 🔴 P1 | NetAlly 데이터셋 평가 | 논문 핵심 실험 |
