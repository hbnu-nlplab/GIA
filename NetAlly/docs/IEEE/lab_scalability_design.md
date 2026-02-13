# 실험실 확장 & Config Generator 설계서

> **목적**: 네트워크 규모(10→20→30→50 노드)와 도메인 다양성에 따른 LLM 성능 변화를 분석하기 위한 실험 환경 설계  
> **핵심 원칙**: 설정 파일만 생성하면 QA 파이프라인이 자동으로 데이터셋 생성 → PNETLab에 복붙하면 바로 적용

---

## 0. 구현 상태 리베이스 (2026-02-13)

| 항목 | 현재 상태 | 조치 |
|---|---|---|
| Lab-A (10노드) | 완료 (v2 1,128 QA) | 검증 보강 후 재실험 |
| Lab-B/C/D 토폴로지 | 설계 문서만 존재 | **Lab-B부터 구현 시작** |
| `config_generator/` | 미구현 | **이번 주 구현 착수** |
| Lab 확장 데이터셋 | 미생성 | Lab-B 우선 생성 |

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

| 실험 | 노드 수 | 도메인 | 핵심 프로토콜 | 예상 QA 수 |
|---|:---:|---|---|:---:|
| **Lab-A** | **10** | SP MPLS VPN | OSPF, BGP, LDP, VRF | 1,128 (기존) |
| **Lab-B** | **20** | SP MPLS VPN 확장 | + L2VPN, iBGP RR | ~2,200 |
| **Lab-C** | **30** | 보안 중심 SP | + ACL, Zone FW, NAT | ~3,500 |
| **Lab-D** | **50** | 멀티도메인 대규모 | Multi-AS, RSVP-TE, SR | ~5,000+ |

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
    10     20     30     50  노드 수
```

---

## 2. 실험실별 상세 설계

### 2.1 Lab-A: SP MPLS VPN (10노드) — 기존 ✅

```
현재 구조: Research_Institute_Internal_DC
  Leaf1─┐         ┌─Leaf3
  Leaf2─┤─PE1──P1─P2─P3─P4─PE2─┤─Leaf4
        │    └────────────────┘  │
        VRF: AI, BIO, HPC       VRF: AI, BIO, HPC
장비: 4 Leaf + 2 PE + 4 P = 10
```

**사용 목적**: Baseline 데이터. 이미 1,128 QA 확보.

---

### 2.2 Lab-B: SP MPLS VPN 확장 (20노드) — 신규

#### 설계 컨셉: "리전(Region) 추가"

기존 10노드를 하나의 Region으로 보고, 유사한 구조의 Region 2를 추가합니다.

```
┌──── Region 1 (기존) ────┐   ┌──── Region 2 (신규) ────┐
│ Leaf1-4  PE1  P1-P4 PE2 │───│ PE3  P5-P8  PE4  Leaf5-8│
│ VRF: AI, BIO, HPC      │   │ VRF: AI, DEV, SEC       │
│ AS 65000                │   │ AS 65000 (iBGP)         │
└─────────────────────────┘   └─────────────────────────┘
```

#### 장비 구성 (20개)

| 역할 | 기존 (유지) | 신규 | 수량 |
|---|---|---|:---:|
| Leaf (CE) | Leaf1-4 | Leaf5-8 | 8 |
| PE | PE1, PE2 | PE3, PE4 | 4 |
| P (Core) | P1-P4 | P5-P8 | 8 |

#### 프로토콜 스택

| 프로토콜 | 설정 내용 |
|---|---|
| OSPF Area 0 | P/PE 전체 (기존과 동일) |
| iBGP VPNv4 | PE1-PE2 기존 + PE3-PE4 신규 + PE1↔PE3 Inter-Region |
| LDP | P/PE 코어 전체 |
| VRF | Region1: AI/BIO/HPC, Region2: AI/DEV/SEC |

#### 이 실험으로 검증하려는 것

- **L2 증가**: 전체 장비 통계 쿼리 범위가 10→20으로 확대
- **L3 증가**: Inter-Region VRF 정합성 검증 (RT import/export 교차)
- **L4 증가**: Region 간 traceroute 경로 길어짐 (hop 수 증가)
- **L5 증가**: Region 간 링크 장애 시 우회 경로 복잡도 증가

#### IP 체계

```
Loopback:   10.255.0.{id}/32  (기존 유지, 신규 21-28)
P2P Links:  10.0.{link_id}.{0|1}/31
VRF Subnets:
  Region1: 172.16.{1-6}.0/24
  Region2: 172.17.{1-6}.0/24
Management: 10.10.10.{id}/24
```

---

### 2.3 Lab-C: 보안 중심 SP (30노드) — 신규

#### 설계 컨셉: "보안 계층 추가"

Lab-B의 20노드 구조 위에 보안 장비(방화벽, DMZ)를 추가하여 ACL/Security 관련 QA를 대폭 증가시킵니다.

```
┌─── External Zone ───┐
│  FW1  FW2  (방화벽)  │
│  DMZ1 DMZ2 (DMZ서버) │
└───────┬──────────────┘
        │ ACL/NAT
┌───────┴──── Core (20노드) ────────────┐
│  Region 1 (10)  ←─→  Region 2 (10)   │
└───────────────────────────────────────┘
        │
┌───────┴──── Management ───────┐
│  MGMT-SW1  MGMT-SW2          │
│  Syslog-SRV  NTP-SRV         │
│  RADIUS-SRV  TACACS-SRV      │
└───────────────────────────────┘
```

#### 추가 장비 (10개)

| 역할 | 장비명 | 수량 |
|---|---|:---:|
| 방화벽 | FW1, FW2 | 2 |
| DMZ 서버 | DMZ1, DMZ2 | 2 |
| 관리 스위치 | MGMT-SW1, MGMT-SW2 | 2 |
| 관리 서버 | Syslog-SRV, NTP-SRV, RADIUS-SRV, TACACS-SRV | 4 |

#### 보안 설정 요소

| 설정 항목 | 효과 |
|---|---|
| Extended ACL (inbound/outbound) | L1(ACL 조회) + L4(차단 여부) QA 증가 |
| Zone-based Firewall Policy | L3(정합성) + L4(도달성) QA 증가 |
| NAT (Static/Dynamic) | L1(NAT 룰 조회) + L4(변환 후 경로) |
| RADIUS/TACACS+ 인증 | L1(인증 서버 조회) + L2(인증 적용 현황) |
| SSH/VTY 접근 제어 | L1(설정 조회) + L2(보안 적용률) |

#### 이 실험으로 검증하려는 것

- **Security 카테고리 QA 폭증**: 기존 40→200+ 예상
- **L4에서 ACL 차단 경로 분석**: "패킷이 ACL에 의해 차단되는가?"
- **도메인 특화 분석**: "보안 중심 실험실에서 LLM이 특히 약한 영역은?"

---

### 2.4 Lab-D: 멀티도메인 대규모 (50노드) — 도전적

#### 설계 컨셉: "실제 소규모 ISP 수준"

```
┌─── AS 65001 ───┐  eBGP  ┌─── AS 65002 ───┐
│ Region 1 (15)  │────────│ Region 3 (15)  │
│ Region 2 (15)  │        │ Region 4 (5)   │
└────────────────┘        └────────────────┘
```

#### 구조

| 영역 | 노드 수 | 특화 |
|---|:---:|---|
| AS 65001 - Region 1 | 15 | 기존 확장 MPLS VPN |
| AS 65001 - Region 2 | 15 | 보안 Zone |
| AS 65002 - Region 3 | 15 | 다른 벤더/구조 시뮬레이션 |
| AS 65002 - Region 4 | 5 | eBGP Peering + Route Filter |

#### 추가 프로토콜

- **eBGP**: AS 간 Peering (route-map, prefix-list 활용)
- **Route Reflector**: 대규모 iBGP를 위한 RR 구조
- **RSVP-TE 또는 Segment Routing**: 고급 경로 제어 (가능하면)
- **Multi-VRF Inter-AS**: Option A/B/C 중 택1

#### 이 실험으로 검증하려는 것

- **50노드에서의 L4/L5 성능**: 경로 길이 및 복잡도 극대화
- **Multi-AS 추론**: LLM이 AS 경계를 넘는 라우팅을 이해하는가?
- **대규모 설정에서의 Context Length 영향**: 50개 설정 파일 → 프롬프트 폭발

---

## 3. Config Generator 설계

### 3.1 아키텍처

```
Make_Dataset/config_generator/
├── generator.py           # 메인 생성 엔진
├── templates/             # Jinja2 config 템플릿
│   ├── pe_router.j2       # PE 라우터 템플릿
│   ├── p_router.j2        # P 코어 라우터 템플릿
│   ├── leaf_switch.j2     # Leaf 스위치 템플릿
│   ├── firewall.j2        # 방화벽 템플릿
│   └── server.j2          # 관리 서버 템플릿
├── topologies/            # 토폴로지 정의 (YAML)
│   ├── lab_b_20nodes.yaml
│   ├── lab_c_30nodes.yaml
│   └── lab_d_50nodes.yaml
└── output/                # 생성된 config 파일
    ├── Lab-B/configs/
    ├── Lab-C/configs/
    └── Lab-D/configs/
```

### 3.2 토폴로지 정의 형식 (YAML)

```yaml
# lab_b_20nodes.yaml
name: "Lab-B_MPLS_VPN_Extended"
description: "Region 확장 MPLS VPN 실험실 (20노드)"
as_number: 65000

nodes:
  # --- Region 1 (기존 구조 재현) ---
  - name: PE1
    role: pe
    region: 1
    loopback: "10.255.0.11/32"
    vrfs: [VRF_AI, VRF_BIO, VRF_HPC]
    interfaces:
      - name: GigabitEthernet0/0
        peer: P1
        ip: "10.0.1.0/31"
        mpls: true
      - name: GigabitEthernet0/1
        vrf: VRF_AI
        ip: "172.16.1.1/24"
      - name: GigabitEthernet0/2
        vrf: VRF_BIO
        ip: "172.16.2.1/24"
    
  - name: P1
    role: p
    region: 1
    loopback: "10.255.0.1/32"
    interfaces:
      - name: GigabitEthernet0/0
        peer: PE1
        ip: "10.0.1.1/31"
        mpls: true
      - name: GigabitEthernet0/1
        peer: P2
        ip: "10.0.2.0/31"
        mpls: true
  
  # ... (추가 노드 정의)

  # --- Region 2 (신규) ---
  - name: PE3
    role: pe
    region: 2
    loopback: "10.255.0.21/32"
    vrfs: [VRF_AI, VRF_DEV, VRF_SEC]
    interfaces:
      - name: GigabitEthernet0/0
        peer: P5
        ip: "10.0.11.0/31"
        mpls: true

vrfs:
  VRF_AI:
    rd: "65000:1"
    rt_import: ["65000:1"]
    rt_export: ["65000:1"]
  VRF_BIO:
    rd: "65000:2"
    rt_import: ["65000:2"]
    rt_export: ["65000:2"]
  VRF_DEV:
    rd: "65000:4"
    rt_import: ["65000:4"]
    rt_export: ["65000:4"]
  VRF_SEC:
    rd: "65000:5"
    rt_import: ["65000:5"]
    rt_export: ["65000:5"]

routing:
  ospf:
    process_id: 1
    area: 0
    networks: auto  # 모든 P2P 링크 자동 포함
  bgp:
    neighbors: auto  # PE 간 iBGP Full-Mesh 또는 RR
    address_families: [vpnv4]
  mpls:
    protocol: ldp
```

### 3.3 Jinja2 템플릿 예시 (PE 라우터)

```jinja2
{# pe_router.j2 #}
!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname {{ node.name }}
!
{% for vrf in node.vrfs %}
vrf definition {{ vrf.name }}
 rd {{ vrf.rd }}
{% for rt in vrf.rt_export %}
 route-target export {{ rt }}
{% endfor %}
{% for rt in vrf.rt_import %}
 route-target import {{ rt }}
{% endfor %}
 !
 address-family ipv4
 exit-address-family
!
{% endfor %}
no aaa new-model
!
no ip domain lookup
ip domain name mylab.local
ip cef
no ipv6 cef
mpls label protocol ldp
!
username admin privilege 15 secret 5 $1$xxxx$xxxxxxxxxxxxxx
!
interface Loopback0
 ip address {{ node.loopback | ip_address }} {{ node.loopback | netmask }}
!
{% for intf in node.interfaces %}
interface {{ intf.name }}
{% if intf.vrf is defined %}
 vrf forwarding {{ intf.vrf }}
{% endif %}
 ip address {{ intf.ip | ip_address }} {{ intf.ip | netmask }}
 duplex auto
 speed auto
 media-type rj45
{% if intf.mpls %}
 mpls ip
{% endif %}
!
{% endfor %}
router ospf {{ routing.ospf.process_id }}
 router-id {{ node.loopback | ip_address }}
{% for network in node.ospf_networks %}
 network {{ network.net }} {{ network.wildcard }} area {{ network.area }}
{% endfor %}
!
router bgp {{ topology.as_number }}
 bgp log-neighbor-changes
{% for neighbor in node.bgp_neighbors %}
 neighbor {{ neighbor.ip }} remote-as {{ neighbor.as }}
 neighbor {{ neighbor.ip }} update-source Loopback0
{% endfor %}
 !
 address-family vpnv4
{% for neighbor in node.bgp_neighbors %}
  neighbor {{ neighbor.ip }} activate
  neighbor {{ neighbor.ip }} send-community both
{% endfor %}
 exit-address-family
{% for vrf in node.vrfs %}
 !
 address-family ipv4 vrf {{ vrf.name }}
  redistribute connected
  redistribute static
 exit-address-family
{% endfor %}
!
ip forward-protocol nd
no ip http server
no ip http secure-server
ip ssh version 2
!
line con 0
line aux 0
line vty 0 4
 login local
 transport input ssh
!
end
```

### 3.4 PNETLab 배포 워크플로우

```
Step 1: Config Generator로 Lab-B/C/D 설정 파일 생성
    $ python Make_Dataset/config_generator/generator.py --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml
    → output/Lab-B/configs/ 에 20개 .cfg 파일 생성

Step 2: PNETLab에서 노드 생성 + eth 연결
    (수동: 유진님이 PNETLab UI에서 노드 배치 + 케이블 연결)

Step 3: 각 노드 콘솔에서 config 복붙
    (수동: 생성된 .cfg 내용을 각 장비 콘솔에 붙여넣기)

Step 4: 연결 확인
    $ python Make_Dataset/src/3-Check_Connectivity.py

Step 5: Batfish에 snapshot 로드 + QA 생성
    $ python Make_Dataset/src/main_batfish.py --lab-path Data/Pnetlab/Lab-B

Step 6: 생성된 데이터셋으로 LLM 평가
```

---

## 4. 도메인별 실험실 특성 분석

### 4.1 예상 QA 분포 차이

| 카테고리 | Lab-A (SP) | Lab-C (보안) | Lab-D (대규모) |
|---|:---:|:---:|:---:|
| System_Inventory | 110 | 300 | 500 |
| Interface_Inventory | 40 | 120 | 200 |
| Security_Inventory | 40 | **200** ⬆️ | 150 |
| Security_Policy | 14 | **100** ⬆️ | 80 |
| Routing_Inventory | 70 | 70 | **200** ⬆️ |
| Reachability_Analysis | 127 | **300** ⬆️ | **500** ⬆️ |
| What_If_Analysis | 187 | 250 | **400** ⬆️ |

### 4.2 논문에서의 활용

> "실험실 도메인에 따라 데이터셋 난이도 분포가 자동으로 달라진다"  
> → 파이프라인의 **범용성(Generalizability)** 입증

```
┌─────────────────────────────────────────────────┐
│  동일 파이프라인 + policies.json               │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │ Lab-A   │  │ Lab-C   │  │ Lab-D   │        │
│  │SP 10노드│  │보안30노드│  │대규모50 │        │
│  └────┬────┘  └────┬────┘  └────┬────┘        │
│       ↓            ↓            ↓              │
│ 1,128 QA      3,500 QA     5,000+ QA          │
│ L4/L5 30%     Security 30%  Multi-AS 40%       │
│                                                 │
│  → "어떤 실험실이든 설정 파일만 넣으면 자동"    │
└─────────────────────────────────────────────────┘
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

| 단계 | 작업 | 소요 | 완료 기준 |
|---|---|:---:|---|
| Phase A | `config_generator` 뼈대 구현 (YAML 로드, 템플릿 렌더, 출력) | 1~1.5일 | Lab-B용 20개 cfg 자동 생성 |
| Phase A | Lab-B 토폴로지 YAML + 기본 템플릿 완성 | 1일 | 수동 수정 없이 부팅 가능한 config |
| Phase B | Lab-B PNETLab 배포 + 라우팅 수렴 확인 | 1~2일 | OSPF/BGP/LDP 정상 |
| Phase B | Lab-B 데이터셋 생성 + 통계 확인 | 0.5일 | CSV/JSON/통계 산출 |
| Phase C | NetAlly 평가 (Lab-A, Lab-B) | 1~2일 | Level별 TA-Acc 비교표 작성 |
| Phase D (옵션) | Lab-C/Lab-D 확장 | 2~4일 | preliminary 결과 확보 |
| **합계** | **MVP 4.5~7일 (Lab-B 기준)** |  |  |

### 현실적 우선순위 (2/28 기준)

| 우선순위 | 작업 | 이유 |
|:---:|---|---|
| 🔴 P0 | Lab-A (기존) 검증 + 재실험 | 논문의 최소 요구사항 |
| 🔴 P1 | Lab-B (20노드) 생성 + 실험 | 스케일러빌리티의 최소 증거 |
| 🟡 P2 | Lab-C (30노드) | 여유 시 preliminary |
| 🟢 P3 | Lab-D (50노드) | Future Work 권장 |
| 🔴 P1 | NetAlly 데이터셋 평가 | 논문 핵심 실험 |
