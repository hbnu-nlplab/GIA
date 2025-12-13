# Phase 1: 5대 네트워크 도메인 데이터셋 구축 전략

> **연구 범위**: LLM의 네트워크 설정 이해력 평가 (Information Retrieval & Understanding)  
> **평가 대상**: Golden Config (정상 상태) 기반 L1-L5 계층별 질의응답 능력

---

## 📋 목차

1. [연구 배경 및 목표](#1-연구-배경-및-목표)
2. [5대 네트워크 도메인 정의](#2-5대-네트워크-도메인-정의)
3. [데이터셋 구축 전략](#3-데이터셋-구축-전략)
4. [평가 메트릭 체계 (L1-L5)](#4-평가-메트릭-체계)
5. [실행 계획](#5-실행-계획)

---

## 1. 연구 배경 및 목표

### 1.1 문제 인식

**현재 상황**:

- 단일 실험실 (L2VPN) 기반 데이터셋 구축
- 주로 정적 연결성 검증 (Ping, OSPF Neighbor) 중심

**문제점**:

1. **다양성 부족**: 단일 네트워크 도메인만으로는 LLM 일반화 능력 검증 불가
2. **현실성 부족**: 실제 서비스가 동작하는 복잡한 네트워크 환경 부재

### 1.2 연구 목표

> **"LLM이 다양한 네트워크 도메인의 설정을 얼마나 정확하게 이해하고 분석할 수 있는가?"**

**평가 범위**:

- L1 (값 추출): "이 장비의 BGP AS는?"
- L2 (집계): "SSH 없는 장비 목록은?"
- L3 (검증): "iBGP 풀메시가 완성되었는가?"
- L4 (도달성): "A에서 B로 도달 가능한가?" (Batfish)
- L5 (What-If): "이 링크 장애 시 영향은?" (Batfish)

---

## 2. 5대 네트워크 도메인 정의

각 도메인은 현업의 특정 네트워크 아키텍처를 대표합니다.

| 도메인            | 실험실명       | 주요 프로토콜         | 검증 대상                 | 상태         |
| ----------------- | -------------- | --------------------- | ------------------------- | ------------ |
| **백본망**        | IGP_Backbone   | OSPF, IS-IS, FRR      | 고속 경로 계산, 빠른 복구 | 🔨 구축 필요 |
| **메트로망**      | L2VPN_Metro    | VPWS, VPLS, QinQ      | 기업 전용선, VLAN 태깅    | ✅ 보유 중   |
| **클라우드 백본** | MPLS_L3VPN     | MP-BGP, VRF, RT       | Multi-Tenant 격리         | 🔨 구축 필요 |
| **인터넷 Edge**   | BGP_Edge       | eBGP, AS-Path, Policy | ISP 멀티호밍, 경로 선택   | 🔨 구축 필요 |
| **차세대 망**     | IPTV_Multicast | PIM-SM, Anycast RP    | IPTV 스트리밍, 멀티캐스트 | 🔨 구축 필요 |

**프로토콜 커버리지 (총 15+)**:

- L2: STP, LACP, QinQ, VPLS
- L3 IGP: OSPF, IS-IS
- L3 EGP: BGP (iBGP, eBGP, MP-BGP)
- Overlay: MPLS, LDP, VRF
- Multicast: PIM-SM, IGMP
- QoS: DSCP, Rate Limiting

---

## 3. 데이터셋 구축 전략

### 3.1 데이터 소스: Golden Config (정상 상태)

```
Data/
├── Golden/              # 5개 도메인의 정상 상태 설정
│   ├── Backbone/       # 12-15대 장비 (P, PE, CE)
│   ├── L2VPN/          # 8대 (기존 보유)
│   ├── L3VPN/          # 10-12대 (P, PE, CE, RR)
│   ├── BGP/            # 6-8대 (Edge Router, ISP)
│   └── Multicast/      # 8-10대 (FHR, LHR, RP, STB)
└── dataset.csv         # 통합 QA 데이터셋
```

**장점**:

- 스냅샷 폭발 문제 없음 (각 도메인당 1세트)
- 관리 용이
- 파이프라인 수정 최소화

### 3.2 데이터 확보 방법

**옵션 1: PNETLab/EVE-NG 포럼 검색**

| 도메인    | 검색 키워드                         | 기대 파일            |
| --------- | ----------------------------------- | -------------------- |
| Backbone  | `MPLS Core`, `SP Backbone OSPF`     | `MPLS_Core.unl`      |
| L3VPN     | `MPLS L3VPN MP-BGP`, `Multi-Tenant` | `L3VPN_Lab.unl`      |
| BGP       | `BGP Multihoming`, `Dual ISP`       | `BGP_Edge.unl`       |
| Multicast | `PIM-SM`, `IPTV Streaming`          | `Multicast_Demo.unl` |

**옵션 2: 직접 구축 (NSO 기반)**

NSO Service Package로 자동 구성 → Config Export

---

## 4. 평가 메트릭 체계

현재 `policies.json`과 `Metrics.md`에 정의된 L1-L5 계층 유지.

### 4.1 메트릭 카테고리 (11개)

1. **System_Inventory** (L1)

   - `system_hostname_text`, `system_version_text`, ...

2. **Security_Inventory** (L1)

   - `ssh_present_bool`, `aaa_present_bool`, ...

3. **Interface_Inventory** (L1)

   - `interface_count`, `interface_ip_map`, ...

4. **Routing_Inventory** (L1)

   - `bgp_local_as_numeric`, `ospf_area_set`, ...

5. **Services_Inventory** (L1)

   - `vrf_names_set`, `mpls_ldp_present_bool`, ...

6. **Security_Policy** (L2)

   - `ssh_missing_devices`, `aaa_enabled_devices`, ...

7. **OSPF_Consistency** (L2)

   - `ospf_area_membership`, ...

8. **BGP_Consistency** (L3)

   - `ibgp_fullmesh_ok`, `ibgp_missing_pairs`, ...

9. **VRF_Consistency** (L3)

   - `vrf_without_rt_pairs`, `vrf_rd_format_invalid_set`, ...

10. **L2VPN_Consistency** (L3)

    - `l2vpn_pwid_mismatch_pairs`, `l2vpn_unidir_count`, ...

11. **Comparison_Analysis** (L3)
    - `compare_bgp_neighbor_count`, `max_interface_device`, ...

### 4.2 Batfish 계층 (L4-L5)

**L4: Reachability Analysis**

- `traceroute_path`: 경로 추적
- `reachability_status`: A→B 도달 가능 여부
- `loop_detection`: 포워딩 루프 탐지
- `blackhole_detection`: 블랙홀 탐지

**L5: What-If Analysis**

- `link_failure_impact`: 링크 장애 영향 분석
- `k_failure_tolerance`: k개 장애 내성 검증
- `config_change_impact`: 설정 변경 전후 비교

---

## 5. 실행 계획

### Phase 1-A: 실험실 확보 (1-2주)

**Week 1-2: 데이터 수집**

- [ ] PNETLab 포럼 검색 (Backbone, L3VPN, BGP, Multicast)
- [ ] 후보 랩 파일 3-5개 선정
- [ ] Import 테스트 및 NSO 연결 확인

### Phase 1-B: 데이터셋 생성 (2-3주)

**Week 3-4: Golden Config Export**

- [ ] 각 도메인별 NSO 동기화
- [ ] Config Export → `Data/Golden/{domain}/`
- [ ] XML 품질 확인 (파싱 가능 여부)

**Week 5: 메트릭 확장**

- [ ] 도메인별 특화 메트릭 추가 (`policies.json` 업데이트)
- [ ] 예: `multicast_rp_count`, `bgp_as_path_prepend_check` 등

### Phase 1-C: 평가 실행 (1주)

**Week 6: Pipeline 실행**

- [ ] `Make_Dataset` 실행 → `dataset.csv` 생성
- [ ] `Evaluation/pipeline_v2` 실행
- [ ] 결과 분석 및 논문 작성

### 예상 데이터셋 규모

| 도메인          | 장비 수   | 예상 질문 수  | 비고               |
| --------------- | --------- | ------------- | ------------------ |
| Backbone        | 12-15     | 150-200       | OSPF, LDP, FRR     |
| L2VPN           | 8         | 100-150       | 기존 보유          |
| L3VPN           | 10-12     | 200-250       | VRF, RT, RR        |
| BGP             | 6-8       | 100-150       | AS, Policy         |
| Multicast       | 8-10      | 100-150       | RP, IGMP           |
| **합계**        | **44-53** | **650-900**   | Rule-based (L1-L3) |
| Batfish (L4-L5) | -         | +300-400      | 도달성, What-If    |
| **총계**        | **~50대** | **950-1,300** | -                  |

---

## 6. 다음 단계 체크리스트

**즉시 착수 (High Priority)**:

1. [ ] PNETLab 포럼 회원가입 및 검색
2. [ ] Backbone 랩 다운로드 (후보 3개)
3. [ ] L3VPN 랩 다운로드 (후보 3개)
4. [ ] 첫 번째 랩 Import 테스트

**중기 목표 (1-2주)**:

- [ ] 5개 도메인 설정 파일 확보
- [ ] NSO 동기화 검증

**장기 목표 (1개월)**:

- [ ] 통합 데이터셋 950+ 샘플 완성
- [ ] 논문 실험 섹션 작성

---

**문서 업데이트**: 본 문서는 프로젝트 진행에 따라 실험실 확보 상황이 업데이트될 예정입니다.

**관련 문서**:

- [Phase1*5대*네트워크*도메인*상세.md](./Phase1_5대_네트워크_도메인_상세.md) - 각 도메인의 상세 설명
- [Phase2 고장 시나리오 (후속 연구)](../고장 시나리오/) - 오류 주입 기반 진단 연구
