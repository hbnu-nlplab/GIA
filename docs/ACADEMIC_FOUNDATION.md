# 🎓 NetConfigQA 학술적 근거 문서

> **이 문서는 NetConfigQA 데이터셋의 질문 설계가 NSDI/SIGCOMM 최상위 학회 논문들에 기반함을 증명합니다.**

---

## 📚 핵심 참조 논문 (Golden 6)

| # | 논문 | 학회 | 인용수 | 핵심 기여 |
|---|------|------|--------|----------|
| 1 | **HSA** (Header Space Analysis) | NSDI 2012 | 1000+ | Reachability, Loop, Isolation 정의 |
| 2 | **VeriFlow** | NSDI 2013 | 1300+ | 실시간 Network-wide Invariant 검증 |
| 3 | **Batfish** | NSDI 2015 | 400+ | Config → Data Plane 분석 파이프라인 |
| 4 | **Minesweeper** | SIGCOMM 2017 | 300+ | 8가지 핵심 검증 속성 정의 |
| 5 | **Config2Spec** | NSDI 2020 | 70+ | 정책 기반 Specification 마이닝 |
| 6 | **DNA** (Differential Network Analysis) | NSDI 2022 | 50+ | What-If / Differential Reachability |

---

## 🔑 핵심 인바리언트 (Core Invariants)

### 6대 논문에서 공통으로 등장하는 검증 속성

| # | 인바리언트 | 설명 | 출처 논문 | NetConfigQA 레벨 |
|---|-----------|------|----------|-----------------|
| 1 | **Reachability** | A→B 트래픽 도달 가능 여부 | HSA, VeriFlow, Batfish, Minesweeper, Config2Spec, DNA | L4 |
| 2 | **Loop-freedom** | 포워딩 루프 없음 | HSA, VeriFlow, Minesweeper | L4 |
| 3 | **Blackhole-freedom** | 패킷이 중간에 드랍되지 않음 | HSA, VeriFlow, Minesweeper | L4 |
| 4 | **Isolation** | 테넌트/VRF 간 트래픽 격리 | HSA, Minesweeper, Config2Spec | L3, L4 |
| 5 | **Waypointing** | 특정 노드(FW, IDS)를 반드시 통과 | Minesweeper, Config2Spec | L4 |
| 6 | **Bounded Path Length** | 경로 홉 수 ≤ N | Minesweeper | L4 |
| 7 | **Fault Tolerance** | k개 링크 장애 시에도 도달성 유지 | Minesweeper, Batfish | L5 |
| 8 | **Differential Reachability** | 변경 전/후 도달성 차이 | DNA, Batfish | L5 |
| 9 | **Consistency** | 멀티패스/장애/목적지별 일관성 | Batfish | L3 |
| 10 | **Functional Equivalence** | 두 라우터가 동일 동작 수행 | Minesweeper | L3 |

---

## 📊 레벨별 인바리언트 매핑

### L1: 단일 장비 설정값 조회
- **관련 개념**: Batfish의 Configuration Parsing
- **예시**: 호스트네임, SSH 버전, OSPF Process ID

### L2: 복수 장비 설정값 집계
- **관련 개념**: Config2Spec의 Policy Mining
- **예시**: SSH 활성화 장비 목록, VRF 사용 장비 그룹

### L3: 복수 장비 + 계산/비교
- **관련 개념**: Batfish의 Consistency 검증, Minesweeper의 Functional Equivalence
- **예시**: iBGP Full-Mesh 검증, VRF RT 일관성, L2VPN 양방향성

### L4: 네트워크 흐름 도달성
- **관련 개념**: HSA/VeriFlow의 Reachability, Minesweeper의 8가지 속성
- **예시**: A→B 도달성, 루프 탐지, 블랙홀 탐지, 웨이포인트 검증

### L5: What-If / Differential 분석
- **관련 개념**: DNA의 Differential Reachability, Minesweeper의 Fault Tolerance
- **예시**: 링크 장애 영향, 설정 변경 영향, k-failure tolerance

---

## 🎯 대표 어려운 질문 예시 (Demo용)

### L1 예시 (2개)
```
Q1: CE1 장비의 SSH 버전은 무엇입니까?
    [근거: Batfish - Configuration Properties]
    
Q2: PE1 장비에 설정된 OSPF Process ID 목록을 알려주세요.
    [근거: Batfish - Routing Configuration]
```

### L2 예시 (2개)
```
Q3: 네트워크에서 SSH가 활성화되지 않은 장비 목록을 알려주세요.
    [근거: Config2Spec - Security Policy Mining]
    
Q4: VRF 'CUSTOMER_A'를 사용하는 모든 장비를 나열하세요.
    [근거: Config2Spec - VRF Policy]
```

### L3 예시 (3개)
```
Q5: AS 65000 내 모든 iBGP 피어가 Full-Mesh로 연결되어 있습니까?
    [근거: Batfish - BGP Consistency, Minesweeper - Functional Equivalence]
    
Q6: PE1과 PE2의 VRF 'CUSTOMER_A' RT(Route Target) 설정이 일치합니까?
    [근거: Batfish - VRF Consistency]
    
Q7: L2VPN PW-ID 100번 회선이 양방향으로 설정되어 있습니까?
    [근거: Batfish - L2VPN Consistency]
```

### L4 예시 (4개) ⭐
```
Q8: CE1(192.168.1.1)에서 CE2(192.168.2.1)로의 TCP/22 트래픽이 도달 가능합니까?
    [근거: HSA, VeriFlow, Batfish - Reachability]
    
Q9: 네트워크에 포워딩 루프가 존재합니까? 존재한다면 어느 경로입니까?
    [근거: HSA, VeriFlow - Loop-freedom]
    
Q10: CE1에서 CE2로 가는 트래픽이 반드시 Firewall(FW1)을 통과합니까?
     [근거: Minesweeper, Config2Spec - Waypointing]
     
Q11: CE1에서 Server(10.0.0.100)로 가는 경로의 홉 수가 5 이하입니까?
     [근거: Minesweeper - Bounded Path Length]
```

### L5 예시 (3개) ⭐⭐
```
Q12: PE1-P1 링크가 다운되어도 CE1에서 CE2로의 도달성이 유지됩니까?
     [근거: Minesweeper - Fault Tolerance, DNA - Differential Reachability]
     
Q13: 임의의 단일 링크 장애 시에도 모든 CE 간 통신이 가능합니까? (1-failure tolerance)
     [근거: Minesweeper - k-Failure Tolerance]
     
Q14: PE1에 새로운 ACL을 적용하면, 어떤 트래픽 흐름에 영향이 있습니까?
     [근거: DNA - Differential Network Analysis]
```

---

## 📝 발표용 슬라이드 문구

### 한국어 (3-4문장)

> **NetConfigQA의 학술적 기반**
>
> 본 데이터셋의 질문들은 임의로 설계된 것이 아니라, **USENIX NSDI와 ACM SIGCOMM**에서 발표된 네트워크 검증 분야의 대표 논문들에 기반합니다.
>
> 특히 **HSA(NSDI'12, 1000+ 인용), VeriFlow(NSDI'13, 1300+ 인용), Batfish(NSDI'15), Minesweeper(SIGCOMM'17)** 등에서 정의된 핵심 검증 속성(Reachability, Loop-freedom, Isolation, Waypointing 등)을 Q&A 형식으로 재구성하였습니다.
>
> 이를 통해 LLM의 네트워크 설정 분석 능력을 **학술적으로 검증된 기준**으로 평가할 수 있습니다.

### English (Optional)

> **Academic Foundation of NetConfigQA**
>
> The questions in this dataset are grounded in seminal network verification papers from top-tier venues including **USENIX NSDI and ACM SIGCOMM**.
>
> We systematically reformulate core invariants from **HSA (NSDI'12), VeriFlow (NSDI'13), Batfish (NSDI'15), Minesweeper (SIGCOMM'17), Config2Spec (NSDI'20), and DNA (NSDI'22)** into a Q&A format.
>
> This enables rigorous evaluation of LLM capabilities in network configuration analysis against academically validated criteria.

---

## 🔗 참고 문헌

1. Kazemian, P., et al. "Header Space Analysis: Static Checking for Networks." **NSDI 2012**.
2. Khurshid, A., et al. "VeriFlow: Verifying Network-Wide Invariants in Real Time." **NSDI 2013**.
3. Fogel, A., et al. "A General Approach to Network Configuration Analysis." **NSDI 2015**.
4. Beckett, R., et al. "A General Approach to Network Configuration Verification." **SIGCOMM 2017**.
5. Birkner, R., et al. "Config2Spec: Mining Network Specifications from Network Configurations." **NSDI 2020**.
6. Zhang, P., et al. "Differential Network Analysis." **NSDI 2022**.
7. Prabhu, S., et al. "Plankton: Scalable Network Configuration Verification through Model Checking." **NSDI 2020**.
8. Gember-Jacobson, A. "Network Verification & Synthesis Reading List." https://aaron.gember-jacobson.com/research/readinglist/

---

## 📅 변경 이력

| 버전 | 날짜 | 변경 내용 |
|------|------|----------|
| 1.0 | 2024-11 | 초기 작성 - Golden 6 논문 기반 인바리언트 정리 |

