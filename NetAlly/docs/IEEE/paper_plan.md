# IEEE TNMS 논문 구성안 (Full Paper Plan)

> **목표 학회**: IEEE Transactions on Network and Service Management (TNMS)  
> **투고 마감**: 2026-02-28  
> **최종 수정**: 2026-02-13 v2

> **실행 기준 (Rebaseline)**: 제출 본문은 v2 공개본 **L1~L5 (1,128)** 기준으로 고정.  
> L6 코드는 유지하되 이번 제출 결과/표/평가에서는 제외한다.

---

## 논문 제목 (안)

**NetConfigQA2.0 & NetAlly: A Scalable Benchmark and Multi-Agent System for Network Configuration Understanding**

---

## 핵심 스토리라인

```
[1] 문제 정의
    "LLM이 네트워크 설정을 이해하고 동적 추론할 수 있는가?"

[2] 벤치마크 제안 — NetConfigQA2.0
    ├── 제출 범위: 5단계 인지 난이도 (L1→L5)
    ├── Batfish 기반 자동 QA 생성 파이프라인
    ├── Type-Aware Accuracy 평가 지표
    └── 스케일러블: 설정 파일만 있으면 어떤 토폴로지든 자동 생성

[3] 스케일러빌리티 실험 — 핵심 차별점 ⭐
    ├── 제출 최소증거: 10 → 20 노드 (Lab-A → Lab-B)
    └── 확장 실험(옵션): 30/50 노드
        ├── 장비 수에 따른 LLM 성능 변화 관찰
        └── 파이프라인의 토폴로지 독립성 + 확장성 입증

[4] 도메인별 실험실 — 다양성 입증 (옵션) ⭐
    ├── SP 망 (MPLS VPN, 현재 사용 중)
    ├── 보안 중심 실험실 (ACL/Firewall 복잡)
    └── 각 실험실 특성에 따른 QA 분포/난이도 자동 적응

[5] 3-Layer 검증 ← NEW
    ├── Layer 1: Batfish 재실행 (1,128건 전수)
    ├── Layer 2: PNETLab 실환경 교차검증 (50건)
    └── Layer 3: LLM-as-Judge (100건)

[6] Single LLM 평가 → 한계 입증
    "L4/L5에서 모든 모델 ≤ 0.3" (KICS 결과 확장)

[7] Multi-Agent 평가 → 한계 극복
    팀원의 Multi-Agent가 Single LLM 대비 성능 향상 입증

[8] 외부 벤치마크 적용 ← NEW
    ├── 제출 우선: NIKA 1종 (장애 진단/트러블슈팅)
    └── 확장(옵션): NetPress, NetConfEval

[9] NetAlly — 실제 PNETLab 배포 + 데이터셋 평가 ← UPDATED
    ├── Multi-Agent를 실제 실험실에 적용한 시스템 = NetAlly
    ├── PNETLab + NSO + Batfish 통합 하이브리드 검증
    └── **NetConfigQA2.0 질문을 NetAlly에 투입 → 성능 측정** ⭐
```

---

## 논문 섹션별 구성

### I. Introduction (1.5p)

- 네트워크 관리의 LLM 활용 트렌드
- 기존 벤치마크의 한계: Knowledge Retrieval에만 집중
- **RQ1**: LLM이 네트워크 동적 추론이 가능한가?
- **RQ2**: 다양한 규모/유형의 네트워크에서도 일관된 평가가 가능한가?
- **RQ3**: Multi-Agent System이 Single LLM의 한계를 극복하는가?
- Contribution 요약

### II. Related Work (2p)

이미 정리 완료 (`research_notes.md` Section 4):
- 벤치마크: TeleQnA, TeleQuAD, NetBench, NetConfEval
- Agent: NIKA, INTA, Cisco DT, KubeLLM
- 도메인 LLM: TelecomGPT
- 포지셔닝 차트

### III. NetConfigQA2.0 — Dataset Construction (3p)

#### III-A. 실험 환경 (Experimental Labs)

| Lab | 노드 수 | 특징 | 프로토콜 |
|---|:---:|---|---|
| SP MPLS VPN | 10 | 기존 (KICS) | OSPF, MP-BGP, LDP, VRF |
| Security Lab | 15-20 | ACL/Firewall 중심 | Zone-based FW, ACL, NAT |
| DC Leaf-Spine | 20-30 | 데이터센터 | VXLAN, EVPN, BGP |
| Large-Scale SP | 40-50 | 대규모 SP | Multi-AS BGP, RSVP-TE |

> ⚠️ **현실적으로**: 2/28 마감 내에 4개 모두 어려울 수 있음. **우선순위**: (1) 기존 10노드 확장/검증, (2) L2VPN 활성화로 2번째 토폴로지, (3) 1-2개 추가 가능하면 추가.

#### III-B. Dual-Path 생성 파이프라인

- Path A: Rule-Based (L1-L3) — policies.json + Scope Expansion
- Path B: Procedural (L4-L5) — Batfish 시뮬레이션
- L6 Diagnostic 코드는 유지하되, 이번 제출에서는 제외(스냅샷 관리/공정성/재현성 리스크)

#### III-C. 5단계 인지 난이도 체계 (L1~L5)

DIKW 피라미드 기반 설계 철학 (`5_LEVEL_DIFFICULTY_PHILOSOPHY.md` 활용):

| Level | 철학 | 인지 활동 | 질문 본질 |
|:---:|---|---|---|
| L1 | Fact | Extraction | "있는 그대로 무엇이 적혀있는가?" |
| L2 | Statistics | Aggregation | "전체적인 현황은?" |
| L3 | Consistency | Comparison | "논리적 모순이 없는가?" |
| L4 | Behavior | Simulation | "패킷을 보내면 어떤 일이?" |
| L5 | Resilience | Counterfactual | "만약 상황이 바뀌면?" |

#### III-D. 스케일러빌리티 실험 설계

```
                 ┌─────────────────────────────────────────┐
                 │  동일 파이프라인으로 자동 생성             │
                 └─────────────────────────────────────────┘
                        ↓           ↓           ↓            ↓
                    10 nodes    20 nodes    30 nodes     50 nodes
                  (1,128 QA)  (~1,500?)   (~2,500?)    (~4,000?)
                        ↓           ↓           ↓            ↓
                 ┌─────────────────────────────────────────┐
                 │  동일 모델로 평가 → 규모에 따른 성능 변화  │
                 └─────────────────────────────────────────┘
```

**예상 발견 (가설)**:
- L1 성능: 장비 수 증가에 비교적 robust (단일 장비 조회이므로)
- L2/L3 성능: 장비 수 증가에 따라 하락 (더 많은 정보 집계 필요)
- L4/L5 성능: 장비 수 증가에 따라 급격히 하락 (경로 복잡도 증가)
- **결론**: "LLM의 네트워크 추론 능력은 네트워크 규모에 반비례한다"

### IV. Evaluation Metric — TA-Acc (1p)

- 기존 지표(BERTScore, EM, F1)의 한계
- Type-Aware Accuracy 수식
- Answer type별 비교 함수
- BERTScore vs TA-Acc 변별력 비교 (KICS 결과 활용)

### V. Dataset Validation (1.5p) — 🔴 새로 작성 필요

#### V-A. 자동 검증 (Automated Verification)

- Batfish 재실행 기반 Ground Truth 일관성 검사
- PASS/FAIL/SKIP 비율 보고
- FAIL 원인 분석: `bounded_path_length` 불일치 등

#### V-B. Cross-Tool Validation (PNETLab 실제 결과와 비교)

```
L4 traceroute 질문 30개:
  Batfish 정답 vs PNETLab 실제 traceroute
  → 일치율 보고 (예: 93% 일치)
```

#### V-C. LLM-as-Judge (보조적)

- GPT-4o로 100개 샘플의 질문 명확성, 정답 정확성 판정
- 자동 검증의 보완

### VI. Experiments (3p) — 핵심 실험 섹션

#### VI-A. 기존 벤치마크 비교 (KICS 결과 확장)

| | TeleQnA | TeleQuAD | NetBench | NetConfigQA2.0 |
|---|:---:|:---:|:---:|:---:|
| 5+ 모델 | ✅ | ✅ | ✅ | ✅ |

#### VI-B. Single LLM 난이도별 성능

- KICS Table 4 확장 (v2 데이터셋 1,128건, L1~L5 기준)
- **추가**: GPT-4o, Claude 3.5 (가능하면)

#### VI-C. 스케일러빌리티 실험 ⭐

| Model | 10 nodes | 20 nodes | 30 nodes | 50 nodes |
|---|:---:|:---:|:---:|:---:|
| GPT-4o-mini | - | - | - | - |
| GPT-OSS-20B | - | - | - | - |
| ... | | | | |

→ 레벨별 × 규모별 heat map이 최고의 시각화

#### VI-D. Multi-Agent vs Single LLM

| Model/System | L1 | L2 | L3 | L4 | L5 |
|---|:---:|:---:|:---:|:---:|:---:|
| GPT-OSS-20B (Single) | 0.873 | 0.873 | 0.605 | 0.266 | 0.134 |
| Multi-Agent (팀원) | ? | ? | ? | ? | ? |

#### VI-E. 기존 연구 벤치마크에서 Multi-Agent 성능 비교

- 타 네트워크 벤치마크/챌린지에 Multi-Agent 적용
- 기존 방법 대비 우위 입증

#### VI-F. Error Analysis

- L4/L5 실패 유형 분류 (30건 정성 분석)
- 실패 원인: 경로 복잡도, VRF 격리 미이해, 장애 전파 추론 실패 등

### VII. NetAlly — Practical Deployment (1.5p)

- Multi-Agent의 실제 PNETLab 적용 = NetAlly
- Orchestrator + Executor 아키텍처
- scan_and_sync → Batfish → NSO 하이브리드 파이프라인
- NetAlly 성능 (NetConfigQA2.0에서 평가)

### VIII. Discussion (1p)

- LLM의 네트워크 추론 한계와 도구 활용의 필요성
- 스케일러빌리티 실험의 시사점
- 도메인별 실험실의 QA 특성 차이
- 범용 LLM vs 도메인 LLM vs 도구 활용 Agent 비교

### IX. Conclusion & Future Work (0.5p)

---

## 검증 코드 관련

### 현재 상태

🔴 **`_verification.md` 및 `_verification_failures.csv`를 생성한 스크립트를 찾지 못했습니다.** 

프로젝트 전체를 검색했으나 `verification_failures`, `_verification.md`, `PASS/FAIL/SKIP` 패턴을 생성하는 Python 코드가 없습니다. 이 검증 보고서는:
1. 삭제된 일회성 스크립트로 생성했거나
2. Jupyter Notebook에서 생성했거나
3. 별도 환경에서 실행했을 가능성

### 관련 코드가 있는 곳

| 파일 | 내용 |
|---|---|
| `Make_Dataset/generate_golden_set.py` | 메트릭당 1개 대표 QA 생성 (검증용은 아님) |
| `Make_Dataset/src/core_batfish/batfish_builder.py` | L4/L5 QA 생성 + "verification" 참조 문자열 |
| `Make_Dataset/tests/test_l6_analyzer.py` | L6 유닛 테스트 (이번 제출 평가 범위 외) |

### 검증 코드 재구축 필요

검증 코드를 새로 작성해야 합니다. 핵심 로직:

```python
# 검증 스크립트 핵심 로직 (작성 필요)
for each QA pair in dataset:
    1. metric 유형 확인
    2. Batfish에 동일 질의 재실행
    3. 생성된 정답 vs 재실행 결과 비교
    4. PASS/FAIL/SKIP 판정
    5. FAIL인 경우 원인 기록
```

---

## 현실적 마감 판단 (2/28까지)

### 반드시 해야 하는 것 (Must-Have)

| # | 작업 | 소요 |
|:---:|---|:---:|
| 1 | v2 데이터셋(1,128건) 검증 코드 작성 + 실행 | 2일 |
| 2 | L2 질문 보강 (21→50+) | 1일 |
| 3 | L6 제외 근거/범위 문서화 완료 | 0.5일 |
| 4 | v2 데이터셋으로 전 모델 재실험 (Single LLM) | 2일 |
| 5 | Error Analysis (L4/L5 실패 유형 30건) | 1일 |
| 6 | Cross-Tool Validation (PNETLab traceroute) | 2일 |
| 7 | 논문 작성 (KICS 확장) | 3일 |

### 가능하면 추가 (Should-Have)

| # | 작업 | 소요 |
|:---:|---|:---:|
| 8 | 스케일러빌리티 실험 (20/30 노드) | 3-5일 |
| 9 | Multi-Agent 평가 (팀원 협업) | 2일 |
| 10 | 2번째 토폴로지 (L2VPN) | 2일 |

### 시간이 남으면 (Nice-to-Have)

| # | 작업 | 소요 |
|:---:|---|:---:|
| 11 | 40/50 노드 확장 | 5일+ |
| 12 | 도메인별 실험실 (Security Lab) | 5일+ |
| 13 | 기존 연구 벤치마크 적용 | 3일+ |

---

## 스케일러빌리티 실험 — 구현 방법

### 토폴로지 확장 접근법

| 방법 | 장점 | 단점 |
|---|---|---|
| **PNETLab에서 직접 구성** | 실제 환경, 가장 신뢰성 높음 | 시간 소요 큼 |
| **GNS3/Batfish 예제 활용** | 다양한 오픈소스 토폴로지 존재 | 설정 파일 형식 확인 필요 |
| **기존 토폴로지 복제+확장** | 빠르고 일관된 설정 | 인위적일 수 있음 |
| **Config Generator 스크립트** | 대규모 생성 가능 | 현실성 검증 필요 |

### 권장: 하이브리드 접근

1. **10 노드**: 기존 Research_Institute_Internal_DC (완료)
2. **20 노드**: 기존 10 노드 + L2VPN 8 노드 합치기, 또는 기존 확장
3. **30 노드**: PNETLab에서 기존 기반으로 확장 구성
4. **50 노드**: 시간 여유 시

> 💡 **핵심**: 파이프라인이 설정 파일만 있으면 자동 생성하므로, **토폴로지 구성만 되면 QA 생성은 자동**. 병목은 토폴로지 구성 시간.

---

## 도메인별 실험실 아이디어

| 실험실 유형 | 특화 영역 | 기대 효과 |
|---|---|---|
| **보안 중심** | ACL 규칙 많음, Zone-based FW, NAT | L3(Security_Policy)와 L4(acl_blocking_point) 질문 풍부 |
| **데이터센터** | Leaf-Spine, VXLAN, EVPN | L1 인터페이스 수 폭발, L3 Fabric 정합성 |
| **SP 대규모** | Multi-AS BGP, RSVP-TE, Segment Routing | L4/L5 경로 복잡도 극대화 |
| **캠퍼스** | STP, DHCP, DNS, RADIUS | L1 풍부하지만 L4/L5 단순 |

→ "실험실 성격에 따라 데이터셋의 난이도 분포가 자동으로 달라진다"는 것 자체가 논문 기여
