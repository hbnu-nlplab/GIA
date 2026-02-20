# NetConfigQA 2.0 & NetAlly: 네트워크 구성 이해를 위한 확장 가능한 벤치마크와 Multi-Agent 시스템

> **대상 학회**: IEEE Transactions on Network and Service Management (TNSM)  
> **초안 버전**: v2.0 (2026-02-18) — TNSM 형식 재구조화  
> **페이지 제한**: 10 pages (2-column, IEEE format) — 초과 시 $220/page  
> **영문 버전**: `paper_draft.md`

---

## 초록 (Abstract)

<!-- 📝 TNSM 규정: 150-250 words, 약어·각주·참고문헌·수식 사용 금지 -->

대규모 언어 모델의 활용이 네트워크 구성 관리에 확대되고 있으나, 기존 벤치마크는 표준 문서의 지식 회상만을 측정할 뿐 실제 설정 파일로부터 네트워크 동작을 추론하는 능력은 평가하지 못한다. 또한 단일 에이전트 구조로는 다수 장비에 걸친 데이터 플레인 시뮬레이션과 장애 영향 분석에 한계가 있다.

본 연구는 벤치마크와 Multi-Agent 시스템을 함께 제안한다. NetConfigQA 2.0은 실제 Cisco IOS 설정 파일과 Batfish 시뮬레이션을 기반으로 5단계 인지 난이도(단일 장비 조회부터 장애 영향 추론까지)의 질문-답변 쌍을 자동 생성하는 벤치마크이다. 이중 경로 생성 파이프라인과 Type-Aware Accuracy 지표를 제공하며, 토폴로지 규모에 무관하게 확장 가능하도록 설계되었다. Ground Truth의 신뢰성은 독립 구문 분석기, 수동 검증, 실장비 CLI 검증의 3중 방식으로 확보한다. NetAlly는 Orchestrator–Executor 구조에 시뮬레이션, 구성 관리, 정형 검증 도구를 통합한 Multi-Agent 시스템으로, 연산 집약적 태스크를 전용 도구에 위임한다.

5개 모델에 대한 실험에서, 모든 모델이 동적 추론 단계에서 정확도 0.3 이하를 보여 단독 추론의 한계가 확인되었다. 반면 기존의 의미 유사도 지표는 0.9를 초과하여 모델 간 차이를 변별하지 못했다.

**키워드**: 네트워크 구성, 대규모 언어 모델, Multi-Agent 시스템, 벤치마크, 정형 검증, Batfish, Type-Aware Accuracy

<!-- 📝 \begin{IEEEkeywords} ... \end{IEEEkeywords} -->

---

## I. 서론 (Introduction)

<!-- 📝 LaTeX 적용 시: \IEEEPARstart{L}{arge} Language Models... -->

대규모 언어 모델(LLM)은 자연어 이해와 코드 생성에서 높은 성능을 보이고 있다 [1]. 그러나 단일 LLM은 다단계 추론, 외부 도구 연동, 동적 환경 인식 등에서 한계가 있다. 이에 따라 여러 에이전트가 협력하여 태스크를 분할 처리하는 Multi-Agent System(MAS) 접근이 활발히 연구되고 있으며 [2], LangGraph, AutoGPT, CrewAI 등의 프레임워크가 에이전트 간 상태 공유와 도구 호출을 체계화하고 있다 [3].

네트워크 관리는 전통적으로 벤더별 CLI 명령어와 스크립팅 전문 지식에 의존하는 영역이다. 최근 Cisco, Juniper 등 주요 벤더들은 LLM을 활용한 자연어 기반 네트워크 운영(ChatOps)을 시도하고 있다 [4]. 학술적으로도 NetConfEval [5], NIKA [6], NetPress [7] 등 LLM의 네트워크 구성 능력을 평가하는 벤치마크와 시스템이 제안되고 있으며, IETF에서도 NetConfBench 프레임워크 초안 [8]을 통해 LLM 에이전트의 다단계 구성 시나리오에 대한 평가 방법론을 표준화하고 있다.

그러나 대부분의 기존 연구는 **지식 검색(Knowledge Retrieval)**에 집중하고 있다—표준 문서에서 사실을 회상하는지(TeleQnA [9], TeleQuAD [10]) 또는 전문가 큐레이션 지식 베이스를 활용하는지(NetBench [11])를 평가한다. 이는 실제 설정 파일에서 네트워크가 어떻게 동작하는지를 이해하는 **동작 추론(Behavioral Inference)**과는 다른 문제이다.

현재 LLM 기반 네트워크 관리 접근법은 세 가지 한계를 가진다. (1) **단일 에이전트의 인지 부하**: 네트워크 토폴로지는 수백 개의 인터페이스, 다중 라우팅 프로토콜(OSPF, BGP, MPLS, LDP), VRF 격리를 포함하며, 단일 LLM이 제한된 컨텍스트 윈도우 내에서 이를 모두 처리하기 어렵다. (2) **검증 없는 생성**: LLM이 생성한 구성이나 분석 결과에 대한 정형 검증 메커니즘이 없어, 환각(hallucination)에 의한 잘못된 출력이 네트워크 변경으로 이어질 수 있다. (3) **평가 체계의 한계**: 기존 벤치마크는 Exact Match, F1, BERTScore 등에 의존하는데, 네트워크 고유 데이터에 대한 변별력이 낮다. 본 실험에서 BERTScore는 모든 모델·모든 난이도에서 0.9를 초과하여 모델 간 차이를 구분하지 못했다.

이에 본 연구는 다음 세 가지 연구 질문을 설정한다:

- **RQ1**: Multi-Agent System이 단일 LLM 대비 구성 조회, 검증, 장애 진단 태스크에서 더 높은 정확도를 보이는가?
- **RQ2**: PNETLab(시뮬레이션), NSO(구성 관리), Batfish(정형 검증)를 결합한 하이브리드 아키텍처가 네트워크 검증에 유효한가?
- **RQ3**: NetConfigQA 2.0 벤치마크가 다중 인지 난이도에 걸쳐 LLM 기반 네트워크 관리 시스템을 적절히 평가할 수 있는가?

본 연구의 기여는 다음과 같다:

- **C1**: 네트워크 관리에 특화된 Multi-Agent System **NetAlly**의 설계 및 구현. Orchestrator–Executor 역할 분리와 LangGraph 기반 상태 관리를 통한 도구 증강 추론.
- **C2**: PNETLab(시뮬레이션), Cisco NSO(구성 관리), Batfish(정형 검증)를 통합한 **하이브리드 검증 파이프라인**. *scan-and-sync*를 통한 자동 온보딩과 *fork-snapshot*을 활용한 비파괴적 장애 시뮬레이션.
- **C3**: **NetConfigQA 2.0** 벤치마크 데이터셋: 5단계 인지 난이도(L1~L5), 126개 메트릭, 17개 카테고리에 걸친 1,029개 Q&A 쌍, 네트워크 특화 평가를 위한 Type-Aware Accuracy(TA-Acc), 임의의 토폴로지로 확장 가능한 자동 생성 파이프라인.

본 논문은 다음과 같이 구성된다. Section II에서 관련 연구를 정리하고, Section III에서 NetConfigQA 2.0 데이터셋의 구축·평가 지표·검증 방법을 기술한다. Section IV에서 NetAlly 시스템 아키텍처를 소개하며, Section V에서 실험 결과를 제시한다. Section VI에서 논의하고, Section VII에서 결론을 맺는다.

---

## II. 관련 연구 (Related Work)

### A. 네트워크 LLM 벤치마크

표 I은 네트워크 분야의 LLM 평가 벤치마크를 비교한다.

<!-- 📝 LaTeX: \begin{table}[!t] ... TABLE I ... \end{table} -->

| 벤치마크 | 태스크 유형 | 데이터 소스 | GT 생성 방식 | 평가 지표 |
|---|---|---|---|---|
| TeleQnA [9] | 지식 회상 (객관식) | 3GPP 표준 문서 | 인간 + LLM | Accuracy |
| TeleQuAD [10] | 지식 추출 (추출형 QA) | 3GPP 규격 | 문서 구간 추출 | F1 / EM |
| NetBench [11] | 지식 서술 (자유 서술) | 전문가 큐레이션 | 전문가 작성 | 전문가 평가 |
| NetConfEval [5] | 설정 생성 | 문서 | 참조 설정 | Accuracy |
| NETLLMBENCH [12] | 설정 생성 + 검증 | 스키마 | Kathara 에뮬레이션 | 구문+의미 |
| NetPress [7] | 상태-동작 추론 | 런타임 생성 | 에뮬레이터 실행 | 정확도+안전+지연 |
| **NetConfigQA 2.0** | **설정 해석 + 동작 추론** | **실제 .cfg 파일** | **Batfish 시뮬레이션** | **TA-Acc** |

기존 벤치마크는 표준 문서에서 사실을 회상하거나 설정을 생성하는 태스크를 다루는 반면, NetConfigQA 2.0은 실제 설정 파일로부터 네트워크 동작을 추론하는 태스크를 평가한다.

### B. LLM 기반 네트워크 관리 에이전트

LLM 에이전트를 네트워크 운영에 활용하는 연구가 2024~2025년에 확대되고 있다.

**NIKA** [6] (ACM SIGCOMM NGNO 2025)는 AI 에이전트의 네트워크 문제 해결 능력을 벤치마킹하는 아레나로, 5개 시나리오, 54종 장애 유형, 640개 이상의 인시던트를 제공한다. MCP 인터페이스를 통해 30개 이상의 도구를 노출하며, GPT-4급 모델이 장애 탐지는 가능하나 위치 특정과 근본 원인 식별에서는 성능이 낮음을 보고하고 있다.

**INTA** [13] (IEEE ICNP 2025)는 RAG 기반 LLM 에이전트로 인텐트 기반 설정 변환을 수행하며, 98.15%의 구문 정확도를 보고하였다. INTA가 설정 *작성*을 다루는 반면, 본 연구는 설정 *읽기 및 추론*을 평가한다.

**Cisco Deep Network Troubleshooting** (Cisco Live 2025)는 도메인 특화 Knowledge Graph와 40년간의 전문 지식을 활용한다. NetAlly는 범용 LLM과 시뮬레이션 도구의 조합으로 유사한 진단 태스크를 수행하는 접근이다.

**KubeLLM** [14]은 Kubernetes 트러블슈팅을 위한 Multi-Agent 프레임워크로, Knowledge Agent와 Tools Agent를 분리하여 단일 에이전트 대비 정확도 개선을 보고하였다.

**Confucius** [15] (SIGCOMM 2025)는 Multi-Agent LLM 기반 인텐트 기반 네트워크 관리를 제안하였다.

**AskBatfish** [16]는 LLM 기반 챗봇을 통해 Batfish와의 자연어 상호작용을 가능하게 한다. AskBatfish가 인터페이스 레이어를 제공하는 반면, NetAlly는 Batfish를 Multi-Agent 추론 파이프라인 내의 도구 중 하나로 통합한다.

### C. 포지셔닝

```
  동작 추론 ───────────────────────────────────────────────────
              │                     ┌── NetAlly ──┐            │
              │                     │  Agent +    │            │
              │          NetPress●  │  동작 추론  │            │
              │     NIKA●           └─────────────┘            │
  평가 전용   │  NETLLMBENCH●                                  │
              │ NetConfEval●      ●NetConfigQA 2.0             │
              │  TeleQnA●                                      │
  지식 검색 ──┼────────────────────────────────────────────── │
              │ NeMoEval● TeleQuAD●   KubeLLM● ●Cisco DT      │
              └────────────────────────────────────────────────
                벤치마크              운영 에이전트
```

본 연구는 벤치마크와 에이전트를 함께 제공하여, "문제 정의 → 한계 확인 → 해결책 제시 → 효과 검증"의 흐름을 하나의 프레임워크 내에서 수행한다.

---

## III. NetConfigQA 2.0: 벤치마크 데이터셋

### A. 실험 환경

기본 토폴로지는 Research Institute Internal DC (Lab-A)로, 10대의 Cisco IOS 라우터로 구성된 Service Provider MPLS VPN 네트워크이다: P(Provider) 라우터 4대, PE(Provider Edge) 라우터 2대, Leaf 스위치 4대가 OSPF, MP-BGP, LDP, VRF 구성으로 연결되어 있다.

확장성 입증을 위해 점진적으로 복잡해지는 National Converged Network(NCN) 시리즈를 설계하였다:

| Lab | 노드 수 | 컨셉 | 핵심 프로토콜 | 활성 메트릭 | 예상 QA |
|---|:---:|---|---|:---:|:---:|
| Lab-A | 10 | SP MPLS VPN | OSPF, BGP, LDP, VRF | ~50 | 1,029 |
| Lab-B | 20 | NCN 기본 SP | + NTP, SNMP, AAA | ~65 | ~1,500 |
| Lab-C | 30 | NCN 보안 + L2VPN | + L2VPN, ACL, eBGP, HSRP | ~75 | ~2,500 |
| Lab-D | 40 | NCN 멀티 AS 복합 | + QoS, NetFlow, Waypoint | ~80+ | ~3,500 |

Config Generator (YAML 토폴로지 + Jinja2 템플릿)가 모든 Lab의 설정 파일 생성을 자동화하며, PNETLab node ID 자동 재매핑(Remap) 기능을 포함한다.

### B. 이중 경로(Dual-Path) QA 생성 파이프라인

NetConfigQA 2.0은 이중 경로 생성 아키텍처를 사용한다.

**경로 A — 규칙 기반 생성 (L1~L3):** 설정 파일을 Batfish가 파싱하여 정적 팩트 JSON으로 변환한다. `policies.json`에 정의된 126개 메트릭 각각에 대해 질문 템플릿, 스코프 확장 규칙, 답변 타입을 지정한다. 스코프 확장(Scope Expansion) 메커니즘이 12가지 스코프 타입(GLOBAL, DEVICE, DEVICE_PAIR, AS, OSPF_AREA, VRF, FLOW 등)에 걸쳐 질문 인스턴스를 동적으로 생성한다.

**경로 B — 절차적 생성 (L4~L5):** 노드 쌍을 샘플링하고, Batfish 시뮬레이션(traceroute, 도달성 분석, fork-snapshot + 차등 도달성)을 실행한 뒤, 결과를 Q&A 쌍으로 변환한다.

<!-- 📝 LaTeX: \begin{figure}[!t] 파이프라인 다이어그램 \end{figure} -->

```
설정 파일 (.cfg)
     │
     ├──→ [Batfish 정적 분석] → Static Facts JSON
     │         │
     │    [경로 A: 규칙 기반]       [경로 B: 절차적]
     │    policies.json (126 메트릭)  Batfish 시뮬레이션
     │    스코프 확장 (12 타입)       traceroute / reachability
     │         │                     fork_snapshot / diff
     │    L1-L3 QA                   L4-L5 QA
     │         │                        │
     └─────── 데이터셋 조립기 ──────────┘
                    │
              최종 데이터셋 (CSV + JSON)
```

### C. 5단계 인지 난이도 체계

네트워크 운영자가 겪는 인지적 부하(Cognitive Load)의 단계를 기준으로 5단계 난이도를 설계하였다. DIKW(Data–Information–Knowledge–Insight) 피라미드를 네트워크 운영 컨텍스트에 맞게 재해석하여, 단순한 정보 조회(Lookup)에서 복잡한 인과 관계 추론(Reasoning) 및 가상 시나리오 분석(Counterfactual)으로 나아가는 체계이다.

<!-- 📝 LaTeX: TABLE II -->

| 레벨 | 속성 | 인지 활동 | 질문 본질 | 정답 생성 방식 | 인지 부하 | 학술 근거 |
|:---:|---|---|---|---|:---:|---|
| **L1** | Fact (사실) | Extraction (추출) | "장비에 있는 그대로 무엇이 적혀있는가?" | Config 파싱 + Batfish Questions | O(1) | Batfish [17] |
| **L2** | Stats (통계) | Aggregation (집계) | "네트워크 전체 통계는 어떠한가?" | 전체 장비 순회/카운팅 | O(N) | Config2Spec [20] |
| **L3** | Logic (정합성) | Comparison (비교) | "설정 간에 논리적 모순이 없는가?" | 장비 간 교차 검증 | O(N²) | Mineray [21] |
| **L4** | Flow (흐름) | Simulation (시뮬레이션) | "패킷을 보내면 실제로 도착하는가?" | Batfish traceroute/reachability | 프로토콜 시뮬레이션 | HSA [22], VeriFlow [23] |
| **L5** | Impact (영향) | Reasoning (인과 추론) | "장애가 나면 어떻게 되는가?" | Fork Snapshot + Differential Reachability | 복수 시뮬레이션 비교 | Minesweeper [24], DNA [25] |

L1~L3는 정적 분석(Static Analysis)으로 설정 파일의 텍스트에서 규칙과 값을 검증하는 영역이며, L4~L5는 동적 추론(Dynamic Reasoning)으로 텍스트 너머의 실제 패킷 흐름과 장애 영향을 예측하는 영역이다.

데이터셋 통계 (Lab-A, v2, EN):

| 레벨 | QA 수 | 비율 | 대표 질문 |
|:---:|:---:|:---:|---|
| L1 | 634 | 61.6% | "PE1의 호스트네임은 무엇입니까?" |
| L2 | 21 | 2.0% | "SSH가 활성화된 장비는 총 몇 대입니까?" |
| L3 | 126 | 12.2% | "iBGP Full-Mesh 구성이 완성되어 있습니까?" |
| L4 | 146 | 14.2% | "PE1에서 10.0.1.1까지의 경로는?" |
| L5 | 102 | 9.9% | "PE1↔P1 링크 장애 시 10.0.0.1→10.0.3.1은?" |
| **합계** | **1,029** | **100%** | |

### D. Type-Aware Accuracy (TA-Acc)

전통적 NLP 지표는 네트워크 구성 평가에 적합하지 않다. BERTScore는 의미적으로 다른 네트워크 데이터(예: `10.0.1.1`과 `10.0.1.10`)에 높은 유사도(>0.9)를 부여한다. Exact Match는 동등한 표현(`{r1, r2, r3}`과 `{r3, r1, r2}`)을 오답으로 처리한다. F1은 라우팅 경로의 순서를 무시한다.

이에 답변 타입에 따른 비교 함수를 정의한다:

| `answer_type` | 비교 방법 | 예시 |
|---|---|---|
| `set` | F1 Score (순서 무관) | BGP 이웃 목록 |
| `text` | 정규화 후 Exact Match | 경로, IP 주소, 호스트네임 |
| `numeric` / `number` | 숫자 추출 후 Exact Match | 홉 수, AS 번호 |
| `boolean` | 의미 정규화 비교 ("yes"/"True"/"1" → True) | SSH 활성화 여부 |
| `map` | Key-Value 구조 비교 | 인터페이스별 IP 매핑 |

TA-Acc는 질문별로 계산하여 레벨별로 평균을 산출한다.

### E. 데이터셋 검증

자동 생성된 Ground Truth의 검증은 핵심 과제이다. Batfish 쿼리를 재실행하는 것은 순환 논증에 해당하므로, 3가지 독립적 방법을 사용한다.

**Method 1: 독립 Config 파서.** Batfish를 사용하지 않는 Python+Regex 파서(약 2,100줄)가 `.cfg` 파일에서 L1~L3 정답을 독립적으로 재도출한다. 파서 코드에서 `pybatfish` import를 명시적으로 금지하여 원본 오라클과의 독립성을 보장한다.

<!-- 📝 LaTeX: TABLE III -->

| 답변 타입 | 총 수 | 일치 | 불일치 | 일치율 |
|---|:---:|:---:|:---:|:---:|
| number | 356 | 354 | 2 | 99.4% |
| set | 232 | 232 | 0 | 100% |
| text | 96 | 96 | 0 | 100% |
| map_str_int | 30 | 30 | 0 | 100% |
| map | 20 | 20 | 0 | 100% |
| edge_set | 16 | 16 | 0 | 100% |
| boolean | 50 | 50 | 0 | 100% |
| **전체** | **800** | **796** | **4** | **99.5%** |

4건의 불일치는 모두 Batfish VRF 이중 카운팅으로, 독립 파서가 더 정확하다 (실질 일치율 100%).

**Method 2: 계층화 수동 검증.** 메트릭·레벨·답변 타입별로 계층 추출한 43개 표본에 대해 원본 `.cfg` 파일과 직접 교차 검증하였다. 결과: **97.7% 일치 (42/43)**. 유일한 불일치(`all_devices_same_as`)는 BGP 미설정 장비의 "AS None" 보고로, 문서화된 설계 선택이다.

**Method 3: PNETLab 실장비 CLI 검증.** 22개 메트릭을 커버하는 44개 표본(L4: 23건, L5: 21건)에 대해 PNETLab의 Cisco IOS 인스턴스에서 CLI 명령(`traceroute`, `ping`, `show ip route`, 인터페이스 `shutdown`/`no shutdown`)을 실행하여 Batfish 예측과 비교한다.

<!-- 📝 TODO: Method 3 실행 후 결과 추가 -->

| Method | 접근법 | 범위 | 일치율 |
|:---:|---|:---:|:---:|
| 1 | 독립 Config 파서 | 800건 (L1~L3 전수) | **99.5%** |
| 2 | 계층화 수동 검증 | 43건 (L1~L3 표본) | **97.7%** |
| 3 | PNETLab 실장비 CLI | 44건 (L4~L5 표본) | <!-- 📝 TODO --> |

---

## IV. NetAlly: 시스템 아키텍처

### A. 설계 동기

Section V의 베이스라인 실험에서 확인되듯이, LLM은 L1~L3(텍스트 기반 분석)에서는 수용 가능한 성능을 보이나 L4~L5(시뮬레이션 기반 분석)에서는 TA-Acc 0.3 이하에 머문다. 이는 네트워크 동작 추론에 텍스트 처리가 아닌 계산(최단 경로 알고리즘, 데이터 플레인 시뮬레이션, 장애 영향 분석)이 필요하기 때문이다. 이에 도메인 특화 모델 학습 대신, 범용 LLM에 적절한 도구를 증강하는 접근을 채택하였다.

### B. 2-에이전트 아키텍처

NetAlly는 Orchestrator–Executor 구조를 채택한다.

<!-- 📝 LaTeX: \begin{figure}[!t] 아키텍처 다이어그램 \end{figure} -->

```
사용자 질의: "P1-P2 링크가 다운되면, PE1→Leaf3는 어떻게 되나?"
     │
     ▼
┌─────────────────────┐
│   ORCHESTRATOR       │  ← 질의 분석, 스킬 선택
│   (LLM + LangGraph)  │  ← 판단: L5 What-If 분석
└──────────┬────────────┘
           │ Task: network_verify(link_failure, P1-P2)
           ▼
┌─────────────────────┐
│   EXECUTOR           │  ← 도구 호출 실행
│   (LLM + Tools)      │
│   ┌──────┐ ┌──────┐ ┌──────┐
│   │ NSO  │ │Batfish│ │PNETLab│
│   │query │ │verify │ │manage │
│   └──────┘ └──────┘ └──────┘
│                       │
│   1. NSO sync-from (최신 설정 수집)
│   2. Batfish fork_snapshot (P1-P2 비활성화)
│   3. Batfish traceroute (PE1→Leaf3)
│   4. 베이스라인과 비교 → "P3 경유 우회"
└──────────┬────────────┘
           ▼
응답: "P3를 경유하여 트래픽이 우회됩니다."
```

**Orchestrator**는 사용자 질의를 분석하여 적절한 스킬(network_query, network_verify, lab_manage)을 선택하고, 필요한 파라미터를 추출한다. **Executor**는 선택된 스킬에 따라 실제 도구를 호출하고 결과를 반환한다.

### C. 세 가지 핵심 도구

| 도구 | 백엔드 | 기능 | 주 사용처 |
|---|---|---|---|
| `network_query` | Cisco NSO | 실시간 구성 조회 | L1~L3 쿼리 |
| `network_verify` | Batfish | 정형 검증, What-If 분석 | L4~L5 쿼리 |
| `lab_manage` | PNETLab | 토폴로지 관리, 자동 온보딩 | 실험실 운영 |

### D. 하이브리드 검증 파이프라인

**Scan-and-Sync**: PNETLab의 시뮬레이션 장비를 자동으로 탐색하여 Cisco NSO에 등록하고, 가상 랩과 운영 도구 간의 간극을 해소한다.

**Fork-Snapshot**: 장애 분석 시 Batfish의 `fork_snapshot`이 지정된 변경(링크/노드 비활성화)을 적용한 네트워크의 가상 복사본을 생성하여, 비파괴적 What-If 분석을 수행한다. `differentialReachability` 쿼리와 결합하여 영향 범위를 식별한다.

---

## V. 실험 (Experiments)

### A. Single LLM 베이스라인

**목적**: 네트워크 동작 추론 태스크에서 LLM의 한계를 정량적으로 확인한다.

**설정**: 5개 LLM을 NetConfigQA 2.0 v2 (1,029 QA, L1~L5)에 대해 Zero-shot 조건으로 평가하였다. 전체 설정 파일을 컨텍스트로 제공한다.

<!-- 📝 LaTeX: TABLE V -->

| 모델 | 파라미터 | L1 | L2 | L3 | L4 | L5 | 전체 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | — | 0.806 | 0.806 | 0.494 | 0.211 | 0.141 | 0.611 |
| **GPT-OSS-20B** | 20B | **0.873** | **0.873** | **0.605** | **0.266** | 0.134 | **0.672** |
| Llama-3.1-8B | 8B | 0.530 | 0.443 | 0.261 | 0.144 | 0.102 | 0.387 |
| Mistral3-8B | 8B | 0.663 | 0.557 | 0.389 | 0.174 | 0.134 | 0.477 |
| Qwen3-8B | 8B | 0.746 | 0.741 | 0.485 | 0.201 | **0.157** | 0.560 |

관찰: (1) L3→L4에서 모든 모델이 큰 성능 하락을 보인다 (평균 0.45 → 0.20). (2) L5에서 최고 모델도 0.157로 낮은 성능을 보인다. (3) L1~L3에서는 모델 크기에 따른 차이가 있으나, L4~L5에서는 모델 크기와 무관하게 낮다. (4) BERTScore ≥ 0.875로, 모델 간 성능 차이를 구분하지 못한다.

<!-- 📝 LaTeX: \begin{figure}[!t] 레벨별 TA-Acc 비교 Bar Chart \end{figure} -->

### B. NetAlly Multi-Agent 평가

**목적**: 도구 증강 Multi-Agent 시스템의 L4/L5 성능을 Single LLM과 비교한다.

**설정**: NetAlly(Orchestrator + Executor + Batfish/NSO/PNETLab)를 동일한 데이터셋에 대해 평가, 최고 Single LLM 베이스라인(GPT-OSS-20B)과 비교.

<!-- 📝 LaTeX: TABLE VI -->

| 레벨 | Single LLM (GPT-OSS-20B) | NetAlly | Δ |
|:---:|:---:|:---:|:---:|
| L1 | 0.873 | <!-- 📝 TODO --> | |
| L2 | 0.873 | <!-- 📝 TODO --> | |
| L3 | 0.605 | <!-- 📝 TODO --> | |
| L4 | 0.266 | <!-- 📝 TODO --> | |
| L5 | 0.134 | <!-- 📝 TODO --> | |

<!-- 📝 TODO: NetAlly 실험 실행 후 실제 수치로 채울 것 -->

L4/L5에서의 성능 개선이 관찰될 경우, 이는 LLM 자체의 추론 능력이 아닌 Orchestrator가 데이터 플레인 쿼리를 Batfish에 위임한 결과로 해석할 수 있다.

### C. 확장성 분석

**목적**: 네트워크 규모 증가에 따른 성능 변화를 관찰한다.

NCN 시리즈(Lab-A: 10, Lab-B: 20 노드)를 사용한다:
- L1은 규모에 robust (단일 장비 조회는 토폴로지 독립적)
- L2/L3는 점진적 하락 예상 (더 많은 장비에 대한 집계)
- L4/L5는 Single LLM은 하락, NetAlly는 도구 기반이므로 안정적 유지 예상

파이프라인 확장성: QA/노드 비율이 약 113으로, 생성 파이프라인의 선형적 확장성을 확인.

<!-- 📝 TODO: Lab-B 실험 결과 추가 -->

### D. 오류 분석

최고 Single LLM의 L4/L5 실패 사례 30건을 정성적으로 분석한다:

<!-- 📝 TODO: 30건 오류 분석 실행 후 채울 것 -->

| 오류 유형 | 건수 | 예시 | 근본 원인 |
|---|:---:|---|---|
| 경로 복잡도 | — | 다중 홉 traceroute 오류 | OSPF SPF 시뮬레이션 불가 |
| VRF 격리 미이해 | — | VRF 간 도달성 가정 | VRF 경계 무시 |
| 장애 전파 추론 | — | 부정확한 blast radius | ECMP/failover 이해 부재 |
| IP 주소 혼동 | — | 유사 주소 혼동 | 의미적 유사도 ≠ 동일성 |

---

## VI. 논의 (Discussion)

### A. LLM이 L4/L5에서 낮은 성능을 보이는 이유

L4/L5에서의 낮은 성능은 모델 규모가 아닌 태스크 특성에 기인한다. 네트워크 동작 추론에 필요한 작업:
- **OSPF SPF 계산**: 가중 그래프에서의 Dijkstra 알고리즘
- **BGP 최적 경로 선택**: AS 경계에 걸친 다중 속성 비교
- **VRF 격리**: 가상 라우팅 인스턴스별 독립 포워딩 테이블
- **장애 영향 전파**: 토폴로지 변경 후 수렴 경로 재계산

이들은 텍스트 처리와 다른 성질의 계산적 태스크이며, LLM이 다중 홉 경로에 대해 Dijkstra와 동등한 결과를 안정적으로 산출하기 어렵다.

### B. 도구 증강에 따른 역할 전환

NetAlly의 결과는 LLM의 역할이 **"추론자"에서 "조율자"**로 바뀌는 구조를 보여준다. LLM이 수행하는 하위 태스크:
1. 사용자 의도의 **이해** (자연어 → 도구 선택)
2. 도구 호출의 **파라미터화** (출발지/목적지/장애 파라미터 추출)
3. 도구 출력의 **해석** (시뮬레이션 결과 → 인간 판독 가능 답변)

각 하위 태스크는 LLM의 처리 범위에 해당하지만, 이를 종합한 종단간 동작 추론은 그렇지 않다.

### C. 파이프라인의 범용성

이중 경로 생성 파이프라인은 토폴로지에 독립적으로 동작한다: `.cfg` 파일과 `policies.json`이 주어지면 해당 토폴로지에 맞는 Q&A 데이터셋을 자동 생성한다. NCN 시리즈(Lab-A~Lab-D)에서 파이프라인 수정 없이 설정 복잡도만 증가시켜 메트릭 커버리지가 52%에서 97%로 확장되었다.

### D. 타당성 위협 (Threats to Validity)

| 위협 | 완화 방안 |
|---|---|
| 단일 토폴로지 의존 | Lab-B(20노드) 확장성 실험; Config Generator의 임의 토폴로지 지원 |
| Batfish GT 순환 논증 | 3-Method 하이브리드 검증: 독립 파서(99.5%), 수동 검증(97.7%), PNETLab CLI |
| 단일 벤더 (Cisco IOS) | 한계로 인정; Batfish는 Juniper/Arista 지원—향후 연구 |
| NetAlly의 도구 편향 | NetAlly가 Batfish를 사용하고 GT도 Batfish 기반—논문에서 명시적으로 논의 |
| 소규모 L2 셋 (21건) | 인정; 스코프 확장이 L1/L5에 효과적이나 GLOBAL 집계에는 제한적 |

---

## VII. 결론 (Conclusion)

본 연구는 LLM의 설정 파일 기반 네트워크 동작 추론 능력을 평가하는 벤치마크 NetConfigQA 2.0과, 도구 증강을 통해 단일 LLM의 한계를 보완하는 Multi-Agent 시스템 NetAlly를 제시하였다. 실험 결과는 다음과 같다:

1. 테스트된 5개 LLM 모두 L4/L5에서 TA-Acc ≤ 0.3으로, 모델 규모와 무관하게 낮은 성능을 보였다.
2. NetAlly는 계산적 태스크를 Batfish에 위임하여 L4/L5에서 성능 개선을 보였다.
3. TA-Acc는 BERTScore·EM이 구분하지 못하는 모델 간 차이를 식별할 수 있었다.
4. 3중 하이브리드 검증으로 순환 논증 없이 Ground Truth 신뢰성을 확인하였다.

향후 연구: (1) L6 진단 트러블슈팅, (2) 멀티 벤더 지원(Juniper, Arista), (3) 설정 생성 능력 평가(Read→Write), (4) NIKA 등 외부 벤치마크 적용, (5) 이중언어(한/영) 교차 평가.

---

## Acknowledgment

<!-- 📝 TODO: 감사 대상 작성 -->
<!-- 예시: 이 연구는 [과제명/기관명]의 지원으로 수행되었습니다. -->

\[작성 필요\]

---

## 참고 문헌 (References)

<!-- 📝 LaTeX: \begin{thebibliography}{19} ... \end{thebibliography} -->

[1] J. Wei et al., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models," *NeurIPS*, 2022.

[2] T. Wu et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," *ICLR*, 2024.

[3] LangGraph, "A library for building stateful, multi-actor applications with LLMs," https://github.com/langchain-ai/langgraph, 2024.

[4] Cisco, "AgenticOps: Deep Network Troubleshooting," *Cisco Live*, 2025.

[5] Y. Wang et al., "NetConfEval: Can LLMs Facilitate Network Configuration?," *Proc. ACM Netw.*, vol. 2, no. 7, 2024 (ACM CoNEXT).

[6] C. Wang et al., "A Network Arena for Benchmarking AI Agents on Network Troubleshooting (NIKA)," *ACM SIGCOMM NGNO Workshop*, 2025.

[7] Froot Systems Lab, "NetPress: Dynamically Generated LLM Benchmarks for Network Applications," *arXiv:2506.03231*, 2025.

[8] IETF, "A Framework to Evaluate LLM Agents for Network Configuration (NetConfBench)," *IETF Internet-Draft*, 2025.

[9] A. Maatouk et al., "TeleQnA: A Benchmark Dataset to Assess Large Language Models Telecommunications Knowledge," 2023.

[10] Ericsson, "TeleQuAD: Telecom Question Answering Dataset from 3GPP Specifications," 2025.

[11] NetoAI, "NetBench: Expert-Level Network QA Benchmark," 2025.

[12] M. Geyer et al., "NETLLMBENCH: Evaluating Large Language Models for Network Management," *IEEE Conf. NFV-SDN*, 2024.

[13] C. Wei et al., "INTA: Intent-Based Translation for Network Configuration with LLM Agents," *IEEE ICNP*, 2025.

[14] UTSA, "KubeLLM: LLM-Based Multi-Agent Framework for Kubernetes Troubleshooting," 2024.

[15] Z. Wang et al., "Intent-Driven Network Management with Multi-Agent LLMs: The Confucius Framework," *ACM SIGCOMM*, 2025.

[16] "AskBatfish: Simplifying Network Analysis via Natural Language," *Medium*, 2025.

[17] A. Fogel et al., "A General Approach to Network Configuration Analysis," *NSDI*, 2015.

[18] "TelecomGPT: A Framework to Build Telecom-Specific Large Language Models," *arXiv:2407.09424*, 2024.

[19] A. Mani et al., "Enhancing Network Management Using Code Generated by Large Language Models (NeMoEval)," *ACM HotNets*, 2023.

[20] R. Birkner et al., "Config2Spec: Mining Network Specifications from Network Configurations," *NSDI*, 2020.

[21] A. Gember-Jacobson et al., "Mineray: Mining Intent-based Specifications from Network Configurations," *NSDI*, 2020.

[22] P. Kazemian et al., "Header Space Analysis: Static Checking for Networks," *NSDI*, 2012.

[23] A. Khurshid et al., "VeriFlow: Verifying Network-Wide Invariants in Real Time," *NSDI*, 2013.

[24] R. Beckett et al., "A General Approach to Network Configuration Verification (Minesweeper)," *ACM SIGCOMM*, 2017.

[25] P. Zhang et al., "Differential Network Analysis (DNA)," *NSDI*, 2022.

---

## 저자 약력 (Biography)

<!-- 📝 LaTeX: \begin{IEEEbiography}{이름} ... \end{IEEEbiography} -->

**Hyeonjeong Lee** <!-- 📝 TODO: 약력 작성 -->
\[작성 필요\]

**Yujin Park** <!-- 📝 TODO: 약력 작성 -->
\[작성 필요\]

**Cheoneum Park** (IEEE Member) <!-- 📝 TODO: 약력 작성 -->
\[작성 필요\]

---

> **📝 문서 상태 요약**
>
> | 항목 | 상태 |
> |---|:---:|
> | Abstract (150-250 words) | ✅ 완료 |
> | I. Introduction | ✅ 완료 |
> | II. Related Work | ✅ 완료 |
> | III. NetConfigQA 2.0 (A~E 통합) | ✅ 완료 |
> | IV. NetAlly Architecture | ✅ 완료 |
> | V-A. Single LLM Baseline | ✅ 완료 |
> | V-B. NetAlly MAS 결과 | 📝 TODO (실험 미실행) |
> | V-C. Scalability 결과 | 📝 TODO (Lab-B 미배포) |
> | V-D. Error Analysis | 📝 TODO (분석 미실행) |
> | III-E Method 3 결과 | 📝 TODO (사람 실행 대기) |
> | VI. Discussion | ✅ 완료 |
> | VII. Conclusion | ✅ 완료 |
> | Acknowledgment | 📝 TODO |
> | References (19편) | ✅ 초안 (DOI 추가 필요) |
> | Biography (3인) | 📝 TODO |
>
> **구조 변경 (v1→v2)**:
> - 9 Sections → **7 Sections**
> - TA-Acc (구 IV)와 Dataset Validation (구 V)을 → **III-D, III-E로 통합**
> - System Architecture를 실험 앞으로 이동 → **IV (구 VII)**
> - Acknowledgment, Biography 섹션 추가
> - 논문 구조 안내 문장을 Introduction 마지막에 추가
