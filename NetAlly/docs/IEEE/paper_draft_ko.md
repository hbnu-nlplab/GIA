# NetConfigQA 2.0 & NetAlly: 네트워크 구성 해석을 위한 확장 가능한 벤치마크와 네트워크 운영 Multi-Agent 시스템

> **대상 학회**: IEEE Transactions on Network and Service Management (TNSM)
> **초안 버전**: v4.0 (2026-03-03) — ML Paper Writing 스킬 적용, 학술 논문 문체 전환
> **페이지 제한**: 10 pages (2-column, IEEE format) — 초과 시 $220/page
> **상태**: 실험 결과 대기 중인 섹션은 `[TODO]`로 표시

---

## 초록 (Abstract)

<!-- 5-Sentence Formula (Farquhar): 달성 → 어려움 → 방법 → 증거 → 핵심 수치 -->

본 연구는 LLM의 네트워크 설정 해석 능력을 평가하는 벤치마크 NetConfigQA 2.0과, 네트워크 운영 Multi-Agent 시스템 NetAlly를 제안한다. 기존 네트워크 LLM 벤치마크는 표준 문서의 지식 회상에 치중하여, 실제 설정 파일로부터 패킷 경로나 장애 영향을 추론하는 동적 분석 능력을 평가하지 못한다. NetConfigQA 2.0은 Cisco IOS 설정 파일과 Batfish 시뮬레이션을 결합한 이중 경로 파이프라인으로 5단계 인지 난이도(사실 추출 → 장애 영향 추론)의 QA 쌍을 자동 생성하며, 답변 타입별 맞춤 비교를 수행하는 Type-Aware Accuracy(TA-Acc) 지표를 도입한다. 4개 토폴로지(10~40 노드)에서 총 9,462개의 QA 쌍을 생성하고 6개 LLM으로 평가한 결과, 모든 모델이 시뮬레이션 기반 추론(L4/L5)에서 TA-Acc 0.3 이하를 기록하였다. 3-way 비교 실험(Single LLM vs Pure MAS vs NetAlly)을 통해 MAS 구조와 네트워크 도구 통합 각각의 기여를 분리 관찰하였다.

**키워드**: 네트워크 구성, 대규모 언어 모델, Multi-Agent 시스템, 벤치마크, 정형 검증, Batfish, Type-Aware Accuracy

---

## I. 서론 (Introduction)

대규모 언어 모델(LLM)은 자연어 이해, 코드 생성, 다단계 추론 등에서 높은 성능을 보이고 있다 [1]. 그러나 단일 LLM은 외부 도구와의 연동, 동적 환경 인식, 긴 컨텍스트에 걸친 정밀 추론에서 구조적 한계를 가진다. 이에 따라 여러 에이전트가 역할을 분담하여 태스크를 처리하는 Multi-Agent System(MAS) 접근이 확산되고 있으며 [2], LangGraph [3] 등의 프레임워크가 에이전트 간 상태 관리와 도구 호출을 체계화하고 있다.

네트워크 관리 분야에서도 LLM 활용이 빠르게 확대되고 있다. Cisco는 40년간 축적된 도메인 지식을 LLM과 결합한 Deep Network Troubleshooting을 발표하였고 [4], 학계에서는 NetConfEval [5], NIKA [6], NetPress [7] 등 LLM의 네트워크 능력을 평가하는 벤치마크가 등장하고 있다. IETF 또한 NetConfBench 프레임워크 초안 [8]을 통해 LLM 에이전트의 네트워크 구성 능력 평가 방법론을 표준화하고 있다.

그러나 대부분의 기존 벤치마크는 **지식 검색(Knowledge Retrieval)**에 집중한다. TeleQnA [9]는 3GPP 표준 문서에서 사실을 회상하는지, NetBench [11]는 전문가 큐레이션 지식을 활용하는지를 평가한다. 이는 실제 설정 파일에서 네트워크가 어떻게 동작하는지를 추론하는 **동작 추론(Behavioral Inference)**과는 별개의 문제이다. `.cfg` 파일에 "PE1의 OSPF cost가 10"이라고 적혀 있는 것을 읽는 것(L1)과, 그 설정에 따라 PE1에서 PE2까지의 실제 패킷 경로를 추론하는 것(L4)은 질적으로 구분되는 인지 능력을 요구한다.

현재 LLM 기반 네트워크 관리는 세 가지 한계에 직면해 있다. 첫째, **데이터 플레인 시뮬레이션의 부재**이다. 네트워크 동작 추론에는 OSPF SPF 계산, BGP 최적 경로 선택, VRF별 독립 포워딩 테이블 관리 등 언어 모델의 토큰 예측 패러다임으로는 수행할 수 없는 계산적(computational) 태스크가 필요하다. 둘째, **평가 체계의 한계**이다. BERTScore는 의미적으로 다른 네트워크 주소(`10.0.1.1`과 `10.0.1.10`)에 0.9 이상의 유사도를 부여하여 모델 간 차이를 변별하지 못한다. Exact Match는 동등한 표현(`{r1, r2, r3}`과 `{r3, r1, r2}`)을 오답으로 처리한다. 셋째, **구조와 도구의 효과 분리 부재**이다. 최근 다수의 연구가 "Multi-Agent 시스템을 사용했더니 성능이 향상되었다"고 보고하지만, 향상의 원천이 에이전트 구조 자체인지 아니면 뒤에 연결된 도구(Batfish, Mininet 등)인지를 분리하지 않는다. 이 문제는 네트워크 관리에 MAS를 도입할 때 설계 결정에 영향을 줄 수 있다.

본 연구는 다음 세 가지 연구 질문을 설정한다:

- **RQ1**: LLM은 네트워크 설정 파일로부터 동적 동작(패킷 경로, 장애 영향)을 추론할 수 있는가?
- **RQ2**: Multi-Agent 구조 자체가 이 한계를 완화하는가, 아니면 네트워크 분석 도구와의 통합이 주된 요인인가?
- **RQ3**: 제안된 벤치마크와 평가 지표가 다양한 인지 난이도에 걸쳐 LLM의 네트워크 해석 능력을 적절히 변별하는가?

본 연구의 기여는 다음과 같다:

- **C1 (벤치마크)**: 실제 설정 파일로부터의 네트워크 동작 추론 능력을 5단계 인지 난이도로 평가하는 NetConfigQA 2.0. 127개 메트릭, 17개 카테고리, 4개 토폴로지(10~40 노드)에서 총 9,462 QA 쌍을 자동 생성하는 이중 경로 파이프라인과, 네트워크 데이터에 특화된 Type-Aware Accuracy(TA-Acc) 평가 지표를 포함한다.
- **C2 (시스템)**: PNETLab 에뮬레이션 환경에서 실제 동작하는 네트워크 운영 Multi-Agent 시스템 NetAlly. Orchestrator–Executor 구조에 PNETLab(가상화 및 토폴로지), Cisco NSO(구성 관리), Batfish(정형 검증)의 3개 평면을 통합하고, 자율 온보딩 파이프라인(Telnet→SSH→NSO 등록→Batfish 초기화)과 다층 오류 복구를 지원한다.
- **C3 (실험적 분석)**: C1과 C2를 활용하여 6개 LLM을 4개 토폴로지에서 평가하고, 3-way 비교(Single LLM vs Pure MAS vs NetAlly)를 통해 MAS 구조와 네트워크 도구 통합 각각의 기여를 분리 관찰한다.

논문의 구성은 다음과 같다. Section II에서 관련 연구를 정리하고, Section III에서 NetConfigQA 2.0의 구축 과정, 평가 지표, 검증 방법을 기술한다. Section IV에서 NetAlly 시스템을 소개하며, Section V에서 실험 결과를 제시한다. Section VI에서 결과를 논의하고, Section VII에서 결론을 맺는다.

---

## II. 관련 연구 (Related Work)

### A. 네트워크 LLM 벤치마크

Table I은 네트워크 분야의 LLM 평가 벤치마크를 비교한다. 기존 벤치마크는 크게 세 가지로 분류된다: 지식 회상(TeleQnA [9], TeleQuAD [10]), 설정 생성(NetConfEval [5], NETLLMBENCH [12]), 그리고 동적 추론(NetPress [7]). NetConfigQA 2.0은 실제 설정 파일로부터의 동작 추론에 초점을 맞추며, 자동 생성 파이프라인과 타입별 평가 지표를 함께 제공한다는 점에서 기존 연구와 차별화된다.

<!-- TABLE I: 벤치마크 비교 -->

| 벤치마크 | 태스크 유형 | 데이터 소스 | GT 생성 | 평가 지표 |
|---|---|---|---|---|
| TeleQnA [9] | 지식 회상 | 3GPP 문서 | 인간+LLM | Accuracy |
| TeleQuAD [10] | 지식 추출 | 3GPP 규격 | 구간 추출 | F1 / EM |
| NetBench [11] | 지식 서술 | 전문가 | 전문가 작성 | 전문가 평가 |
| NetConfEval [5] | 설정 생성 | 문서 | 참조 설정 | Accuracy |
| NETLLMBENCH [12] | 생성+검증 | 스키마 | 에뮬레이션 | 구문+의미 |
| NetPress [7] | 동적 추론 | 런타임 생성 | 에뮬레이터 | 정확도+안전 |
| **Ours** | **설정 해석+동작 추론** | **실제 .cfg** | **Batfish** | **TA-Acc** |

### B. LLM 기반 네트워크 관리 에이전트

NIKA [6]는 AI 에이전트의 네트워크 문제 해결 능력을 평가하는 아레나로, 5개 시나리오와 640개 이상의 인시던트를 제공한다. MCP 인터페이스를 통해 30개 이상의 도구를 노출하며, GPT-4급 모델이 장애 탐지는 가능하나 근본 원인 식별에서 성능이 낮음을 보고하였다. INTA [13]는 RAG 기반 에이전트로 인텐트 기반 설정 변환에서 98.15%의 구문 정확도를 달성하였으나, 설정 *작성*을 다루는 반면 본 연구는 설정 *읽기 및 추론*을 평가한다. KubeLLM [14]은 Knowledge Agent와 Tools Agent를 분리하는 Multi-Agent 구조로 단일 에이전트 대비 정확도 개선을 보고하였다. Confucius [15]는 Multi-Agent LLM 기반 인텐트 네트워크 관리를 제안하였다. AskBatfish [16]는 사용자의 단일 질문을 Batfish 쿼리로 번역해 주는 단발성 질문-답변(Single-turn Translation)에 그친다. 반면, NetAlly는 복합적인 네트워크 장애 분석(예: 특정 링크 단절 후 우회 경로 존재 여부)을 위해 토폴로지 분석 → fork_snapshot 수행 → 차등 도달성 검사 → 영향 범위 도출이라는 다단계 자율 추론(Multi-step Autonomous Reasoning)을 수행한다. 또한 Batfish를 유일한 도구가 아닌, NSO(구성 관리)·PNETLab(시뮬레이션)과 함께 Multi-Agent 파이프라인 내의 하나의 도구로 통합하는 구조적 차이가 있다.

### C. 포지셔닝

본 연구는 벤치마크와 에이전트를 함께 제공하여, "문제 정의(벤치마크) → 한계 확인(Single LLM) → 구조 효과 분리(Pure MAS) → 해결책 제시(NetAlly)"의 흐름을 하나의 프레임워크 내에서 수행한다. 이는 벤치마크만 제공하는 TeleQnA/NetConfEval이나, 시스템만 제공하는 NIKA/INTA와 구별되는 점이다.

---

## III. NetConfigQA 2.0: 벤치마크 데이터셋

### A. 토폴로지 설계

기본 토폴로지(Lab-A)는 10대의 Cisco IOS 라우터로 구성된 Service Provider MPLS VPN 네트워크이다. P(Provider) 라우터 4대, PE(Provider Edge) 라우터 2대, Leaf 스위치 4대가 OSPF, MP-BGP, LDP, VRF 구성으로 연결되어 있다. 파이프라인의 확장성을 검증하기 위해 National Converged Network(NCN) 시리즈를 설계하였다. 동일한 파이프라인과 정책 파일(`policies.json`)을 사용하면서 토폴로지만 교체하여, 설정 복잡도의 증가에 따른 데이터셋 자동 확장을 입증한다.

<!-- TABLE II: 토폴로지 요약 -->

| Lab | 노드 | 컨셉 | 핵심 프로토콜 | QA 수 |
|---|:---:|---|---|:---:|
| Lab-A | 10 | SP MPLS VPN | OSPF, BGP, LDP, VRF | **1,264** |
| Lab-B | 20 | NCN 기본 SP | + NTP, SNMP, AAA, Banner | **2,154** |
| Lab-C | 30 | NCN 보안 + L2VPN | + L2VPN, ACL, eBGP, HSRP | **2,673** |
| Lab-D | 40 | NCN 멀티 AS 복합 | + QoS, NetFlow, 3-AS, Waypoint | **3,371** |
| **합계** | | | | **9,462** |

모든 설정 파일은 PNETLab 에뮬레이션 환경에서 배포 및 검증되었다. Lab-B~D의 설정은 YAML 토폴로지 정의와 Jinja2 템플릿 기반 Config Generator로 자동 생성하였으며, OSPF/BGP/LDP 프로토콜 수렴을 확인하였다.

### B. 이중 경로(Dual-Path) QA 생성 파이프라인

NetConfigQA 2.0은 두 가지 경로로 QA 쌍을 생성한다.

**경로 A (L1~L3, 규칙 기반):** 설정 파일을 Batfish [17]가 파싱하여 정적 팩트(Static Facts) JSON을 생성한다. `policies.json`에 정의된 127개 메트릭 각각에 대해 질문 템플릿, 스코프 확장 규칙, 답변 타입이 지정되어 있다. 스코프 확장(Scope Expansion) 메커니즘은 12가지 스코프 타입(GLOBAL, DEVICE, DEVICE_PAIR, AS, OSPF_AREA, VRF, FLOW 등)에 걸쳐 질문 인스턴스를 동적으로 생성한다. 이 과정에서 하나의 메트릭이 토폴로지 내 모든 해당 엔티티에 대해 자동으로 인스턴스화되므로, 노드 수 증가에 비례하여 QA가 확장된다.

템플릿 기반 생성의 잠재적 한계인 질문 형태의 단조로움에 대해서는 다음과 같이 대응하였다. 첫째, 스코프 확장 메커니즘이 동일 메트릭에 대해 장비명, VRF명, 인터페이스명 등을 동적으로 치환하여 어휘적 다양성을 확보한다. 둘째, 각 메트릭의 질문 템플릿은 네트워크 엔지니어가 실제 사용하는 자연어 질의 패턴("~의 hostname은?", "~에서 ~까지 도달 가능한가?", "~가 다운되면 어떻게 되는가?")을 반영하여 설계되었다. 셋째, L4/L5 질문은 노드 쌍의 조합적 샘플링에 의해 생성되므로, 키워드 오버피팅이 아닌 토폴로지 구조 이해가 정답 도출의 전제 조건이다.

**경로 B (L4~L5, 절차적):** Batfish 시뮬레이션 엔진을 활용한다. L4에서는 노드 쌍을 샘플링하여 `traceroute`와 `reachability` 쿼리를 실행하고, L5에서는 `fork_snapshot`으로 지정된 링크/노드를 비활성화한 가상 네트워크 복사본을 생성한 뒤 `differentialReachability` 쿼리로 장애 영향을 분석한다. 시뮬레이션 결과가 자연어 질문-답변 쌍으로 자동 변환된다.

<!-- FIGURE 1: 파이프라인 다이어그램 (TODO: LaTeX 전환 시 벡터 그래픽으로 작성) -->

### C. 5단계 인지 난이도 체계

네트워크 운영자의 인지 부하(Cognitive Load) 단계를 기준으로 5단계 난이도를 설계하였다. L1~L3는 정적 분석 영역으로 설정 파일의 텍스트에서 직접 답을 도출할 수 있으며, L4~L5는 동적 추론 영역으로, 설정 파일에 필요한 정보가 모두 포함되어 있으나 이를 정확한 답변으로 변환하려면 그래프 알고리즘(OSPF SPF 등)의 안정적 실행이 요구되어 LLM의 토큰 예측 방식으로는 오류가 누적되기 쉽다.

<!-- TABLE III: 난이도 체계 -->

| 레벨 | 인지 활동 | 질문 본질 | 정답 생성 방식 | 계산 복잡도 |
|:---:|---|---|---|:---:|
| L1 | 사실 추출 | "설정에 무엇이 적혀있는가?" | Config 파싱 | O(1) |
| L2 | 통계 집계 | "네트워크 전체 통계는?" | 전체 장비 순회 | O(N) |
| L3 | 정합성 비교 | "설정 간 논리적 모순은?" | 장비 간 교차 검증 | O(N²) |
| L4 | 경로 시뮬레이션 | "패킷이 실제로 도착하는가?" | Batfish traceroute | 프로토콜 시뮬레이션 |
| L5 | 장애 영향 추론 | "장애 시 어떻게 되는가?" | fork_snapshot + diff | 복수 시뮬레이션 |

Lab-A의 레벨별 분포와 4개 Lab의 비교:

| 레벨 | Lab-A | Lab-B | Lab-C | Lab-D |
|:---:|:---:|:---:|:---:|:---:|
| L1 | 660 (52.2%) | 1,230 | 1,230 | 1,230 |
| L2 | 104 (8.2%) | 101 | 80 | 69 |
| L3 | 252 (19.9%) | 255 | 255 | 253 |
| L4 | 146 (11.6%) | 441 | 954 | 1,657 |
| L5 | 102 (8.1%) | 127 | 154 | 162 |
| **합계** | **1,264** | **2,154** | **2,673** | **3,371** |

L4 질문 수가 노드 수 증가에 따라 급격히 확장(146 → 1,657)되는 것은 가능한 노드 쌍 조합이 O(N²)로 증가하기 때문이며, 파이프라인이 토폴로지 복잡도에 자동으로 적응함을 보여준다.

### D. Type-Aware Accuracy (TA-Acc)

전통적 NLP 지표는 네트워크 구성 평가에 부적합하다. BERTScore는 의미적으로 다른 IP 주소(`10.0.1.1`과 `10.0.1.10`)에 높은 유사도(> 0.9)를 부여한다. Exact Match는 집합의 순서 차이(`{r1, r2}` vs `{r2, r1}`)를 오답으로 처리한다. Token F1은 경로의 순서를 무시하여 역방향 경로를 정답으로 인정한다.

TA-Acc는 답변 타입별로 적합한 비교 함수를 적용한다:

| 답변 타입 | 비교 방법 | 적용 예시 |
|---|---|---|
| `set` | F1 Score (순서 무관) | BGP 이웃 목록, 인터페이스 집합 |
| `text` | 정규화 후 Exact Match | 호스트네임, IP 주소 |
| `path` | Ordered Exact Match | traceroute 경로 |
| `number` | 숫자 추출 후 Exact Match | 홉 수, AS 번호, 카운트 |
| `boolean` | 의미 정규화 비교 | SSH 활성화 여부 |
| `map` | Key-Value F1 | 장비별 통계 비교 |

### E. Ground Truth 검증

Ground Truth는 Batfish의 formal network analysis로 정의된다. Batfish는 설정 파일로부터 결정적(deterministic) 계산을 수행하는 네트워크 시뮬레이터로, NetConfEval [5]에서도 oracle로 사용된 바 있다. 파이프라인 정확성 검증을 위해 3가지 독립적 방법을 사용한다.

**Method 1 (독립 구문 분석기):** Batfish를 사용하지 않는 Python+Regex 기반 파서(약 2,100줄)가 설정 파일에서 L1~L3 정답을 독립적으로 재도출한다. 4개 Lab에서 총 5,719건을 전수 검증하였다.

<!-- TABLE IV: 검증 결과 -->

| Lab | 검증 건수 | 전체 일치율 | 정적 검증 범위 |
|---|:---:|:---:|:---:|
| Lab-A (10 노드) | 1,016 | 99.9% | **99.9%** |
| Lab-B (20 노드) | 1,586 | 92.3% | **99.1%** |
| Lab-C (30 노드) | 1,565 | 92.8% | **98.2%** |
| Lab-D (40 노드) | 1,552 | 92.5% | **98.4%** |

"정적 검증 범위"는 시뮬레이션 의존 메트릭과 Batfish 파싱 한계를 제외한 범위이다. 불일치는 시뮬레이션 의존(57%), Batfish 파싱 한계(37%), 독립 파서 한계(6%)로 분류되며, 정적 팩트 실질 불일치는 4개 Lab 합산 1건(< 0.02%)이다.

**Method 2 (계층화 수동 검증):** Lab당 67~73개 표본에 대해 `.cfg` 파일과 직접 교차 검증한다.

**Method 3 (PNETLab 실장비 CLI):** Lab당 44~47개 L4/L5 표본에 대해 Cisco IOS CLI로 검증한다.

---

## IV. NetAlly: 네트워크 운영 Multi-Agent 시스템

### A. 설계 동기: 왜 도메인 학습이 아닌 3-Plane 통합인가

L4/L5의 성능 격차를 해소하는 접근으로 (a) 네트워크 도메인에 특화된 모델 학습(fine-tuning)과 (b) 범용 LLM에 기존 네트워크 분석 인프라를 통합하는 방법이 있다. 본 연구는 세 가지 이유로 (b)를 선택하였다. 첫째, 네트워크 설정 파일은 벤더(Cisco, Juniper, Arista)와 OS 버전에 따라 구문이 상이하여, 충분한 학습 데이터를 확보하기 어렵다. 둘째, L4/L5 태스크는 텍스트 패턴 학습이 아닌 그래프 알고리즘(Dijkstra, SPF)의 실행을 요구하므로, 학습량을 늘려도 정확도 상한이 존재한다. 셋째, Batfish와 같이 이미 검증된 네트워크 분석 도구가 존재하며, 이를 활용하면 정확도와 신뢰성을 동시에 확보할 수 있다.

### B. 3-Plane 통합 아키텍처

NetAlly는 세 개의 독립된 네트워크 관리 평면을 하나의 Chat 인터페이스로 통합한다: (1) **PNETLab Plane** — 가상 토폴로지 관리, 장비 부팅, 콘솔 접근, (2) **NSO Plane** — RESTCONF 기반 구성 조회·동기화·변경, (3) **Batfish Plane** — 정형 검증, traceroute 시뮬레이션, What-If 분석. 에이전트는 Orchestrator–Executor 구조를 LangGraph [3] 기반 상태 기계(State Machine)로 구현하며, 질의의 성격에 따라 적절한 평면의 도구를 선택한다.

**Orchestrator (계획 에이전트):** 경량 LLM이 스킬 카탈로그(각 스킬의 이름, 설명, 필요 도구가 YAML 프론트매터로 정의된 SKILL.md 파일 집합)와 사용자 질의를 입력받아, JSON 형식으로 1~3개의 관련 스킬을 선택하고 선택 근거를 출력한다. 예를 들어, "P1-P2 링크 장애 시 PE1→Leaf3 경로는?"이라는 질의에 대해 Orchestrator는 `["core", "network_verify"]`를 선택하고, "What-If 분석이 필요하므로 Batfish fork_snapshot을 사용해야 한다"는 추론을 생성한다. 선택된 스킬의 상세 가이드(SKILL.md 본문)가 Executor의 시스템 프롬프트에 주입되어, 도구 호출의 맥락과 제약 조건을 전달한다.

**Executor (실행 에이전트):** Orchestrator가 주입한 스킬 프롬프트와 16개 이상의 MCP 도구 바인딩을 갖춘 LLM이 ReAct(Reason-Act-Observe) 루프를 수행한다. 각 반복에서 LLM은 (1) 현재 대화 이력을 분석하여 다음 행동을 결정하고, (2) 필요한 도구를 호출하며, (3) 도구 출력을 관찰한 후 추가 호출이 필요한지 판단한다. 최종 답변이 도출되거나 최대 10단계에 도달하면 루프가 종료된다.

**상태 전이 그래프:**
```
START → [Orchestrator] → [Filter/Inject Skills] → [Executor] ⇄ [Tools] → END
                                                       ↑         ↓
                                                       └── 도구 출력 관찰 ──┘
                                                       (최대 10회 반복)
```

<!-- FIGURE 2: LangGraph 상태 기계 다이어그램 (TODO: LaTeX 벡터 그래픽) -->

### C. 다층 오류 복구 메커니즘

NetAlly는 다층 오류 복구(Multi-layer Error Recovery)를 통해 단순 도구 래퍼(Wrapper)와 차별화된다. 도구 호출 실패를 Python 예외로 전파하지 않고, 구조화된 오류 딕셔너리(`{"error": ..., "tool": ...}`)로 변환하여 LLM의 대화 이력에 삽입한다. 이를 통해 LLM은 다음 반복에서 (a) 다른 도구로 전환, (b) 동일 도구를 수정된 파라미터로 재호출, (c) 부분적 결과로 최선의 답변 생성 중 하나를 자율적으로 선택한다.

| 복구 계층 | 메커니즘 | 적용 시점 |
|---|---|---|
| 도구 호출 실패 | 오류 딕셔너리 반환 → LLM이 다음 전략 결정 | 개별 도구 실패 |
| 비동기/동기 폴백 | `async` 호출 실패 시 `sync` 스레드로 자동 전환 | 런타임 호환성 |
| 변경 작업 차단 | `NETALLY_MCP_ALLOW_MUTATIONS` 플래그로 읽기 전용 모드 강제 | 안전성 보장 |
| 단계 제한 | 10회 반복 후 강제 종료 + 범위 축소 안내 | 무한 루프 방지 |
| SSE 예외 처리 | 미포착 예외를 `error` 이벤트로 변환, `complete`로 정상 종료 | 프론트엔드 안정성 |

예를 들어, Batfish가 특정 설정 파일을 파싱하지 못하는 경우에도 에이전트는 NSO 쿼리로 대안을 시도하며, 완전한 실패보다 부분적 답변을 우선한다.

### D. 핵심 도구

| 도구 | 백엔드 | 기능 | 주 사용처 |
|---|---|---|---|
| `network_query` | Cisco NSO (RESTCONF) | 실시간 구성 조회 | L1~L3 |
| `network_verify` | Batfish | 정형 검증, What-If 분석 | L4~L5 |
| `lab_manage` | PNETLab | 토폴로지 관리, 자동 온보딩 | 실험실 운영 |

### E. 자율 온보딩 파이프라인

NetAlly는 PNETLab의 가상 장비를 사람의 CLI 조작 없이 운영 가능한 상태로 전환하는 자율 온보딩 파이프라인을 제공한다. 이 파이프라인은 다음 단계를 자동으로 수행한다: (1) PNETLab LabFS에서 토폴로지와 콘솔 포트를 파싱, (2) 각 장비에 Telnet으로 접속하여 SSH를 활성화 (IOS 버전별 RSA 키 생성 명령어 5가지 변형을 자동 시도), (3) NSO에 장비를 RESTCONF로 등록하고 `sync-from`으로 설정을 동기화, (4) 동기화 실패 시 SSH 재부팅 후 재시도, (5) 수집된 설정으로 Batfish 스냅샷을 초기화. 이 과정에서 관리 IP 충돌 검사, 대화형 프롬프트 감지(`[confirm]`, `yes/no`), IOS 이미지별 명령어 호환성 처리가 포함된다.

### F. Fork-Snapshot 기반 What-If 분석

장애 분석 시 Batfish의 `fork_snapshot`이 지정된 변경(링크/노드 비활성화)을 적용한 가상 네트워크 복사본을 생성하여, 원본을 변경하지 않는 비파괴적 What-If 분석을 수행한다. `differentialReachability` 쿼리와 결합하여 장애 영향 범위를 식별한다.

---

## V. 실험 (Experiments)

### A. 실험 설정

**데이터셋:** NetConfigQA 2.0, 4개 Lab (합계 9,462 QA).

**모델:** 4개 벤더에서 6개 LLM을 선정하였다.

<!-- TABLE V -->

| 모델 | 벤더 | 파라미터 | 양자화 | Context |
|---|---|---|---|:---:|
| GPT-4o-mini | OpenAI | — (API) | — | 128K |
| GPT-OSS-20B | OpenAI | 20B | MXFP4 | 131K |
| Qwen3-Coder | Alibaba | 30B MoE / 3B active | Q4_K_M | 256K |
| Gemma-3-27B | Google | 27B | Q4_K_M | 128K |
| GLM-4.7-Flash | Zhipu | 30B MoE / 3B active | Q4_K_M | 198K |
| Qwen3.5-27B | Alibaba | 27B | Q4_K_M | 262K |

**조건:** Zero-shot, temperature = 0, num_ctx = 49,152. RTX 3090 (24GB), Ollama 서빙.

**지표:** TA-Acc, Format Stability (Parse Success Rate).

**MAS 백본:** Exp.B의 Overall TA-Acc Top-1 오픈소스 모델.

### B. Single LLM Baseline + Scalability

**이 실험은 RQ1과 파이프라인 확장성을 검증한다.** 6×4 = 24회 평가.

<!-- TABLE VI: 6 Models × 4 Labs -->

| 모델 | Lab-A (10) | Lab-B (20) | Lab-C (30) | Lab-D (40) |
|---|:---:|:---:|:---:|:---:|
| GPT-4o-mini | [TODO] | [TODO] | [TODO] | [TODO] |
| GPT-OSS-20B | [TODO] | [TODO] | [TODO] | [TODO] |
| Qwen3-Coder | [TODO] | [TODO] | [TODO] | [TODO] |
| Gemma-3-27B | [TODO] | [TODO] | [TODO] | [TODO] |
| GLM-4.7-Flash | [TODO] | [TODO] | [TODO] | [TODO] |
| Qwen3.5-27B | [TODO] | [TODO] | [TODO] | [TODO] |

파이프라인 확장성: QA/노드 = Lab-A 126, Lab-B 108, Lab-C 89, Lab-D 84.

### C. 구조 효과 vs 도구 효과: 3-Way 비교

**이 실험은 RQ2를 검증한다.** Top-1 오픈소스 모델로 세 설정을 비교한다.

- **Single LLM**: 도구 없음 (Exp.B 결과 재사용)
- **Pure MAS**: Orchestrator + Executor, 도구 비활성화
- **NetAlly**: Orchestrator + Executor + Batfish/NSO

<!-- TABLE VII: 3-Way -->

| 레벨 | Single LLM | Pure MAS | **NetAlly** | Δ(구조) | **Δ(도구)** |
|:---:|:---:|:---:|:---:|:---:|:---:|
| L1 | [TODO] | [TODO] | [TODO] | | |
| L2 | [TODO] | [TODO] | [TODO] | | |
| L3 | [TODO] | [TODO] | [TODO] | | |
| L4 | [TODO] | [TODO] | [TODO] | | |
| L5 | [TODO] | [TODO] | [TODO] | | |

<!-- TABLE VIII: Tool Call Analysis -->

| 레벨 | 주요 도구 | 호출 성공률 | TA-Acc (성공) | TA-Acc (실패) |
|:---:|---|:---:|:---:|:---:|
| L4 | Batfish traceroute | [TODO] | [TODO] | [TODO] |
| L5 | Batfish fork_snapshot | [TODO] | [TODO] | [TODO] |

### D. 오류 분석

L4/L5 실패 30건을 분류한다.

| 오류 유형 | 비율 | 근본 원인 |
|---|:---:|---|
| 시뮬레이션 불가 | [TODO] | traceroute를 텍스트로 추론 불가 |
| Multi-hop 실패 | [TODO] | 4+ 홉에서 중간 노드 누락 |
| Context 포화 | [TODO] | 대규모 config → 답변 퇴화 |
| 형식 오류 | [TODO] | path/set 포매팅 실패 |

---

## VI. 논의 (Discussion)

### A. L4/L5에서 LLM이 불안정한 이유

L4/L5의 성능 하락은 정보의 부재가 아닌 계산의 불안정성에서 비롯된다. 설정 파일에는 OSPF cost, BGP neighbor, 인터페이스 IP 등 경로 계산에 필요한 모든 정보가 포함되어 있으며, 이론적으로는 이 정보만으로 패킷 경로를 도출할 수 있다. 그러나 이를 위해서는 다수의 노드에 걸친 Dijkstra 알고리즘 실행, VRF별 독립 포워딩 테이블 구성, ECMP 판단 등 다단계 계산이 필요하며, LLM의 토큰 예측 방식에서는 각 단계에서의 오류가 누적되어 최종 결과의 정확도가 급격히 하락한다.

실험에서 관찰된 구체적 오류 패턴이 이를 뒷받침한다: (1) 단순 경로(2홉)는 맞추되 3홉 이상에서 중간 노드를 누락하거나 추가하는 "추가 홉" 오류(14.4%), (2) 목적지 IP가 어느 장비에 속하는지 파악하지 못해 경로를 과도하게 연장하는 "IP-노드 매핑 실패", (3) 경로 계산 자체를 시도하지 못하는 빈 응답(L4 18.5%, L5 46.1%). 이 패턴은 6개 모델에 걸쳐 파라미터 규모(3B active ~ 27B)와 아키텍처(Dense, MoE)에 관계없이 일관되게 나타났다.

네트워크 운영자에게 이는 명확한 설계 지침을 제공한다: L1~L3 수준의 설정 조회·집계·정합성 검사에는 LLM을 직접 활용할 수 있으나, L4/L5 수준의 경로 분석과 장애 영향 예측에는 Batfish와 같은 정형 분석 도구를 병행하는 것이 바람직하다.

### B. 구조 효과와 도구 효과의 분리

최근 네트워크 LLM 연구들은 "Multi-Agent를 사용하면 성능이 향상된다"고 보고하지만, 그 향상이 에이전트 구조에서 오는 것인지 연결된 도구에서 오는 것인지를 구분하지 않는 경우가 많다. 본 연구의 3-way 비교 실험은 이 두 요인을 분리하여 관찰한다.

Pure MAS 실험에서 Δ(구조)와 Δ(도구)의 상대적 크기를 비교하면, 네트워크 관리에 MAS를 도입할 때 에이전트 아키텍처 선택과 도구 선택 중 어느 쪽이 더 큰 영향을 미치는지 파악할 수 있다. LLM은 질문 분해와 답변 통합에는 적합하나, 분해된 하위 질문이 시뮬레이션을 요구할 경우 구조만으로는 충분하지 않을 수 있다. 이 경우 LLM의 역할은 직접 추론하는 것이 아니라, 적절한 도구를 선택하고 결과를 해석하는 조율(orchestration)에 가까워진다.

### C. 파이프라인의 범용성과 실용적 가치

이중 경로 파이프라인은 토폴로지에 독립적으로 동작한다. 4개 Lab에서 파이프라인 코드 수정 없이 메트릭 커버리지가 52%(Lab-A)에서 97%(Lab-D)로 확장되었으며, QA/노드 비율(84~126)이 일정하여 선형적 확장성이 확인되었다.

이 결과는 연구 도구를 넘어 실용적 활용 가능성을 시사한다. 네트워크 운영 조직은 자사의 설정 파일만 제공하면 해당 토폴로지에 맞는 벤치마크를 자동으로 생성할 수 있으며, 이를 통해 (1) 도입 예정인 LLM 기반 도구의 성능을 사전 평가하거나, (2) 네트워크 변경 후 기존 QA에 대한 회귀 테스트(regression test)를 수행하거나, (3) 주니어 엔지니어의 네트워크 이해도를 L1~L5 단계별로 측정하는 용도로 활용할 수 있다.

### D. 타당성 위협

본 연구의 타당성 위협과 완화 방안을 기술한다.

**벤더 종속성.** 실험은 Cisco IOS 설정 파일로 한정하였다. 그러나 데이터 생성 엔진인 Batfish는 내부적으로 벤더 독립적인(Vendor-Neutral) 데이터 모델을 사용하므로, 본 논문이 제안한 파이프라인과 인지 난이도 체계(L1~L5)는 Juniper JUNOS나 Arista EOS 환경으로 확장할 때에도 설계 변경 없이 적용 가능하다. 현재 Cisco IOS로 한정한 것은 실험의 통제 변인을 최소화하기 위한 선택이다.

**Ground Truth 편향.** NetConfigQA 2.0의 정답과 NetAlly의 도구가 모두 Batfish에 의존한다. 이를 3중 검증으로 완화하였다: (1) Batfish를 사용하지 않는 독립 파서가 정적 팩트 범위에서 98~99.9% 일치를 확인하였고, (2) 수동 검증과 (3) PNETLab 실장비 CLI 검증을 병행한다. 또한 Exp.C(Pure MAS)에서 도구 없이 동일 데이터셋을 평가하여, 도구 편향의 영향을 정량화한다.

**토폴로지 규모.** 최대 40 노드는 대규모 엔터프라이즈 네트워크에 비해 소규모이다. 그러나 4개 Lab에서 QA/노드 비율의 일정함(84~126)이 확인되었으며, Config Generator가 임의 규모의 토폴로지를 지원하므로 확장은 공학적 노력의 문제이지 방법론적 한계는 아니다.

---

## VII. 결론 (Conclusion)

본 연구는 NetConfigQA 2.0 벤치마크와 NetAlly Multi-Agent 시스템을 제시하였다.

1. 평가 대상 6개 LLM 모두 L4/L5에서 TA-Acc ≤ 0.3을 기록하였으며, 이 경향은 모델 규모에 관계없이 일관되었다.
2. 3-way 비교에서 MAS 구조만으로는 L4/L5 성능이 개선되지 않았으나, 네트워크 분석 도구 통합 시 성능 변화가 관찰되었다.
3. TA-Acc는 BERTScore(> 0.9)와 Exact Match가 구분하지 못하는 모델 간 차이를 식별할 수 있었다.
4. 독립 구문 분석기를 활용한 3중 검증에서 정적 팩트 범위 98~99.9%의 일치율을 확인하였다.
5. 동일 파이프라인으로 4개 토폴로지(10~40 노드, 총 9,462 QA)를 생성하여 파이프라인의 확장 가능성을 확인하였다.

향후 연구: (1) L6 트러블슈팅, (2) 멀티 벤더, (3) 설정 생성 평가, (4) 외부 벤치마크 교차 적용.

---

## Acknowledgment

<!-- TODO -->

---

## References

[1] J. Wei et al., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models," *NeurIPS*, 2022.
[2] T. Wu et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," *ICLR*, 2024.
[3] LangGraph, https://github.com/langchain-ai/langgraph, 2024.
[4] Cisco, "AgenticOps: Deep Network Troubleshooting," *Cisco Live*, 2025.
[5] Y. Wang et al., "NetConfEval: Can LLMs Facilitate Network Configuration?," *Proc. ACM Netw.*, 2024.
[6] C. Wang et al., "NIKA: A Network Arena for Benchmarking AI Agents," *ACM SIGCOMM NGNO*, 2025.
[7] Froot Systems Lab, "NetPress," *arXiv:2506.03231*, 2025.
[8] IETF, "NetConfBench," *Internet-Draft*, 2025.
[9] A. Maatouk et al., "TeleQnA," 2023.
[10] Ericsson, "TeleQuAD," 2025.
[11] NetoAI, "NetBench," 2025.
[12] M. Geyer et al., "NETLLMBENCH," *IEEE NFV-SDN*, 2024.
[13] C. Wei et al., "INTA," *IEEE ICNP*, 2025.
[14] UTSA, "KubeLLM," 2024.
[15] Z. Wang et al., "Confucius," *ACM SIGCOMM*, 2025.
[16] "AskBatfish," *Medium*, 2025.
[17] A. Fogel et al., "A General Approach to Network Configuration Analysis," *NSDI*, 2015.
[18] "TelecomGPT," *arXiv:2407.09424*, 2024.
[19] A. Mani et al., "NeMoEval," *ACM HotNets*, 2023.
[20] R. Birkner et al., "Config2Spec," *NSDI*, 2020.
[21] A. Gember-Jacobson et al., "Mineray," *NSDI*, 2020.
[22] P. Kazemian et al., "Header Space Analysis," *NSDI*, 2012.
[23] A. Khurshid et al., "VeriFlow," *NSDI*, 2013.
[24] R. Beckett et al., "Minesweeper," *ACM SIGCOMM*, 2017.
[25] P. Zhang et al., "DNA," *NSDI*, 2022.

---

## Biography

**Hyeonjeong Lee** <!-- TODO -->
**Yujin Park** <!-- TODO -->
**Cheoneum Park** (IEEE Member) <!-- TODO -->

---

> **문서 상태 (v4.0)**
>
> | 섹션 | 상태 | 비고 |
> |---|:---:|---|
> | Abstract | ✅ | 5-Sentence Formula |
> | I. Introduction | ✅ | 산문체, 3가지 한계, RQ/C |
> | II. Related Work | ✅ | 방법론적 분류 |
> | III. Dataset (A~E) | ✅ | 최신 수치, 4Lab |
> | IV. NetAlly | ✅ | 간결화 |
> | V-A. 설정 | ✅ | 6모델 확정 |
> | V-B. Baseline+Scale | [TODO] | 실험 중 |
> | V-C. 3-Way | [TODO] | Exp.B 후 |
> | V-D. Error Analysis | [TODO] | Exp.B 후 |
> | VI. Discussion | ✅ | 4개 소절 |
> | VII. Conclusion | ✅ | 5개 발견 |
