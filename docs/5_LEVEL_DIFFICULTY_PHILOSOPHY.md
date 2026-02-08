# 🧠 NetConfigQA 5단계 난이도 체계의 철학과 설계 원칙

> **"네트워크 운영자가 겪는 인지적 부하(Cognitive Load)의 단계"**를 기준으로 5단계 난이도를 설계했습니다.  
> 단순한 정보 조회(Lookup)에서 시작하여, 복잡한 인과 관계 추론(Reasoning) 및 가상 시나리오 분석(Counterfactual)으로 나아가는 체계입니다.

---

## 1. 난이도 설계의 핵심 철학 (The Philosophy)

우리의 5단계 시스템은 **"데이터(Data) → 정보(Information) → 지식(Knowledge) → 통찰(Insight)"**로 발전하는 DIKW 피라미드 모델을 네트워크 운영 컨텍스트에 맞게 재해석했습니다.

| 레벨 | 철학적 키워드 (Keyword) | 인지적 활동 (Cognitive Activity) | 질문의 본질 (Nature of Question) |
| :-- | :--- | :--- | :--- |
| **L1** | **Fact (사실)** | **Extraction (추출)** | "장비에 **있는 그대로** 무엇이 적혀있는가?" |
| **L2** | **Statistics (통계)** | **Aggregation (집계)** | "전체적인 **현황(Overview)**은 어떠한가?" |
| **L3** | **Consistency (정합성)** | **Comparison (비교)** | "설계 원칙대로 **논리적 모순**이 없는가?" |
| **L4** | **Behavior (동작)** | **Simulation (시뮬레이션)** | "실제로 패킷을 보내면 **어떤 일이 벌어지는가**?" |
| **L5** | **Resilience (탄력성)** | **Counterfactual (반사실적 사고)** | "만약(What-if) 상황이 바뀌면 **어떻게 될 것인가**?" |

---

## 2. 레벨별 상세 컨셉 (Detailed Concepts)

### 🌱 L1: 단일 장비 설정 조회 (Single Device Fact Retrieval)
*   **Concept**: **"Reading the Manual"** (매뉴얼 읽기)
*   **Philosophy**: 네트워크의 가장 기본 단위인 '장비(Atom)' 하나의 상태를 정확히 파악하는 능력입니다.
*   **인지적 부하**: 낮음 (O(1) - 파일 1개만 보면 됨)
*   **질문 예시**: "R1의 OSPF Process ID는?"
*   **평가 요소**: 텍스트 파싱 능력, 기본 키워드 인식.

### 🌿 L2: 네트워크 전역 현황 집계 (Network-Wide Visibility)
*   **Concept**: **"Taking Inventory"** (재고 조사)
*   **Philosophy**: 개별 장비(Tree)가 아닌 숲(Forest)을 보는 능력입니다. 파편화된 정보를 모아 의미 있는 통계로 변환합니다.
*   **인지적 부하**: 중간 (O(N) - 전체를 훑어야 함)
*   **질문 예시**: "SSH가 설정되지 않은 장비는 총 몇 대인가?"
*   **평가 요소**: 정보 수집, 필터링, 집계(Count, List) 능력.

### 🌲 L3: 논리적 정합성 검증 (Logical Consistency Check)
*   **Concept**: **"Debug by Comparison"** (비교를 통한 디버깅)
*   **Philosophy**: "A와 B는 같아야 한다"는 설계 의도(Intent)와 실제 설정 간의 괴리를 찾아내는 **분석적 사고**입니다. 단순 조회가 아닌 '관계'를 봅니다.
*   **인지적 부하**: 중간~높음 (O(N^2) - 장비 간 상관관계 파악)
*   **질문 예시**: "iBGP Full-Mesh가 깨진 구간이 있는가?", "VRF 이름은 같은데 RT 값이 다른가?"
*   **평가 요소**: 패턴 매칭, 이상 탐지(Anomaly Detection), 규범적 판단.

### 🌪️ L4: 네트워크 동적 행위 예측 (Dynamic Behavior Prediction)
*   **Concept**: **"Mental Simulation"** (뇌내 시뮬레이션)
*   **Philosophy**: 정적인 설정(Static Config) 텍스트만 보고, 동적인 패킷의 흐름(Dynamic Flow)을 머릿속으로 그려내는 능력입니다. **Control Plane(설정)을 보고 Data Plane(동작)을 예측**하는 고차원 추론입니다.
*   **인지적 부하**: 높음 (프로토콜 로직 시뮬레이션 필요)
*   **질문 예시**: "A에서 B로 가는 패킷이 방화벽에 차단되는가? 아니면 루프에 빠지는가?"
*   **참조 이론**: **HSA (Header Space Analysis)**, **VeriFlow**
*   **평가 요소**: 라우팅 프로토콜 이해, ACL 해석, 포워딩 로직 추론.

### 🔮 L5: 인과 관계 및 가상 시나리오 추론 (Causal & Counterfactual Reasoning)
*   **Concept**: **"Parallel Universe"** (평행 우주 탐험)
*   **Philosophy**: 현재 존재하지 않는 상황(장애, 변경)을 가정하고, 그 여파를 예측하는 **가장 고차원의 지능**입니다. 단순한 시뮬레이션을 넘어, **"Why?"(원인)와 "What If?"(가정)**를 다룹니다.
*   **인지적 부하**: 매우 높음 (복수의 시뮬레이션 결과를 비교 분석)
*   **질문 예시**: "Core 라우터가 죽으면 어떤 서비스들이 단절되는가? (Blast Radius)", "이 링크 장애가 전체망 분단(Partition)을 일으키는가?"
*   **참조 이론**: **Minesweeper (Fault Tolerance)**, **DNA (Differential Network Analysis)**
*   **평가 요소**: 인과 관계 추론, 장애 영향도 평가(Risk Assessment), 근본 원인 분석(RCA).

---

## 3. 학술적 매핑 (Academic Alignment)

우리의 난이도 체계는 **NSDI/SIGCOMM**의 주요 논문들이 다루는 검증 영역과 정확히 일치합니다.

| Level | 관련 논문 (Key Paper) | 핵심 검증 속성 (Invariant) |
| :--- | :--- | :--- |
| **L1/L2** | **Batfish (NSDI'15)** | Configuration Analysis (Parse & Query) |
| **L3** | **Mineray (NSDI'20)** | Intent Discovery & Consistency |
| **L4** | **HSA (NSDI'12), VeriFlow (NSDI'13)** | Reachability, Loop-Freedom, Isolation |
| **L5** | **Minesweeper (SIGCOMM'17), DNA (NSDI'22)** | Fault Tolerance, Differential Reachability |

---

## 4. 발표용 한 줄 요약 (Elevator Pitch)

> "NetConfigQA의 질문들은 단순히 텍스트를 찾는 **검색(Retrieval)** 능력을 넘어, 네트워크의 동작을 **시뮬레이션(Simulation)**하고, 보이지 않는 위험을 **추론(Reasoning)**하는 AI의 '엔지니어링 지능'을 평가하도록 설계되었습니다."

