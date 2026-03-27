🚀 NetAgent: 5-Stage Multi-Agent System for Network Operations
NetAgent는 네트워크 환경에서 발생하는 설정 오류와 장애를 진단하기 위해 설계된 **5단계 다중 에이전트 프레임워크(5-Stage Multi-Agent Framework)**입니다.

기존 LLM이 방대한 네트워크 설정을 한 번에 처리할 때 발생하는 '환각(Hallucination)'과 '문맥 누수(Context Leakage)'를 원천 차단하기 위해, 단일 모델(Single Model) 기반의 엄격한 패시지(Passage) 생성 파이프라인과 Debate 2 (찬반 토론) 메커니즘을 결합하여 인간 엔지니어 수준의 신뢰성을 확보합니다.

👥 Core Agent Roles (5 에이전트 역할 구성)
NetAgent는 명확히 분리된 5개의 에이전트로 구성됩니다. 실험의 통제와 일관성을 위해 전체 시스템은 단일 LLM 백본(All-Local 또는 All-API) 위에서 구동되며, 각 에이전트는 독립된 시스템 프롬프트를 통해 자신의 역할만을 수행합니다.

1️⃣ Agent 1: Information Extractor (정보 추출 에이전트)
시스템의 첫 관문으로, 사용자의 질의를 분석하여 원시 데이터(Raw Data)를 수집합니다.

Our Dataset (동적 환경): MCP(Model Context Protocol) 툴을 능동적으로 호출하여 필요한 장비의 전체 설정이나 상태 정보를 Fetch 합니다.

Other Benchmarks (정적 환경): 툴 사용 없이, 데이터셋이 제공하는 전체 긴 Context 문서를 읽어들입니다.

2️⃣ Agent 2: Passage Generator (패시지 생성 에이전트)
가장 중요한 환각 방어선입니다. Agent 1이 수집한 방대한 원시 데이터에서 노이즈를 제거하고, 정답 도출에 결정적인 **10~20줄의 고순도 패시지(Passage)**만을 엄격하게 추출/생성합니다.

3️⃣ Agent 3: Answer Deriver (초기 정답 도출 에이전트)
Agent 2가 전달한 '정제된 패시지'만을 기반으로 네트워크 상태를 분석하여 논리적인 초기 결론(Candidate Answer)을 도출합니다. 전체 문맥을 보지 않기 때문에 문맥 누수(Context Leakage)가 발생하지 않습니다.

4️⃣ Agent 4: Proponent (Debate 2 - 찬성 측 에이전트)
이후 진행되는 Debate 2 토론 단계에서 찬성 및 방어(Advocate) 역할을 맡습니다. Agent 3이 도출한 초기 정답의 논리를 강화하고, 상대측의 공격에 맞서 정답의 타당성을 증명합니다.

5️⃣ Agent 5: Critic (Debate 2 - 비판 측 에이전트)
시스템 내에서 의도적인 회의론자(Skeptic) 역할을 수행합니다. Agent 3의 정답과 Agent 4의 논리에 네트워크 프로토콜 위배(예: BGP AS 불일치 등)나 논리적 비약이 없는지 비판(Critique)하고 반박 논거를 제시합니다.

🔄 Multi-Agent Workflow: The "Debate 2" Process
NetAgent의 문제 해결 과정은 단방향 출력이 아닌, 정보 정제부터 치열한 찬반 토론으로 이어지는 5단계 파이프라인을 따릅니다.

📍 Step 1: Raw Information Extraction (원시 정보 추출)
Agent 1이 질의를 분석하고 환경(동적/정적)에 맞춰 원시 네트워크 데이터를 수집하여 전달합니다.

📍 Step 2: Strict Context Scoping (패시지 생성)
Agent 2가 원시 데이터를 필터링하여 오직 답변에 필요한 '핵심 Passage'만 생성합니다. 다른 장비의 무관한 설정은 이 단계에서 모두 버려집니다.

📍 Step 3: Initial Answer Generation (초기 정답 생성)
Agent 3이 고순도 Passage를 분석하여 "장애 원인은 OSPF Area 불일치이다"와 같은 초기 정답(Draft)을 도출합니다.

📍 Step 4: Debate 2 - The Pro/Con Clash (핵심 찬반 토론) 🔥
시스템의 신뢰성을 극대화하는 Debate 2 단계가 시작됩니다.

Con (공격): Agent 5 (Critic)가 "Passage를 보면 OSPF Area는 일치한다. 문제는 인터페이스 Down이다"라며 논리적 허점을 찌릅니다.

Pro (방어/수정): Agent 4 (Proponent)는 비판을 분석하여 "네 말이 맞다. 인터페이스 상태를 간과했다"라며 논리를 수정하거나, "아니다, 가상 링크가 설정되어 있어 Area 0과 연결된다"라며 방어합니다.

피드백 루프: 두 에이전트가 주어진 Passage만으로 결론을 내지 못하면, 파이프라인 앞단(Agent 1, 2)에 추가 정보 탐색을 요청합니다.

📍 Step 5: Consensus & Final Output (합의 및 최종 정답 도출)
Agent 4와 5가 오류 없음에 합의(Consensus)하거나 지정된 토론 턴(Max Turns)이 종료되면, 가장 논리적으로 완벽하게 검증된 **최종 정답(Final Answer)**을 출력합니다.

---

## 현재 아키텍처 (v1 — Current)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        DEBATE 1 (Extraction)                        │
  │                                                                     │
  │  Raw Context                                                        │
  │      │                                                              │
  │      ▼                                                              │
  │  ┌──────────┐   raw_data   ┌──────────┐  current_passage  ┌──────────────┐
  │  │ Agent 1  │ ──────────► │ Agent 2  │ ────────────────► │   Agent 3    │
  │  │Collector │             │ Verifier │                   │ Synthesizer  │
  │  └──────────┘             └──────────┘                   └──────────────┘
  │       ▲  (L4/L5 only: Verifier bypass → raw_data 직통)       │
  │       │                                                     │ candidate_answer
  └───────┼─────────────────────────────────────────────────────┼───────┘
          │                                                     ▼
  ┌───────┼─────────────────────────────────────────────────────────────┐
  │       │                  DEBATE 2 (Verification)                    │
  │       │                                                             │
  │       │                                        ┌──────────────┐    │
  │       │                        ┌──────────────►│   Agent 4    │    │
  │       │                        │  CONTINUE_    │  Proponent   │    │
  │       │                        │  DEBATE       └──────┬───────┘    │
  │       │                        │  (답 그대로)         │ pro_argument│
  │       │                        │                      ▼            │
  │       │                        │               ┌──────────────┐    │
  │       │  NEED_MORE_INFO        │               │   Agent 5    │    │
  │       └────────────────────────┤               │    Critic    │    │
  │         (feedback_to_collector │               └──────┬───────┘    │
  │          파싱되나 state 미저장  │                      │            │
  │          → Collector 빈 상태   │               critic_feedback     │
  │            로 재실행 [BUG])    └──────────────────────┘            │
  │                                        ACCEPT ──► Final Answer     │
  └─────────────────────────────────────────────────────────────────────┘

  [문제점]
  1. L3 질문도 Verifier 필터링 적용 → cross-device 비교에 필요한 context 손실
  2. CONTINUE_DEBATE 시 candidate_answer 미갱신 → Proponent가 오답을 반복 방어
     (Anchor Bias: D1 오답이 끝까지 유지됨)
     - critic_feedback은 state에 이미 존재하지만 Proponent는 이를 "방어 강화"에만 사용
     - candidate_answer를 새로 생성하는 주체(Synthesizer)가 루프에서 빠져있음
  3. NEED_MORE_INFO → Collector 루프: 라우팅은 존재하나 feedback_to_collector가
     skeptic_node 반환값에 누락 → Collector가 피드백 없이 재실행됨 [BUG]
```

---

## 개선 아키텍처 (v2 — Proposed)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        DEBATE 1 (Extraction)                        │
  │                                                                     │
  │  Raw Context                                                        │
  │      │                                                              │
  │      ▼                                                              │
  │  ┌──────────┐   raw_data   ┌──────────────────────────┐            │
  │  │ Agent 1  │ ──────────► │        Agent 2           │            │
  │  │Collector │             │        Verifier           │            │
  │  └──────────┘             │  ┌───────────────────┐   │            │
  │       ▲                   │  │ L1/L2: 필터링 적용 │   │            │
  │       │ NEED_MORE_INFO    │  │ L3~L5: BYPASS     │   │            │
  │       │ (outer loop ≤3)   │  └───────────────────┘   │            │
  │       │                   └────────────┬─────────────┘            │
  │       │                     current_passage                        │
  │       │                                ▼                           │
  │       │                        ┌──────────────┐ ◄──────────────┐  │
  │       │                        │   Agent 3    │                │  │
  │       │                        │ Synthesizer  │  critic_feedback│  │
  │       │                        └──────┬───────┘  (재생성 트리거) │  │
  │       │                               │ candidate_answer         │  │
  └───────┼───────────────────────────────┼──────────────────────────┼──┘
          │                               ▼                          │
  ┌───────┼──────────────────────────────────────────────────────────────┐
  │       │                  DEBATE 2 (Verification)                     │
  │       │                                                              │
  │       │                              ┌───────────────────────────┐  │
  │       │         CONTINUE_DEBATE      │        Agent 4            │  │
  │       │         ┌───────────────────►│       Proponent           │  │
  │       │         │                    │                           │  │
  │       │         │  (inner ≤3)        │  판정: DEFEND / CONCEDE   │  │
  │       │         │                    └──────┬──────────┬─────────┘  │
  │       │         │               DEFEND      │          │ CONCEDE    │
  │       │         │               (방어 가능) ▼          │ (비판 인정) │
  │       │         │                    ┌──────────────┐  │            │
  │       │  NEED_  │                    │   Agent 5    │  │            │
  │       │  MORE_  │                    │    Critic    │  │            │
  │       │  INFO   │                    └──────┬───────┘  │            │
  │       └─────────┤   CONTINUE_DEBATE         │          │            │
  │  (feedback_to_  │   (inner ≤3) ─────────────┘          │            │
  │   collector 포함│                                       │ CONCEDE    │
  │   — Fix 3)      │        ACCEPT ──► Final Answer        │ (inner ≤3) │
  │                 │                                ┌──────▼───────┐   │
  │                 │                                │   Agent 3    │   │
  │                 └────────────────────────────────│ Synthesizer  │   │
  │                         NEED_MORE_INFO           │  (재생성)    │   │
  │                                                  └──────────────┘   │
  └───────────────────────────────────────────────────────────────────────┘

  [개선 사항 — 기존 필드 재활용, 라우팅 + 프롬프트만 변경]

  Fix 1. Verifier: L3 bypass 추가 (L4/L5는 이미 적용됨)
         → L3 cross-device 비교 질문에서 context 손실 방지

  Fix 2. Proponent에 CONCEDE 판정 추가 (핵심)
         - Proponent가 Critic의 비판을 검토 후 두 가지 판정 출력:
           · DEFEND  → pro_argument 출력 후 Critic에게 전달 (방어 가능할 때)
           · CONCEDE → 비판이 타당함을 인정, Synthesizer 재호출 트리거
         - Synthesizer는 critic_feedback(이미 state에 존재)을 반영하여 candidate_answer 재생성
         - 수정 범위: Proponent 프롬프트에 판정 포맷 추가 + main_netconfig.py 라우팅 추가
         → 진짜 토론: 방어 가능하면 DEFEND, 인정할 때만 CONCEDE → 불필요한 재생성 방지
         → Anchor Bias 제거 (Proponent가 방어 불가 판단 시에만 답 갱신)

  Fix 3. feedback_to_collector 버그 수정
         - skeptic_node가 feedback_to_agent1을 파싱하나 state 반환값에 누락
         - 수정: return dict에 "feedback_to_collector": feedback_to_agent1 추가
         → NEED_MORE_INFO 루프 시 Collector가 구체적 재수집 지시 수신 가능
```

---

## 개선 전후 예상 성능 변화 (NetConfigQA 2.0 기준)

| 항목 | v1 (현재) | v2 (개선) | 원인 |
|---|---|---|---|
| Text 타입 TA-Acc | 49.7% | 향상 예상 | Synthesizer 재실행으로 오답 수정 가능 |
| L3 TA-Acc | 74.3% | 향상 예상 | Verifier bypass로 context 보존 |
| L4/L5 TA-Acc | 30.3% / 18.1% | 향상 예상 | Anchor Bias 제거 |
| Map 타입 TA-Acc | 85.0% | 유지 | Collector 세밀 추출 효과 유지 |
| 전체 TA-Acc | 65.79% | D2Only(67.33%) 초과 목표 | 두 Fix 복합 효과 |

---

⚙️ Experimental Setup (실험 환경 세팅)
본 연구는 통제된 실험을 위해 모델을 섞어 쓰지 않고, 5개의 에이전트 파이프라인 전체를 단일 체급의 모델로 고정하여 두 가지 세팅으로 비교 평가합니다.

Setup A (All-Local Mode): Agent 1~5 모두 vLLM (AWQ 4bit) 기반의 로컬 모델 하나만 사용하여 구동. (비용 0, 프라이버시 유지, 빠른 처리 속도 입증 목적)

Setup B (All-API Mode): Agent 1~5 모두 OpenRouter (GLM-4.7-flash) 외부 API 하나만 사용하여 구동. (최고 수준의 논리 추론 및 Debate 2 성능 확인 목적)