# NetAgent (agents_v2): 5-Stage Multi-Agent System for Network Configuration QA

NetAgent는 네트워크 설정 파일(.cfg)로부터 LLM이 정확한 답변을 추론하도록 설계된 **5단계 다중 에이전트 프레임워크**입니다.

단일 LLM이 방대한 네트워크 설정을 한 번에 처리할 때 발생하는 **환각(Hallucination)**과 **문맥 누수(Context Leakage)**를 차단하기 위해, Debate 1 (정보 정제) + Debate 2 (찬반 검증) 구조를 결합합니다.

---

## 에이전트 역할

| Agent | 이름 | 역할 | 사용 모델 |
|---|---|---|---|
| Agent 1 | Collector | 질문과 관련된 config 라인 추출 | Model B (GPT-4o mini) |
| Agent 2 | Verifier | 추출된 정보에서 무관한 라인 필터링 → 고순도 패시지 생성 | Model A (gemini-flash) |
| Agent 3 | Synthesizer | 정제된 패시지로부터 후보 답변 생성 | Model A (gemini-flash) |
| Agent 4 | Proponent | 후보 답변 방어 논리 제시 | Model A (gemini-flash) |
| Agent 5 | Critic | 패시지 대비 답변의 정확성 검증, 판정 출력 | Model B (GPT-4o mini) |

> **Hetero 구성**: A = gemini-3.1-flash-lite, B = GPT-4o mini
> 비용 효율을 위해 추론 부담이 낮은 에이전트(Verifier, Synthesizer, Proponent)에 경량 모델 A를,
> 판단 정확도가 중요한 에이전트(Collector, Critic)에 강력한 모델 B를 배치.

---

## 전체 파이프라인

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     DEBATE 1 (Extraction)                           │
  │                                                                     │
  │  Raw Context                                                        │
  │      │                                                              │
  │      ▼                                                              │
  │  ┌──────────┐  raw_data  ┌──────────────────────────┐              │
  │  │ Agent 1  │ ─────────► │        Agent 2           │              │
  │  │Collector │            │        Verifier           │              │
  │  └──────────┘            │  ┌────────────────────┐  │              │
  │       ▲                  │  │ L1/L2/L3: 필터링    │  │              │
  │       │ NEED_MORE_INFO   │  │ L4/L5: BYPASS      │  │              │
  │       │ (outer ≤3)       │  └────────────────────┘  │              │
  │       │ + feedback       └────────────┬─────────────┘              │
  │       │                   current_passage                           │
  │       │                              ▼                              │
  │       │                      ┌──────────────┐                      │
  │       │                      │   Agent 3    │                      │
  │       │                      │ Synthesizer  │                      │
  │       │                      └──────┬───────┘                      │
  │       │                             │ candidate_answer              │
  └───────┼─────────────────────────────┼────────────────────────────  ┘
          │                             ▼
  ┌───────┼──────────────────────────────────────────────────────────────┐
  │       │                  DEBATE 2 (Verification)                     │
  │       │                                                              │
  │       │                    ┌────────────────────────────┐           │
  │       │    CONTINUE_DEBATE │        Agent 4             │           │
  │       │    ┌──────────────►│       Proponent            │           │
  │       │    │  (inner ≤3)   │  후보 답변 방어 논리 제시   │           │
  │       │    │               └──────────────┬─────────────┘           │
  │       │    │                    DEFEND     │                         │
  │       │    │                    (방어)     ▼                         │
  │       │    │               ┌──────────────────┐                     │
  │       │ NEED_MORE_INFO     │     Agent 5       │                     │
  │       └────────────────────│      Critic       │                     │
  │         (feedback 포함)    └──────────┬────────┘                    │
  │                   CONTINUE_DEBATE     │                              │
  │                   (inner ≤3) ─────────┘                             │
  │                                       │                             │
  │                   ACCEPT ──► Final Answer                           │
  └──────────────────────────────────────────────────────────────────────┘
```

### 라우팅 규칙

| Critic 판정 | 조건 | 다음 노드 |
|---|---|---|
| ACCEPT | — | END (최종 답변 확정) |
| CONTINUE_DEBATE | inner_turn_count < 3 | Proponent |
| CONTINUE_DEBATE | inner_turn_count ≥ 3 | END (강제 종료) |
| NEED_MORE_INFO | outer_loop_count < 3 | Collector (feedback 전달) |
| NEED_MORE_INFO | outer_loop_count ≥ 3 | END (강제 종료) |

---

## 레벨별 처리 전략

| Level | 질문 유형 | Collector | Verifier | Synthesizer 전략 |
|---|---|---|---|---|
| L1/L2 | 단일 장비 fact 추출 | 해당 장비 config 추출 | 필터링 적용 | 정확한 config 값 직접 추출 |
| L3 | 다중 장비 cross-비교 | 관련 장비 config 추출 | 필터링 적용 | 장비 간 비교 추론 |
| L4 | 경로 추적 (traceroute) | 전체 토폴로지 추출 | **BYPASS** | hop-by-hop 라우팅 시뮬레이션 |
| L5 | 장애 분석 (what-if) | 전체 토폴로지 추출 | **BYPASS** | **6단계 fault analysis** |

### L5 Synthesizer 6단계 추론

```
[Step 1] 정상 토폴로지 구축 — 모든 장비의 인터페이스 + 라우팅 테이블 나열
[Step 2] 정상 경로 추적 — hop-by-hop으로 src→dst 경로 확인
[Step 3] 장애 적용 — 지정된 링크/장비 제거, 영향 인터페이스/라우트 표시
[Step 4] 장애 후 경로 재추적 — NO_ROUTE 지점 또는 대안 경로 탐색
[Step 5] 답 결정 — Blocking device / Possible / Impossible / count
[Step 6] 최종 한 줄 출력
```

> **근거**: homo(all GPT-4o mini) L5=48.5% vs hetero full L5=18.1%. 단계적 추론 없이는
> gemini-flash-lite가 복잡한 fault analysis를 처리하지 못함. 6단계 명시로 추론 구조 제공.

---

## 답변 타입별 출력 규칙

| answer_type | 출력 형식 | 특이사항 |
|---|---|---|
| text | 정확한 config 값 (원문 그대로) | case 보존 필수 (e.g. "PE1" not "pe1") |
| numeric | 정수 또는 소수 | 단위 없음, 설명 없음 |
| number | 정수 | 카운팅 결과 |
| set | JSON 배열 `["a","b"]` | **Loopback 마지막** |
| map | JSON 객체 `{"k":"v"}` | **Loopback 마지막**, 추론 규칙 적용 |
| boolean | `true` or `false` | |
| path | `A→B→C` or `No path` | 정확한 hostname case 사용 |

> **Loopback 순서 규칙**: set/map 타입에서 물리 인터페이스(GigabitEthernet 등) 먼저,
> Loopback 인터페이스 마지막. e.g. `{"GigabitEthernet0/0": "...", "Loopback0": "..."}`

---

## Verifier 필터링 철학

```
기존: "무관한 줄은 삭제" → 공격적 필터링 → Text 타입 정답 라인 소실
개선: "의심스러우면 보존" → 보수적 필터링
```

핵심 규칙:
- **Rule 3**: "WHEN IN DOUBT, KEEP THE LINE. Only delete if certain."
- **Rule 10**: Value-extraction 질문(hostname, version, AS number 등)은 관련 섹션 전체 보존

---

## 실험 결과 (NetConfigQA 2.0, TA-Acc)

### 전체 성능

| Configuration | EM | TA-Acc | 비고 |
|---|---|---|---|
| Single LLM (GPT-4o mini) | 0.3976 | 51.51 | baseline |
| NetAgent homo (GPT-4o mini) | 0.4869 | 56.06 | 전 에이전트 동일 모델 |
| NetAgent D1 Only | 0.4921 | 59.75 | Debate-2 없음 |
| NetAgent D2 Only | 0.5866 | **67.33** | Debate-1 없음, raw context |
| **NetAgent hetero (agents_v2)** | **0.6260** | 65.79 | Full pipeline |

### 타입별 TA-Acc

| Configuration | Map | Numeric | Text | Number | Set |
|---|---|---|---|---|---|
| Single LLM | 61.8 | 68.3 | 42.6 | 19.4 | 73.3 |
| homo | 15.0 | 78.2 | 48.4 | 19.4 | 86.1 |
| D1 Only | 12.5 | **95.0** | 51.6 | 3.0 | 92.7 |
| D2 Only | 17.5 | 94.1 | **60.5** | 29.9 | **95.1** |
| **hetero (agents_v2)** | **85.0** | 94.1 | 49.7 | **37.3** | 94.1 |

### 난이도별 TA-Acc

| Configuration | L1 | L2 | L3 | L4 | L5 |
|---|---|---|---|---|---|
| Single LLM | 76.5 | 54.1 | 36.9 | 26.7 | 15.9 |
| homo | 72.0 | 54.7 | 70.6 | 10.1 | **48.5** |
| D1 Only | 80.7 | 87.9 | 73.5 | 18.8 | 21.5 |
| D2 Only | 84.3 | 87.3 | **81.9** | **34.5** | 32.2 |
| **hetero (agents_v2)** | **89.2** | **89.9** | 74.3 | 30.3 | 18.1 |

---

## 분석: Full Pipeline vs D2Only

D2Only(67.33%) > Full hetero(65.79%)인 원인:

| 원인 | 영향 |
|---|---|
| Verifier가 Text 답변 라인 삭제 | Text -10.8% |
| Anchor Bias: Proponent가 오답을 그대로 방어 | L3/L4/L5 하락 |
| L5 Synthesizer 추론 부족 | L5 -14% vs homo |
| Collector NEED_MORE_INFO 재추출 시 context 손실 | L4/L5 하락 |

> **Full이 D2Only 대비 강점**: Map +67.5%, Number +7.4%, L1/L2 +3~5%
> Debate-1 Collector의 구조화 추출 효과는 Map 타입에서 명확히 입증됨.

---

## 실험 환경

| 항목 | 설정 |
|---|---|
| Model A | gemini-3.1-flash-lite (Verifier, Synthesizer, Proponent) |
| Model B | GPT-4o mini (Collector, Critic) |
| 데이터셋 | NetConfigQA 2.0 (762 QA, L1~L5, 127 메트릭) |
| 평가 지표 | TA-Acc (Type-Aware Accuracy), EM, BertScore |
| 병렬 처리 | ThreadPoolExecutor (MAX_WORKERS=50) |
| Recursion limit | 25 (LangGraph 기본값) |
