# 🚀 NetAgent: 5-Stage Multi-Agent System for Network Configuration QA

NetAgent는 네트워크 설정 파일(`.cfg`)로부터 질문에 대한 정확한 답변을 추론하는 **5단계 다중 에이전트 프레임워크**입니다.

단일 LLM이 방대한 설정을 한 번에 처리할 때 발생하는 **환각(Hallucination)**과 **문맥 누수(Context Leakage)**를 방지하기 위해, 추출 → 검증 → 생성 → 옹호 → 비판의 역할 분리 파이프라인을 구성합니다.

---

## 👥 Agent 역할 구성

| 에이전트 | 역할 | 판정 출력 |
|---|---|---|
| Agent 1: Collector | 질문 관련 장비 설정 추출 | - |
| Agent 2: Verifier | 추출 품질 점수 평가 (관련성 게이트) | RELEVANT / IRRELEVANT |
| Agent 3: Synthesizer | 패시지 기반 후보 답변 생성 | - |
| Agent 4: Supporter | 패시지 근거로 후보 답변 옹호 | - |
| Agent 5: Critic | 패시지 + 답변 + 옹호 종합 판정 | ACCEPT / REVISE |

---

## 🔄 전체 파이프라인 (v3 — Current)

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                       DEBATE 1 (Extraction)                          │
  │                                                                      │
  │  ConfigManager                                                       │
  │  (=== START/END OF CONFIG: HOSTNAME === 헤더 포함)                   │
  │      │                                                               │
  │      ▼  context (장비별 필터링 또는 전체)                              │
  │  ┌──────────┐   raw_data   ┌─────────────────────────────────────┐  │
  │  │ Agent 1  │ ──────────► │             Agent 2                  │  │
  │  │Collector │             │             Verifier                  │  │
  │  └──────────┘             │                                       │  │
  │       ▲                   │  채점 항목 (총 10점, 임계값 6점):      │  │
  │       │ IRRELEVANT        │    C1 Device Match       0/1/3점      │  │
  │       │ (score < 6)       │    C2 Feature Presence   0/2/4점      │  │
  │       │ + feedback        │    C3 Completeness        0/1/2점      │  │
  │       └───────────────────│    C4 Format Integrity    0/1점        │  │
  │         (outer_loop ≤ 3)  └──────────────┬──────────────────────┘  │
  │                              RELEVANT     │ current_passage          │
  │                              (score ≥ 6) ▼                          │
  │                           ┌──────────────────┐ ◄──────────────────┐ │
  │                           │     Agent 3      │                    │ │
  │                           │   Synthesizer    │  synthesizer_      │ │
  │                           └────────┬─────────┘  feedback          │ │
  │                                    │ candidate_answer  (REVISE 시) │ │
  └────────────────────────────────────┼───────────────────────────────┼─┘
                                       ▼                               │
  ┌────────────────────────────────────────────────────────────────────┼─┐
  │                       DEBATE 2 (Verification)                      │ │
  │                                                                    │ │
  │                           ┌──────────────────┐                    │ │
  │                           │     Agent 4      │                    │ │
  │                           │    Supporter     │                    │ │
  │                           │  (passage 근거   │                    │ │
  │                           │   답변 옹호)     │                    │ │
  │                           └────────┬─────────┘                    │ │
  │                                    │ pro_argument                  │ │
  │                                    ▼                               │ │
  │                           ┌──────────────────┐                    │ │
  │                           │     Agent 5      │                    │ │
  │                           │      Critic      │                    │ │
  │                           └────────┬─────────┘                    │ │
  │                                    │                               │ │
  │              ACCEPT ───────────────┘                               │ │
  │           → Final Answer                                           │ │
  │                                                                    │ │
  │              REVISE (inner_turn ≤ 3) ──────────────────────────────┘ │
  │           → synthesizer_feedback 포함 → Synthesizer 재생성            │
  └───────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Agent별 상세 동작

### Agent 1: Collector

- **입력**: `context` (ConfigManager가 생성한 `=== START/END OF CONFIG ===` 헤더 포함 설정)
- **역할**: 질문에 해당하는 장비 설정 블록을 verbatim 추출
- **프롬프트 설계**: Verifier 채점 항목(C1~C4)에 맞춰 구성
  - C1 대응: `=== START/END OF CONFIG ===` 마커 + `hostname` 라인 반드시 포함
  - C2 대응: 질문이 묻는 특정 커맨드 섹션 명시 추출, 없으면 `[FEATURE_NOT_FOUND]`
  - C3 대응: 블록 절대 잘라내지 말 것, COUNT/MAP 질문별 완전 추출
  - C4 대응: raw config만, 자연어 변환 금지
- **폴백**: 추출 결과 < 30자이면 원본 `context` 그대로 사용
- **L4/L5**: `netconfig_topo` 전략 — 전체 장비 블록 + 라우팅 섹션 추출

### Agent 2: Verifier (Scoring-based Relevance Gate)

- **입력**: `raw_data` (Collector 추출 결과)
- **역할**: 추출 품질을 점수로 평가하여 Synthesizer 진입 여부 결정
- **채점 루브릭**:

| 항목 | 점수 | 기준 |
|---|---|---|
| C1 Device Match | 0/1/3 | 질문의 장비명이 추출 결과에 있는가 |
| C2 Feature Presence | 0/2/4 | 질문이 묻는 커맨드/섹션이 존재하는가 |
| C3 Completeness | 0/1/2 | 블록이 답변 가능할 만큼 완전한가 |
| C4 Format Integrity | 0/1 | raw config 형태인가 (자연어 변환 아닌가) |

- **판정**:
  - `total ≥ 6` → **RELEVANT**: `raw_data`를 그대로 `current_passage`로 전달 (필터링 없음)
  - `total < 6` → **IRRELEVANT**: 실패 항목 기반 `feedback_to_collector` 생성 → Collector 재호출
- **즉시 통과**: `[FEATURE_NOT_FOUND]` 포함 시 RELEVANT (기능 부재 확인된 것)
- **즉시 실패**: `raw_data`가 비어있거나 `[NONE]`이면 LLM 없이 IRRELEVANT

### Agent 3: Synthesizer

- **입력**: `current_passage` + (REVISE 루프 시) `synthesizer_feedback`
- **역할**: 패시지만 보고 후보 답변 생성. context 전체를 보지 않아 문맥 누수 방지
- **REVISE 시**: Critic의 `synthesizer_feedback`을 프롬프트에 포함하여 오류 수정 재생성
- **answer_type별 출력 포맷**: text / number / set / map / boolean / path 각각 엄격한 형식 적용

### Agent 4: Supporter

- **입력**: `current_passage` + `candidate_answer` + (이전 라운드) `synthesizer_feedback`
- **역할**: 후보 답변을 패시지 근거로 옹호. 패시지 라인 직접 인용 필수
- **이전 Critic 피드백 있으면**: 각 지적 사항에 패시지 근거로 반박

### Agent 5: Critic

- **입력**: `current_passage` + `candidate_answer` + `pro_argument`
- **역할**: 패시지와 답변의 일치 여부를 최종 판정
- **판정**:
  - **ACCEPT**: 답변이 패시지로 정확히 뒷받침됨 → `final_answer` 확정, 종료
  - **REVISE**: 오류/논리 비약 발견 → `synthesizer_feedback`에 구체적 수정 지시 포함 → Synthesizer 재호출
- **REVISE 트리거 기준**: 패시지에 없는 값 사용, 언더카운팅, null/0/{} 오용, unknown 값 사용 등

---

## ⚙️ Context 결정 로직 (ConfigManager)

```python
# 토폴로지 전체 필요 여부 판별
topo_keywords = ('hop', 'path', 'block', 'flow', 'reach', 'traceroute', 'fail', 'down', 'between')

if level in ('L4', 'L5') or any(kw in question for kw in topo_keywords):
    context = config_manager.get_all_configs()        # 전체 장비 (헤더 포함)
else:
    context = config_manager.get_filtered_configs(question)  # 장비명 word-boundary 매칭
    # 매칭 실패 시 자동으로 전체 반환 (집계 질문 대응)
```

- 장비명 매칭: `re.search(r'\b' + device_name + r'\b')` — `pe1`이 `pe10`에 매칭되는 오류 방지
- 전체 config는 `=== START OF CONFIG: PE1 ===` ... `=== END OF CONFIG: PE1 ===` 헤더 포함 반환

---

## 🔁 루프 제어

| 루프 | 조건 | 최대 횟수 | 카운터 |
|---|---|---|---|
| Verifier → Collector | Verifier score < 6 | 3회 | `outer_loop_count` |
| Critic → Synthesizer | Critic 판정 REVISE | 3회 | `inner_turn_count` |

- **타임아웃**: 항목당 300초. 초과 시 `[TIMEOUT]` 반환 후 다음 항목 처리
- **MAX_WORKERS**: 10 (병렬 처리 스레드 수, rate limit 방지)

---

## 🆚 버전별 아키텍처 비교

| 항목 | v1 (기존) | v2 (중간) | v3 (현재) |
|---|---|---|---|
| Context 전달 | 전체 config 무조건 전달 | 장비명 단순 포함 검사 | word-boundary 매칭 + ConfigManager 헤더 |
| Verifier 역할 | 라인 필터링 | 라인 필터링 | **점수 기반 관련성 게이트 (C1~C4)** |
| Verifier→Collector 루프 | 없음 | 없음 | **추가 (score < 6)** |
| Collector 프롬프트 | ALREADY scoped (모순) | 헤더 미인식 | **C1~C4 항목별 대응 규칙** |
| NEED_MORE_INFO | Critic이 발행 (BUG 있음) | Critic이 발행 | **제거 (Verifier가 담당)** |
| CONTINUE_DEBATE | Supporter 재호출 | CONCEDE/DEFEND | **제거** |
| Critic 판정 | ACCEPT/CONTINUE/NEED | ACCEPT/CONTINUE/NEED | **ACCEPT / REVISE** |
| Synthesizer 재생성 | 없음 | CONCEDE 시 | **REVISE 시 + synthesizer_feedback** |
| Supporter 역할 | 일방 옹호 | DEFEND/CONCEDE 판정 | **단순 옹호 (판정 없음)** |
| 타임아웃 | 없음 (hang 발생) | 없음 | **300초** |

---

## ⚙️ 실험 환경

- **Setup A (All-Local)**: Agent 1~5 전부 vLLM (AWQ 4bit) 로컬 모델 단일 사용
- **Setup B (All-API)**: Agent 1~5 전부 OpenRouter 외부 API 단일 사용
- 실험 통제를 위해 에이전트 간 모델 혼용 없음 (단일 백본 고정)
