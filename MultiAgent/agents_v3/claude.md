# agents_v3 — NetAgent 개선 아키텍처 (v2 기반)

## 개요

agents_v2의 세 가지 버그/한계를 수정한 버전입니다.
기존 state 필드 재활용을 원칙으로 하며, **라우팅 로직과 프롬프트만 변경**합니다.

---

## v1 문제점 요약

| # | 문제 | 증상 |
|---|---|---|
| 1 | L3도 Verifier 필터링 적용 | cross-device 비교에 필요한 context 손실 |
| 2 | CONTINUE_DEBATE 시 candidate_answer 미갱신 | Proponent가 D1 오답을 끝까지 반복 방어 (Anchor Bias) |
| 3 | `feedback_to_collector` state 반환 누락 | NEED_MORE_INFO 루프에서 Collector가 빈 상태로 재실행 |

---

## 아키텍처 다이어그램 (v2)

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
│   — Fix 3)      │        ACCEPT ──► Final Answer        │            │
│                 │                                ┌──────▼───────┐   │
│                 │                                │   Agent 3    │   │
│                 └────────────────────────────────│ Synthesizer  │   │
│                         NEED_MORE_INFO           │  (재생성)    │   │
│                                                  └──────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 개선 사항 (Fix 1~3)

### Fix 1. Verifier — L3 bypass 추가

- **변경 전**: L4/L5만 Verifier 필터링 bypass
- **변경 후**: L3~L5 모두 bypass (L1/L2만 필터링 적용)
- **수정 위치**: `debate1.py` Verifier 분기 조건
- **효과**: L3 cross-device 비교 질문에서 context 손실 방지

### Fix 2. Proponent — CONCEDE 판정 추가 (핵심)

- **변경 전**: Proponent는 항상 candidate_answer를 방어 → Anchor Bias 발생
- **변경 후**: Proponent가 두 가지 판정을 출력
  - `DEFEND`: 비판이 타당하지 않음 → `pro_argument` 출력 후 Critic에게 전달
  - `CONCEDE`: 비판이 타당함을 인정 → Synthesizer 재호출 트리거
- **Synthesizer 재생성**: `critic_feedback`(이미 state에 존재)을 반영해 `candidate_answer` 재생성
- **수정 위치**: `debate2.py` Proponent 프롬프트 + `main_netconfig.py` 라우팅
- **효과**: 진짜 토론 구현 + Anchor Bias 제거 (방어 불가 시에만 답 갱신)

### Fix 3. feedback_to_collector 버그 수정

- **변경 전**: `skeptic_node`가 `feedback_to_agent1`을 파싱하지만 state 반환값에 누락
- **변경 후**: `return dict`에 `"feedback_to_collector": feedback_to_agent1` 추가
- **수정 위치**: `debate2.py` skeptic_node 반환부
- **효과**: NEED_MORE_INFO 루프 시 Collector가 구체적 재수집 지시 수신 가능

---

## 예상 성능 변화 (NetConfigQA 2.0 기준)

| 항목 | v1 (agents_v2) | v2 목표 | 근거 |
|---|---|---|---|
| Text 타입 TA-Acc | 49.7% | 향상 | Synthesizer 재실행으로 오답 수정 |
| L3 TA-Acc | 74.3% | 향상 | Verifier bypass로 context 보존 |
| L4 TA-Acc | 30.3% | 향상 | Anchor Bias 제거 |
| L5 TA-Acc | 18.1% | 향상 | Anchor Bias 제거 |
| Map 타입 TA-Acc | 85.0% | 유지 | Collector 세밀 추출 효과 유지 |
| 전체 TA-Acc | 65.79% | 67.33% 초과 목표 | Fix 1~3 복합 효과 |

> 비교 기준: D2Only 단독 실험 결과 67.33%를 목표 하한선으로 설정

---

## 수정 범위 요약

| 파일 | 변경 내용 |
|---|---|
| `debate1.py` | Verifier bypass 조건: `L4/L5` → `L3/L4/L5` |
| `debate2.py` | Proponent 프롬프트에 `DEFEND/CONCEDE` 판정 포맷 추가; skeptic_node 반환에 `feedback_to_collector` 추가 |
| `main_netconfig.py` | Proponent 판정 라우팅 추가: `CONCEDE` → Synthesizer 재호출 |
| `state.py` | 변경 없음 (기존 필드 재활용) |
