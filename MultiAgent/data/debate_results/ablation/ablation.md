# Ablation 실험 계획

## 현황 정리

| 실험 | 조건 | 데이터셋 | 상태 |
|---|---|---|---|
| A1. Single LLM | 단일 모델 baseline | NetConfig, TeleQnA, TeleQuAD, NetBench | ✅ 완료 |
| A3. Full 5-agent | Collector→Verifier→Synthesizer→Supporter→Skeptic | NetConfig, TeleQnA, TeleQuAD, NetBench | ✅ 완료 |
| C2a. Heterogeneous | gpt-4o-mini (A) + gemini2.5-flash (B) | NetConfig, TeleQnA, TeleQuAD, NetBench | ✅ 완료 |
| C2b. Heterogeneous | gpt-4o-mini (A) + gemini2.5-flash-lite (B) | NetConfig, TeleQnA, TeleQuAD, NetBench | ✅ 완료 |

> 이 폴더(`ablation1/`)의 teleqna_result.json, telequad_result.json은 위 실험 중 하나의 결과.

---

## 추가 필요 실험

### [A] 에이전트 구성 Ablation

**목표**: A1 < A2 < A3 계단식 성능 향상을 보여 각 debate phase의 기여를 증명.

| 조건 | 구성 | 상태 | 비고 |
|---|---|---|---|
| A1. Single LLM | Synthesizer만 (no debate) | ✅ 완료 | baseline |
| **A2. Debate-1 only** | Collector→Verifier→Synthesizer (Supporter/Skeptic 없음) | ❌ 미실행 | **1순위** |
| A3. Full 5-agent | 전체 파이프라인 | ✅ 완료 | 기준점 |
| A4. w/o Verifier | Collector→Synthesizer 직행 | ❌ 미실행 | 3순위 |
| A5. w/o Collector | raw context → Synthesizer 직행 | ❌ 미실행 | 3순위 |

### [C] 모델 조합 Ablation

**목표**: Heterogeneous(이종 모델) debate가 Homogeneous(동종 모델)보다 효과적임을 증명.

| 조건 | A 모델 | B 모델 | 상태 | 비고 |
|---|---|---|---|---|
| **C1. Homogeneous** | gpt-4o-mini | gpt-4o-mini | ❌ 미실행 | **2순위** |
| C2a. Heterogeneous | gpt-4o-mini | gemini2.5-flash | ✅ 완료 | |
| C2b. Heterogeneous | gpt-4o-mini | gemini2.5-flash-lite | ✅ 완료 | |

> 모델 역할: A = Verifier, Synthesizer, Supporter / B = Collector, Skeptic

### [B] Debate 반복 횟수 Ablation (선택)

**목표**: loop 비용 대비 성능 향상 정량화.

| 조건 | inner_turn_count (max) | outer_loop_count (max) | 상태 |
|---|---|---|---|
| B1. No loop | 1 | 1 | ❌ 미실행 |
| B4. Full loop | 3 | 3 | ✅ 현재 설정 |

---

## 실행 우선순위

```
1순위 (반드시): A2 — Debate-1 only
2순위 (중요):   C1 — Homogeneous (gpt-4o-mini + gpt-4o-mini)
3순위 (추가):   A4 or A5 — 개별 에이전트 기여도
4순위 (선택):   B1 — loop=1 vs loop=3
```

A2 + C1만 완료해도 ablation 섹션 구성 가능.

---

## 에이전트 구조 참고

```
Collector(B) → Verifier(A) → Synthesizer(A) → Supporter(A) → Skeptic(B)
                                                     ↑              |
                                              CONTINUE_DEBATE ←──────┘ (max 3회)
                             ↑                                         |
                      NEED_MORE_INFO ←─────────────────────────────────┘ (max 3회)
```
