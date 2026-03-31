# IEEE TNSE 실험 계획

## 논문 핵심 질문

> 네트워크 설정 분석에서 성능 향상은 **MAS 구조** 때문인가, **MCP 도구** 때문인가, **둘 다** 때문인가?

이걸 답하려면 **요인을 분리**해야 한다.

---

## Phase 1: 메인 결과 테이블 (4-way x 4 Labs)

| 시스템 | MAS | MCP 도구 | 모델 | 왜 이 실험이 필요한가 |
|--------|:---:|:-------:|------|----------------------|
| Single LLM | X | X | 각 Lab별 best | **baseline** - LLM만으로 얼마나 하는지 |
| Pure MAS | O | X | 각 Lab별 best | **MAS만의 기여** - 토론이 성능을 올리는지 |
| Single+MCP | X | O | gpt-4o-mini | **MCP만의 기여** - 도구가 성능을 올리는지 |
| **NetAlly (MAS+MCP)** | O | O | gpt-4o-mini | **제안 시스템** - 둘 다 합치면 어떤지 |

### 왜 4-way인가

- 4칸 중 하나만 빠져도 "MAS 기여 vs MCP 기여"를 분리할 수 없다.
- 리뷰어 예상 질문 1: "도구 없이 MAS만 써도 되지 않나?" -> Pure MAS 결과로 답변
- 리뷰어 예상 질문 2: "에이전트 없이 도구만 쓰면?" -> Single+MCP 결과로 답변

### 예상 결과와 논문 스토리

```
Single LLM:     ~40%  --> baseline
Pure MAS:       ~45%  --> MAS만으로는 +5%p (미미)
Single+MCP:     ~85%  --> MCP 도구가 +45%p (핵심 기여!)
NetAlly:        ~92%  --> MAS+MCP 시너지로 +7%p 추가
```

**스토리: MCP 도구가 핵심 기여(+45%p), MAS가 추가 품질 개선(+7%p), 둘의 시너지가 최고 성능.**

### 담당 분배

| 실험 | 담당 | 상태 |
|------|------|------|
| Single LLM (5 models x 4 Labs) | 완료 | DONE |
| Pure MAS (best model x 4 Labs) | 팀원 | TODO |
| Single+MCP (gpt-4o-mini x 4 Labs) | 나 | TODO (구현 필요: Collector만 + 도구, debate 없음) |
| NetAlly MAS+MCP (gpt-4o-mini x 4 Labs) | 나 | LabB DONE, A/C/D TODO |

### 모델 선택 기준

메인 테이블의 각 시스템은 **best 모델 1개만** 사용한다. 메인 테이블의 목적은 **"시스템 구조 비교"**이지 "모델 비교"가 아니다. 모델 비교는 Phase 2에서 한다.

---

## Phase 2: 모델 Ablation (Lab D only)

### 왜 Lab D만 하는가

- 가장 어려운 토폴로지 (Single LLM 최저 14-27%)
- 모델 차이가 극대화됨
- 쉬운 Lab에서는 다 비슷하게 나와서 의미 없음
- 논문에 "가장 어려운 토폴로지에서 ablation 수행"이라고 쓰면 리뷰어도 납득

### 왜 이 실험을 하는가

리뷰어 예상 질문: "왜 그 모델을 골랐나? 다른 모델이면 어떤가?"

### 2-A. 동일 모델 비교 (5회)

5개 에이전트 전부 같은 모델 사용. MAS+MCP 프레임워크에서 **모델 선택의 영향**을 측정.

| 실험 | 모델 (5에이전트 동일) | Lab D | 특성 |
|------|----------------------|-------|------|
| A-1 | gpt-4o-mini | ? | tool calling 특화 (OpenAI RLHF) |
| A-2 | gpt-oss-20b | ? | 대형 오픈소스 |
| A-3 | Mistral3-8B | ? | Single LLM best |
| A-4 | Qwen3-8B | ? | 아시아권 모델 |
| A-5 | Llama-3.1-8B | ? | 메타 오픈소스 |

-> **"MAS+MCP에서도 모델 선택이 중요한가?"**에 답변

### 2-B. 역할별 모델 분리 (2-3회)

MAS의 5개 에이전트 중 **어떤 역할이 모델 성능에 가장 민감한가** 측정.

에이전트 역할:
- **Collector**: 도구 선택 + 데이터 수집 (tool calling 능력 중요)
- **Verifier**: 노이즈 제거 (단순 필터링)
- **Synthesizer**: 최종 답변 생성 (추론 능력 중요)
- **Supporter/Skeptic**: 답변 검증 + debate (비판적 사고 중요)

| 실험 | Collector/Verifier | Synthesizer | Supporter/Skeptic | Lab D |
|------|-------------------|-------------|-------------------|-------|
| B-1 | Mistral-8B | **gpt-4o-mini** | Mistral-8B | ? |
| B-2 | **gpt-4o-mini** | Mistral-8B | gpt-4o-mini | ? |
| B-3 | Mistral-8B | Mistral-8B | **gpt-4o-mini** | ? |

-> **"Synthesizer(답변 생성)의 모델이 가장 중요하다"** 같은 insight 도출

---

## Phase 3: 분석 (실험 아님, 결과 해석)

| 분석 | 목적 | 논문 위치 | 교수님 피드백 반영 |
|------|------|----------|-------------------|
| 레벨별 breakdown (L1-L5) | 난이도별 시스템 차이 | Table / Figure | question_type 분류 |
| Tool usage 통계 | 어떤 도구가 핵심인지 | Section V | 정량적 분석 |
| 오답 정성 분석 | 왜 틀리는지 패턴 분류 | Section V | 정성적 분석 |
| 속도/토큰 비교 | 실용성 평가 | Table | - |

---

## 전체 실험량 정리

| Phase | 실험 수 | 담당 | 비고 |
|-------|--------|------|------|
| Phase 1 메인 테이블 | 4시스템 x 4Labs = **16회** | 나 + 팀원 분담 | 전체 데이터셋 (vLLM) |
| Phase 2-A 모델 비교 | 5모델 x 1Lab = **5회** | 나 or 팀원 | Lab D only |
| Phase 2-B 역할 분리 | 2-3조합 x 1Lab = **3회** | 팀원 | Lab D only |
| **총** | **~24회** | | 모든 리뷰어 질문에 답변 가능 |

---

## 현재 진행 상태

### 완료

- [x] Single LLM x 5 models x 4 Labs
- [x] NetAlly (MAS+MCP) LabB sampled 100문제: gpt-4o-mini 92%, gpt-oss-20b 87%
- [x] TA-Acc scorer 정규화 (한국어, alias, 대소문자)
- [x] 대규모 평가 안정성 (per-question timeout, hard shutdown)
- [x] Batfish 스냅샷/포트 문제 해결

### 다음 단계

1. [ ] Ubuntu PC vLLM 서버 시작
2. [ ] NetAlly (MAS+MCP) Lab B 전체 데이터셋
3. [ ] Single+MCP 구현 (Collector만 + 도구, debate 없음)
4. [ ] NetAlly Lab A, C, D 전체 데이터셋
5. [ ] Single+MCP Lab A-D 전체 데이터셋
6. [ ] Phase 2 모델 ablation (Lab D)
