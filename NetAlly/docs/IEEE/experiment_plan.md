# IEEE TNSE 실험 계획 (v2)

> 최종 수정: 2026-03-31
> 📊 = 실측 완료, 📐 = 실험 필요

---

## 논문 핵심 질문

> 네트워크 설정 분석에서 성능 향상은 **MAS 구조** 때문인가, **MCP 도구** 때문인가, **둘 다** 때문인가?

이걸 답하려면 **요인을 분리**해야 한다.

---

## Phase 1: 메인 결과 테이블 (Table I — 4-way × 4 Labs)

### 실험 설계

| # | 시스템 | MAS | MCP | 설명 |
|---|--------|:---:|:---:|------|
| 1 | Single LLM | X | X | config 텍스트만 주고 LLM이 직접 답변 (baseline) |
| 2 | Pure MAS | O | X | 5-agent debate, config 텍스트만 사용, 도구 없음 |
| 3 | Single+MCP | X | O | LLM 1개 + MCP 도구(NSO/Batfish), debate 없음 |
| 4 | NetAlly (MAS+MCP) | O | O | 5-agent debate + MCP 도구 (제안 시스템) |

### 왜 4개 모두 필요한가

```
                 MCP 도구 없음        MCP 도구 있음
              ┌─────────────────┬─────────────────┐
  MAS 없음   │  Single LLM     │  Single+MCP     │
              │  (baseline)     │  (MCP만의 기여)  │
              ├─────────────────┼─────────────────┤
  MAS 있음   │  Pure MAS       │  NetAlly        │
              │  (MAS만의 기여) │  (제안 시스템)   │
              └─────────────────┴─────────────────┘
```

- 하나라도 빠지면 "MAS 기여 vs MCP 기여" 분리 불가
- 리뷰어 예상 질문: "도구 없이 MAS만?" → Pure MAS, "MAS 없이 도구만?" → Single+MCP

### 상세 실험 목록

#### 실험 1: Single LLM ✅ 완료

> 담당: 완료 (팀원)
> 출처: `paper_summary_20260331_112207.md`

| 모델 | Params | Lab A | Lab B | Lab C | Lab D | Avg | L4 Avg | L5 Avg |
|------|-------:|------:|------:|------:|------:|----:|-------:|-------:|
| Mistral3-8B | 8B | 43.38 📊 | 42.28 📊 | 33.33 📊 | 26.70 📊 | **36.42** | 15.85 | 12.13 |
| GPT-OSS-20B | 20B | **46.99** 📊 | 41.54 📊 | 31.51 📊 | 24.19 📊 | 36.06 | 12.62 | 13.20 |
| Qwen3-8B | 8B | 41.11 📊 | 38.42 📊 | 28.92 📊 | 21.92 📊 | 32.59 | 11.19 | 11.52 |
| GPT-4o-mini | 8B* | 39.43 📊 | 39.02 📊 | 28.56 📊 | 22.32 📊 | 32.33 | 15.62 | 5.87 |
| Llama-3.1-8B | 8B | 23.30 📊 | 25.23 📊 | 17.78 📊 | 14.48 📊 | 20.19 | 5.93 | 6.00 |

메인 테이블(Table I)에는 **각 Lab별 best 모델** 사용:
- Lab A: GPT-OSS-20B (46.99%)
- Lab B: Mistral3-8B (42.28%)
- Lab C: Mistral3-8B (33.33%)
- Lab D: Mistral3-8B (26.70%)

#### 실험 2: Pure MAS 📐

> 담당: **팀원**
> 코드: `MultiAgent/agents_v3/` (기존 MAS, 도구 없음)
> 입력: config 텍스트를 static context로 전달

| 모델 | Lab A | Lab B | Lab C | Lab D | 비고 |
|------|------:|------:|------:|------:|------|
| Mistral3-8B | 📐 | 📐 | 📐 | 📐 | Single LLM best이므로 동일 모델 사용 |

**실행 방법:**
```bash
# vLLM 서버에서 Mistral3-8B 서빙
# agents_v3 MAS eval runner로 전체 데이터셋 실행
cd MultiAgent
python run_eval.py --module agents_v3 --model Mistral3-8B --lab LabA
python run_eval.py --module agents_v3 --model Mistral3-8B --lab LabB
python run_eval.py --module agents_v3 --model Mistral3-8B --lab LabC
python run_eval.py --module agents_v3 --model Mistral3-8B --lab LabD
```

#### 실험 3: Single+MCP 📐

> 담당: **나**
> 코드: 새로 구현 필요 — Collector 1개만 + MCP 도구, debate 없음
> 모델: gpt-4o-mini (MCP에서 tool calling RLHF가 중요)

| 모델 | Lab A | Lab B | Lab C | Lab D | 비고 |
|------|------:|------:|------:|------:|------|
| gpt-4o-mini | 📐 | 📐 | 📐 | 📐 | tool calling 특화 모델 |

**구현 방법:**
- `agents_netally/debate1.py`에서 Verifier/Synthesizer/Supporter/Skeptic 제거
- Collector가 도구 호출 → 바로 답변 생성 (1-agent pipeline)
- 또는 `run_netally_eval_direct.py`에서 graph 대신 단일 LLM+도구 호출

**실행 방법:**
```bash
cd NetAlly
# Lab별 데이터셋 경로 확인 후 실행
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabA_.../full_dataset_en.json \
  --lab Lab-A --model-tag "single-mcp" --single-agent-mode
# Lab B, C, D 반복
```

#### 실험 4: NetAlly (MAS+MCP) — 부분 완료

> 담당: **나**
> 코드: `agents_netally/` (현재 코드)
> 모델: gpt-4o-mini

| 모델 | Lab A | Lab B | Lab C | Lab D | 비고 |
|------|------:|------:|------:|------:|------|
| gpt-4o-mini | 📐 | **92.0 📊*** | 📐 | 📐 | *sampled 100문제 |

**실행 방법:**
```bash
cd NetAlly
# vLLM에서 gpt-4o-mini는 불가 → OpenRouter 사용
# 또는 vLLM에서 gpt-oss-20b로 대체 실행 후 OpenRouter로 gpt-4o-mini 실행

# Lab B 전체 (vLLM / OpenRouter)
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/Dataset/20260325_101536/full_dataset_en.json \
  --lab Lab-B --model-tag "netally-gpt4omini"

# Lab A, C, D 동일 (데이터셋 경로만 변경)
```

**주의: gpt-4o-mini는 폐쇄형 → vLLM 불가, OpenRouter 사용 필수**
- 전체 데이터셋(2000+문제) × OpenRouter = 비용 + 시간 고려
- 대안: gpt-oss-20b(vLLM)로 메인 실행 + gpt-4o-mini는 sampled로 비교

---

## Phase 2: 모델 Ablation (Table I 보충, Lab D only)

### 왜 Lab D만

- 가장 어려운 토폴로지 (Single LLM 최저 14-27%)
- 모델 차이가 극대화됨
- 쉬운 Lab은 다 비슷 → 차별성 없음
- 논문에 "hardest topology에서 ablation" → 리뷰어 납득

### 왜 이 실험이 필요한가

리뷰어 예상 질문:
- "왜 그 모델을 골랐나?"
- "다른 모델이면 어떤가?"
- "모델 크기가 중요한가?"

### 실험 2-A: 동일 모델 비교 (5회) 📐

> 담당: **나** (NetAlly MAS+MCP 프레임워크)
> 5개 에이전트 전부 같은 모델 사용

| # | 모델 | Params | Lab D | 서빙 방법 | 비고 |
|---|------|-------:|------:|----------|------|
| A-1 | gpt-4o-mini | 8B* | 📐 | OpenRouter | tool calling RLHF 특화 |
| A-2 | gpt-oss-20b | 20B | 📐 | OpenRouter or vLLM | LabB sampled: 87% 📊 |
| A-3 | Mistral3-8B | 8B | 📐 | vLLM | Single LLM best |
| A-4 | Qwen3-8B | 8B | 📐 | vLLM | 아시아권 다국어 |
| A-5 | Llama-3.1-8B | 8B | 📐 | vLLM | 메타 오픈소스 |

**실행 방법:**
```bash
cd NetAlly

# A-1: gpt-4o-mini (OpenRouter)
# .env: NETALLY_EXECUTOR_LLM_MODEL=openai/gpt-4o-mini
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabD_.../full_dataset_en.json \
  --lab Lab-D --model-tag "ablation-gpt4omini"

# A-2: gpt-oss-20b (OpenRouter)
# .env: NETALLY_EXECUTOR_LLM_MODEL=openai/gpt-oss-20b
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabD_.../full_dataset_en.json \
  --lab Lab-D --model-tag "ablation-oss20b"

# A-3~5: vLLM 서빙 모델 (Ubuntu PC)
# .env: NETALLY_EXECUTOR_LLM_BACKEND=vllm, VLLM_BASE_URL=http://100.67.63.77:8000/v1
# .env: NETALLY_EXECUTOR_LLM_MODEL=Mistral3-8B (또는 Qwen3-8B, Llama-3.1-8B)
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabD_.../full_dataset_en.json \
  --lab Lab-D --model-tag "ablation-mistral"
```

### 실험 2-B: 역할별 모델 분리 (3회) 📐

> 담당: **팀원** (agents_netally 코드에서 에이전트별 모델 지정)
> Baseline: 전부 Mistral3-8B, 한 역할만 gpt-4o-mini로 교체

에이전트 역할과 중요도:
- **Collector**: 도구 선택 + 데이터 수집 → tool calling 능력 필요 (가장 중요 예상)
- **Verifier**: 노이즈 제거 → 단순 필터링 (중요도 낮음)
- **Synthesizer**: 최종 답변 생성 → 추론 능력 필요
- **Supporter/Skeptic**: 답변 검증 + debate → 비판적 사고 필요

| # | Collector/Verifier | Synthesizer | Supporter/Skeptic | Lab D |
|---|:------------------:|:-----------:|:-----------------:|------:|
| B-0 | Mistral3-8B | Mistral3-8B | Mistral3-8B | 📐 (baseline) |
| B-1 | **gpt-4o-mini** | Mistral3-8B | Mistral3-8B | 📐 |
| B-2 | Mistral3-8B | **gpt-4o-mini** | Mistral3-8B | 📐 |
| B-3 | Mistral3-8B | Mistral3-8B | **gpt-4o-mini** | 📐 |

**구현 방법:**
- `agents_netally/model_loader.py`에서 에이전트별 모델 지정 기능 추가
- 또는 `debate1.py`에서 노드별 다른 LLM 객체 사용

**실행 방법:**
```bash
cd NetAlly
# B-0: baseline (전부 Mistral3-8B)
NETALLY_EXECUTOR_LLM_MODEL=Mistral3-8B \
.venv/bin/python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabD_.../full_dataset_en.json \
  --lab Lab-D --model-tag "role-baseline"

# B-1~3: 역할별 모델 교체 (구현 후)
# --collector-model gpt-4o-mini --other-model Mistral3-8B
```

---

## Phase 3: 분석 (실험 아님, 결과 해석)

### 논문에 포함할 분석 항목

| 분석 | 데이터 소스 | 논문 위치 | 교수님 피드백 |
|------|-----------|----------|-------------|
| 레벨별 breakdown (L1-L5) | Phase 1 전체 | Fig 2 (bar chart) | question_type 분류 ✓ |
| 도구 사용 패턴 | NetAlly eval 로그 | Fig 4 (stacked bar) | 정량적 분석 ✓ |
| 오답 정성 분석 | 오답 샘플링 | Section V-G | 정성적 분석 ✓ |
| 속도/토큰/비용 비교 | Phase 1 전체 | Table III | — |
| 모델 크기 vs 성능 | Phase 2-A | Fig 3 (bar+radar) | — |
| 에이전트 역할 민감도 | Phase 2-B | 본문 텍스트 | — |

---

## 전체 실험량 및 일정

| Phase | 실험 | 횟수 | 담당 | 서빙 | 예상 시간 |
|-------|------|-----:|------|------|----------|
| 1-1 | Single LLM × 5 models × 4 Labs | 20회 | ✅ 완료 | vLLM | — |
| 1-2 | Pure MAS × 1 model × 4 Labs | **4회** | 팀원 | vLLM | ~40시간 |
| 1-3 | Single+MCP × 1 model × 4 Labs | **4회** | 나 | OpenRouter | ~10시간 |
| 1-4 | NetAlly × 1 model × 4 Labs | **4회** | 나 | OpenRouter | ~10시간 |
| 2-A | NetAlly × 5 models × Lab D | **5회** | 나 | vLLM+OpenRouter | ~15시간 |
| 2-B | NetAlly 역할분리 × 3 조합 × Lab D | **3회** | 팀원 | vLLM+OpenRouter | ~9시간 |
| | **총** | **~40회** | | | |

### 실행 우선순위

```
1순위: Phase 1-4 NetAlly Lab B 전체 데이터셋    ← 메인 결과 확정
2순위: Phase 1-3 Single+MCP 구현 + Lab B        ← MCP 기여 분리
3순위: Phase 1-4 NetAlly Lab A, C, D            ← 메인 테이블 완성
4순위: Phase 1-3 Single+MCP Lab A, C, D         ← 메인 테이블 완성
5순위: Phase 2-A 모델 ablation Lab D            ← ablation
6순위: Phase 2-B 역할 분리 Lab D                ← ablation (팀원)
```

---

## 현재 진행 상태

### ✅ 완료

- [x] Single LLM × 5 models × 4 Labs (전체 데이터셋)
- [x] NetAlly (MAS+MCP) LabB sampled 100문제
  - gpt-4o-mini: L1=85, L2=100, L3=80, L4=95, L5=95 → **92%**
  - gpt-oss-20b: 정규화 후 **87%**
- [x] TA-Acc scorer 정규화 (한국어, alias, 대소문자)
- [x] 대규모 평가 안정성 (per-question timeout 300s, hard shutdown)
- [x] Batfish 스냅샷/포트 문제 해결
- [x] experiment_tables_draft.md (Table 3 + Fig 4 구성)

### 📐 다음 단계

1. [ ] Ubuntu PC vLLM 서버 시작 (Mistral3-8B)
2. [ ] NetAlly (MAS+MCP) Lab B 전체 데이터셋 (gpt-4o-mini, OpenRouter)
3. [ ] Single+MCP 구현 (Collector만 + 도구, debate 없음)
4. [ ] Single+MCP Lab B 전체 데이터셋
5. [ ] NetAlly Lab A, C, D 전체 데이터셋
6. [ ] Single+MCP Lab A, C, D 전체 데이터셋
7. [ ] Phase 2 모델 ablation (Lab D)

### ⚠️ 결정 필요 사항

1. **gpt-4o-mini 전체 데이터셋 비용**: 2000문제 × OpenRouter ≈ $50-100. 허용 가능한가?
   - 대안: gpt-oss-20b(vLLM, 무료)로 메인 + gpt-4o-mini sampled로 비교
2. **Pure MAS 모델**: Mistral3-8B (Single LLM best)로 확정? 아니면 다른 모델?
3. **데이터셋 경로**: Lab A, C, D 전체 데이터셋 경로 확인 필요
