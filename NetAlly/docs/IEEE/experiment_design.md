# IEEE TNMS 논문 실험 설계서

> **목적**: 논문에 포함될 모든 실험의 상세 설계, 기대 결과, 비교 방법, 결과 테이블 형식을 사전 정의
> **논문 Section**: IV. Experiments → V. Results → VI. Discussion
> **최종 업데이트**: 2026-03-02

---

## 실험 전체 설계

### 실험 매트릭스 — 총 5개 실험 (재구성)

```
┌─────────────────────────────────────────────────────────────────┐
│                    IEEE TNMS 실험 체계                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Exp.1               Exp.2               Exp.3                  │
│  ┌──────────┐       ┌──────────┐        ┌──────────┐           │
│  │Dataset   │       │Single LLM│        │Scalab-   │           │
│  │Validation│       │Baseline  │        │ility     │           │
│  │(3-Layer) │       │(7 Models)│        │(A→B→C→D) │           │
│  └──────────┘       └──────────┘        └──────────┘           │
│       ↓                  ↓                   ↓                  │
│  "데이터 신뢰성"    "LLM 혼자의 한계"   "파이프라인 범용성"      │
│                                                                 │
│  Exp.4               Exp.5                                      │
│  ┌──────────────┐   ┌──────────────┐                            │
│  │Pure MAS      │   │NetAlly MAS   │                            │
│  │(도구 없음)   │   │(Batfish+NSO) │                            │
│  │LLM×N만       │   │              │                            │
│  └──────────────┘   └──────────────┘                            │
│       ↓                   ↓                                     │
│  "구조만의 효과"     "도구가 한계를 극복"                        │
│                                                                 │
│  ★ 핵심 비교: Exp.2 → Exp.4 → Exp.5                            │
│    Single LLM → Pure MAS → NetAlly                              │
│    (구조 효과 분리)  (도구 효과 분리)                            │
└─────────────────────────────────────────────────────────────────┘
```

### 논문 핵심 스토리라인

```
"LLM 혼자는 L4/L5에서 구조적으로 실패한다" (Exp.2)
    → "Multi-Agent 구조만으로는 해결 불가" (Exp.4)
    → "도구(Batfish)가 핵심이다" (Exp.5)
    → "이 파이프라인은 40노드까지 확장 가능하다" (Exp.3)
```

---

## 실행 리베이스 (2026-03-02 갱신)

| 구분 | 실험 | 제출 필수 여부 | 실행 기준 | 상태 |
|---|---|:---:|---|:---:|
| Core | Exp.1 Dataset Validation | ✅ 필수 | 3-Method Hybrid 완료 | ✅ Method 1-2 완료 |
| Core | Exp.2 Single LLM Baseline | ✅ 필수 | 7모델 × Lab-A | ⬜ 실험 필요 |
| Core | Exp.3 Scalability | ✅ 필수 | **Lab A→B→C→D 전부 데이터 완료** | ✅ 데이터 준비 완료 |
| Core | Exp.4 Pure MAS (도구 없음) | ✅ 필수 | Lab-A, 2모델 | ⬜ 실험 필요 |
| Core | Exp.5 NetAlly MAS | ✅ 필수 | Lab-A, 2모델 | ⬜ 실험 필요 |
| Sub | Exp.5b Tool Ablation | 🟡 권장 | Batfish only / NSO only / Full | ⬜ 옵션 |
| External | Exp.6 External Benchmark | ⚠️ 선택 | NIKA 우선 1개 | ⬜ 선택 |

### Scope Freeze

1. 데이터셋: **Lab-A 1,264 QA (L1~L5)** 기준으로 Exp.2/4/5 실행
2. L6는 이번 논문에서는 **제외** (코드 보존, 결과/표/평가 미포함)
3. Scalability(Exp.3)는 단일 Best 모델 + NetAlly 2가지로 비교

---

## 실험 실행 순서

```
Step 1: Exp.2 Single LLM (7모델) 실행
            ↓
        L4/L5 랭킹 확인 → MAS 백본 2개 선정
            ↓
Step 2: Exp.4 Pure MAS (선정된 2모델)
Step 3: Exp.5 NetAlly MAS (동일 2모델)
            ↓
        3-way 비교 테이블 완성
            ↓
Step 4: Exp.3 Scalability (Best 모델 1개 × A→D)
```

---

## Experiment 1: Dataset Validation (3-Method Hybrid 검증)

### 목적

> NetConfigQA2.0의 Ground Truth가 신뢰할 수 있음을 입증

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 (Lab-A: 1,264 QA, L1~L5) |
| 토폴로지 | LabA_Research_Institute_DC_10nodes (10 nodes) |
| Method 1 | Batfish-free Independent Parser (L1-L3 전수 800건) |
| Method 2 | Stratified Sampling + 자동 교차검증 + 사람 검토 (43건) |
| Method 3 | PNETLab 실환경 CLI 검증 (L4 23건 + L5 21건) |

### 검증 전략 — Circular Reasoning 방어

```
Batfish로 생성한 정답 → Batfish로 재검증 = 순환 논증 (학회 거절 사유)
                ↓ 해결
Method 1: Batfish-free Parser (Python+Regex) — 독립 엔진으로 검증
Method 2: 사람이 .cfg 원본을 직접 트레이스 — 수동 로직 검증
Method 3: PNETLab 실장비 CLI 실행 — 실환경 검증
```

### 실행 결과

**Table 1: Dataset Verification Results**

| Method | Approach | Scope | Agreement (%) | Status |
|:---:|---|:---:|:---:|:---:|
| Method 1 | Independent Config Parser | 800 (L1-L3 전수) | **99.5%** (실질 100%) | ✅ 완료 |
| Method 2 | Stratified Sampling + Manual | 43 (L1-L3 표본) | **97.7%** (42/43) | ✅ 자동 완료, ⬜ 사람 검토 대기 |
| Method 3 | PNETLab Real CLI | 44 (L4: 23, L5: 21) | — | ⬜ 사람 실행 대기 |

**Table 1-B: Method 1 — Answer Type별 Agreement**

| Answer Type | Total | Agree | Disagree | Agreement |
|---|:---:|:---:|:---:|:---:|
| number | 356 | 354 | 2 | 99.4% |
| set | 232 | 232 | 0 | 100% |
| text | 96 | 96 | 0 | 100% |
| map_str_int | 30 | 30 | 0 | 100% |
| map | 20 | 20 | 0 | 100% |
| edge_set | 16 | 16 | 0 | 100% |
| boolean | 50 | 50 | 0 | 100% |

> 4건 불일치 모두 Batfish VRF 이중 카운팅 아티팩트 → 독립 파서가 더 정확 → 실질 100%

---

## Experiment 2: Single LLM Baseline

### 목적

> LLM 단독으로 네트워크 설정을 해석할 때의 성능 한계를 계량적으로 입증

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 Lab-A (1,264 QA, L1~L5) |
| 평가 지표 | TA-Acc (Type-Aware Accuracy) + **Format Stability Metrics** |
| 프롬프트 | Zero-shot, 전체 설정 파일 제공 |
| 반복 | 3회 (평균 ± 표준편차) |

### 추가 지표: Format Stability Metrics

TA-Acc만으로는 "모델이 답을 모르는 것"과 "답을 알지만 포맷을 못 맞추는 것"을 구분할 수 없음.
Exp.2 로그에서 아래 2개 지표를 추가 측정하여, MAS Executor 적합성 판단 근거로 활용.

**측정 방법**: LLM 원본 출력을 answer_type별 파서에 통과시켜 사후 집계 (추가 실험 불필요)

| answer_type | Parse Success 기준 | Completeness 기준 |
|---|---|---|
| `scalar_str/int` | 단일 값 토큰 추출 가능 | — (스칼라) |
| `bool` | yes/no/true/false 식별 가능 | — |
| `set_str` | 쉼표/줄바꿈 구분 리스트 파싱 가능 | 기대 원소 수 대비 추출 비율 |
| `map_str_int` | key:value 쌍 파싱 가능 | 기대 키 수 대비 추출 비율 |
| `path` | 노드 시퀀스(→ 구분자) 파싱 가능 | 기대 홉 수 대비 추출 비율 |

**Table 3-B (목표): Format Stability — Parse Success Rate per Model**

| Model | scalar | bool | set | map | path | Overall Parse % |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | ? | ? | ? | ? | ? | ? |
| ... | ... | ... | ... | ... | ... | ... |

> **활용**: TA-Acc가 유사한 모델 간에도 형식 안정성 차이가 있음을 보여줌
> → "MAS Executor로는 형식 안정성이 높은 모델이 유리" 라는 발견 도출 가능

### 모델 선정 (6개) — Ollama 서빙 확정

| # | 모델 | Ollama 태그 | 벤더 | 양자화 | VRAM | Context | 선정 이유 |
|---|---|---|---|---|:---:|:---:|---|
| 1 | GPT-4o-mini | (OpenAI API) | OpenAI | — | — | 128K | 유일한 API 모델, 업계 기준선 |
| 2 | GPT-OSS-20B | `gpt-oss:20b` | OpenAI | MXFP4 (native) | 14GB | — | KICS Best, 비교 앵커 |
| 3 | Qwen3-Coder | `qwen3-coder:30b-a3b-q4_K_M` | Alibaba | Q4_K_M | 19GB | **256K** | 코딩+Agent 특화, 30B/3.3B active MoE |
| 4 | Gemma-3-27B | `gemma3:27b-it-q4_K_M` | Google | Q4_K_M | 17GB | 128K | 범용 대형, 벤더 다양성 |
| 5 | GLM-4.7-Flash | `glm-4.7-flash:q4_K_M` | Zhipu | Q4_K_M | 19GB | **198K** | 범용 MoE, 도구호출 강점 |
| 6 | Qwen3.5-27B | `qwen3.5:27b` | Alibaba | Q4_K_M | 17GB | **262K** | 최신 로컬 SOTA |

> **벤더 4곳**: OpenAI(2) / Alibaba(2) / Google(1) / Zhipu(1)
> **서빙**: API 1개 (GPT-4o-mini) + Ollama 5개 (순차 실행, RTX 3090 24GB)
> **Context 검증**: Lab-D (40노드) 전체 = ~25,000 토큰 → 6개 모델 전부 여유 (최소 128K)
>
> **Qwen3-Coder vs GLM-4.7-Flash**: 둘 다 MoE/3B-active이지만 "코딩Agent특화 vs 범용"
> → "코딩 특화 모델이 네트워크 config 해석에서도 우위를 보이는가?" 연구 질문

### 서빙 환경 및 재현성 설정

**Ollama 버전**: `>= 0.14.3` (GLM-4.7-Flash 지원에 필요, pre-release)

**평가 전용 Modelfile (재현성 확보)**:
```
# 평가 파라미터 (run_eval.py Config 클래스에서 관리)
temperature = 0
num_ctx = 49,152      # Lab-D 31K input 토큰 커버
MAX_OUTPUT_TOKENS = 70,000  # reasoning 모델의 내부 추론 토큰 포함
```
> `num_ctx=49,152`: Lab-D(40노드) 전체 config = ~31K 토큰 + 시스템 프롬프트 + 출력 여유
> `MAX_OUTPUT_TOKENS=70,000`: GPT-OSS-20B 등 reasoning 모델이 내부 추론에 최대 ~19K 토큰 사용 관찰 → 넉넉히 설정
> 모델별 기본 컨텍스트(128K~262K)가 다르므로, **공정 비교를 위해 num_ctx 통일**
> Ollama native API (`/api/chat`) 사용 — OpenAI 호환 API는 num_ctx 전달 불가

**모델별 eval 래퍼 생성 예시**:
```bash
# Modelfile.gemma3-eval
FROM gemma3:27b-it-q4_K_M
PARAMETER temperature 0
PARAMETER top_p 1
PARAMETER num_ctx 32768

# 생성
ollama create gemma3-eval -f Modelfile.gemma3-eval
# 사용
ollama run gemma3-eval
```

**Ollama 모델 다운로드 명령어**:
```bash
ollama pull gpt-oss:20b
ollama pull qwen3-coder:30b-a3b-q4_K_M
ollama pull gemma3:27b-it-q4_K_M
ollama pull glm-4.7-flash:q4_K_M          # Ollama >= 0.14.3 필요
ollama pull qwen3.5:27b
```

### KICS 2026 참조 결과 (10노드, v1 762 QA)

**Table 2: KICS Baseline (참조용 — 모델/데이터 변경으로 직접 비교 불가)**

| Model | L1 | L2 | L3 | L4 | L5 |
|---|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | 0.765 | 0.541 | 0.369 | 0.267 | 0.159 |
| GPT-OSS-20B | **0.873** | **0.873** | **0.605** | **0.266** | 0.134 |

> KICS에서 사용했던 Llama-3.1-8B, Mistral3-8B, Qwen3-8B는 최신 모델로 교체됨

**Table 3 (목표): Single LLM TA-Acc — 6 Models × 4 Labs**

| Model | Lab-A (10) | Lab-B (20) | Lab-C (30) | Lab-D (40) |
|---|:---:|:---:|:---:|:---:|
| GPT-4o-mini | ? | ? | ? | ? |
| GPT-OSS-20B | ? | ? | ? | ? |
| Qwen3-Coder-Next | ? | ? | ? | ? |
| Gemma-3-12B | ? | ? | ? | ? |
| GLM-4.7-Flash | ? | ? | ? | ? |
| Qwen3.5-27B | ? | ? | ? | ? |

> 가로: Scalability (규모 증가에 따른 성능 변화)
> 세로: Model Comparison (모델 간 성능 비교)
> Exp.2와 Exp.3을 하나의 테이블로 통합

### 핵심 관찰 (KICS 기반 예상)

1. **L4 절벽**: 모든 모델이 L3→L4에서 급격한 성능 하락 (평균 0.45 → 0.20)
2. **L5 바닥**: 최고 모델도 0.2 이하 — 사실상 시뮬레이션 불가
3. **BERTScore 무용**: 모든 레벨에서 0.9+ → 변별력 완전 부재 → TA-Acc 정당성

### MAS 백본 선정 규칙

> **규칙: Exp.2의 Overall TA-Acc Top-1 오픈소스 모델을 Exp.4/5 백본으로 사용한다.**

- Overall Top-1을 선택하는 이유: 특정 레벨에 가중치를 두면 cherry-picking 비판이 생김
- 오픈소스 단독으로 가는 이유: "오픈소스 로컬 모델 + Agent + 도구 = API 모델 단독 수준 도달?" 이라는 연구 질문에 부합
- GPT-4o-mini / GPT-OSS-20B는 Exp.2 참조선(reference)으로만 사용, Exp.4/5에는 불포함

```
Exp.2 결과 → Overall TA-Acc 랭킹
  → Top-1 오픈소스 모델 선택 (예: Qwen3.5-27B 또는 GLM-4.7-Flash)
  → 동일 모델로 Single(Exp.2) / Pure MAS(Exp.4) / NetAlly(Exp.5) 3-way 비교
  → 유일한 변수 = "구조" 와 "도구"
```

---

## Experiment 3: Scalability Analysis

### 목적

> 동일 파이프라인으로 네트워크 규모(10→40노드)에 따른 QA 생성과 LLM 성능 변화를 관찰

### 데이터셋 현황 (✅ 전부 생성 완료, 2026-03-02)

| Lab | Nodes | QA Count | Level Distribution | Domain |
|---|:---:|:---:|---|---|
| Lab-A | 10 | **1,264** | L1:660 L2:104 L3:252 L4:146 L5:102 | SP MPLS VPN |
| Lab-B | 20 | **2,154** | L1:1230 L2:101 L3:255 L4:441 L5:127 | SP Extended |
| Lab-C | 30 | **2,673** | L1:1230 L2:80 L3:255 L4:954 L5:154 | Security + L2VPN |
| Lab-D | 40 | **3,371** | L1:1230 L2:69 L3:253 L4:1657 L5:162 | Multi-AS Complex |

### 결과 테이블 형식

**Table 4: Scalability — Single LLM (Best Model)**

| Level | 10 nodes | 20 nodes | 30 nodes | 40 nodes | Degradation |
|:---:|:---:|:---:|:---:|:---:|:---:|
| L1 | ? | ? | ? | ? | ? |
| L2 | ? | ? | ? | ? | ? |
| L3 | ? | ? | ? | ? | ? |
| L4 | ? | ? | ? | ? | ? |
| L5 | ? | ? | ? | ? | ? |

**Table 5: Pipeline Scalability — QA Generation**

| Lab | Nodes | Config Files | Total QA | QA/Node |
|---|:---:|:---:|:---:|:---:|
| Lab-A | 10 | 10 | **1,264** | **126** |
| Lab-B | 20 | 20 | **2,154** | **108** |
| Lab-C | 30 | 30 | **2,673** | **89** |
| Lab-D | 40 | 40 | **3,371** | **84** |

> "QA/Node 비율이 일정(84~126) → 파이프라인이 선형적으로 확장됨을 입증"
> "동일 policies.json으로 토폴로지만 교체하면 메트릭 커버리지 52% → 97%로 자동 확장"

---

## Experiment 4: Pure MAS Evaluation (도구 없음) ⭐ 신규

### 목적

> Multi-Agent 구조 자체의 효과를 도구 효과와 분리하여 측정
> "구조만으로는 L4/L5 한계를 극복할 수 없다"는 것을 입증

### 설계 원칙

```
Single LLM (Exp.2)    →    Pure MAS (Exp.4)    →    NetAlly (Exp.5)
─────────────────          ─────────────────          ─────────────────
LLM 1개                    Orchestrator LLM           Orchestrator LLM
+ config 파일 전체          + Executor LLM             + Executor LLM
                            (도구 없음)                + Batfish / NSO

비교 목적:                  Exp.2 → Exp.4:            Exp.4 → Exp.5:
                            구조의 효과 측정           도구의 효과 측정
```

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 Lab-A (1,264 QA, L1~L5) |
| 모델 | Exp.2 결과 기반 선정된 2개 (API 1 + Local Best 1) |
| 구조 | Orchestrator LLM (질문 분해) + Executor LLM (답변 생성) |
| 도구 | **없음** — config 파일 텍스트만 참조 |
| 평가 지표 | TA-Acc per Level |

### Pure MAS 구조

```
[질문] → Orchestrator LLM
              ↓ (질문 분해, 필요 정보 파악)
         "PE1의 Loopback0 IP를 찾아라"
         "P1-P2 링크가 다운되면..."
              ↓
         Executor LLM
              ↓ (config 파일 텍스트 검색 + 답변)
         [답변 반환]
              ↓
         Orchestrator LLM
              ↓ (최종 답변 통합)
         [최종 답변]
```

> L4/L5에서 Executor가 "config 텍스트로는 traceroute 결과를 알 수 없음" → 실패 예상

### 기대 결과

**Table 6 (목표): Pure MAS vs Single LLM**

| Level | Single LLM | Pure MAS | Δ (구조 효과) | 해석 |
|:---:|:---:|:---:|:---:|---|
| L1 | ~0.85 | ~0.88 | +0.03 | 질문 분해로 소폭 향상 |
| L2 | ~0.85 | ~0.87 | +0.02 | 집계 질문 분해 도움 |
| L3 | ~0.60 | ~0.63 | +0.03 | 정합성 검증 소폭 향상 |
| L4 | ~0.25 | ~0.27 | **+0.02** | **구조만으로는 무의미** |
| L5 | ~0.15 | ~0.16 | **+0.01** | **시뮬레이션 불가 → 실패** |

> **핵심 메시지**: L4/L5에서 Pure MAS ≈ Single LLM → 구조가 아니라 도구가 핵심

---

## Experiment 5: NetAlly MAS Evaluation ⭐ 핵심

### 목적

> 도구를 가진 NetAlly가 Pure MAS의 L4/L5 한계를 극복할 수 있는가?
> "Batfish 도구 호출이 성능 향상의 원천임"을 입증

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 Lab-A (1,264 QA, L1~L5) |
| 시스템 | NetAlly (Orchestrator + Executor + Batfish/NSO/PNETLab) |
| 모델 | Exp.2와 동일 2개 (공정 비교) |
| 평가 지표 | TA-Acc, 도구 호출 성공률, 응답 시간 |

### 핵심 비교 테이블 (논문 메인 테이블)

**Table 7: 3-Way Comparison — Single LLM vs Pure MAS vs NetAlly**

| Level | Single LLM | Pure MAS | **NetAlly** | Δ(구조) | **Δ(도구)** |
|:---:|:---:|:---:|:---:|:---:|:---:|
| L1 | ~0.85 | ~0.88 | ~0.95 | +0.03 | +0.07 |
| L2 | ~0.85 | ~0.87 | ~0.95 | +0.02 | +0.08 |
| L3 | ~0.60 | ~0.63 | ~0.85 | +0.03 | +0.22 |
| **L4** | **~0.25** | **~0.27** | **~0.75** | +0.02 | **+0.48 ★** |
| **L5** | **~0.15** | **~0.16** | **~0.60** | +0.01 | **+0.44 ★** |

> L4/L5에서 Δ(도구) >> Δ(구조) → "Multi-Agent 구조보다 도구 접근이 핵심"

### 도구별 기여 분석

**Table 8: NetAlly Tool Usage Analysis**

| Level | Primary Tool | Success Rate | Avg. Latency |
|:---:|---|:---:|:---:|
| L1 | NSO / Config Parser | ? | ? |
| L2 | NSO + Aggregation Logic | ? | ? |
| L3 | Batfish + Cross-check | ? | ? |
| L4 | **Batfish traceroute** | ? | ? |
| L5 | **Batfish fork_snapshot** | ? | ? |

### (옵션) Exp.5b: Tool Ablation

| 설정 | 사용 도구 | 목적 |
|---|---|---|
| Batfish only | Batfish만 | L4/L5에서 Batfish 단독 기여 측정 |
| NSO only | NSO만 | L1-L3에서 NSO 기여 측정 |
| Full NetAlly | Batfish + NSO | 전체 시스템 |

---

## Error Analysis (Discussion 섹션)

> 추가 실험 불필요 — Exp.2 결과 데이터에서 추출

**분류 기준 (L4/L5 실패 사례 30건 이상)**

| 오류 유형 | 예상 비율 | 원인 |
|---|:---:|---|
| Data plane 시뮬레이션 불가 | ~50% | LLM은 traceroute를 텍스트로 추론 불가 |
| Multi-hop 경로 추론 실패 | ~25% | 4+ 홉 경로에서 중간 노드 누락 |
| Context window 초과 | ~15% | 40노드 config 파일 길이 → L4/L5 답변 퇴화 |
| 답변 형식 오류 | ~10% | path/set 타입 포매팅 실패 |

> **핵심 주장**: "L4/L5 실패는 프롬프트 전략으로 해결 불가 — 근본적으로 데이터 플레인 시뮬레이션 엔진이 필요"

---

## 논문 핵심 주장 3가지

1. **"LLM은 L4/L5에서 구조적으로 실패한다"**
   - 근거: Exp.2 (Table 3) — 7개 모델 모두 L4 ≤ 0.3
   - 원인: Data plane 시뮬레이션 불가, Context overflow

2. **"Multi-Agent 구조만으로는 이 한계를 극복할 수 없다"**
   - 근거: Exp.4 (Table 6) — Pure MAS ≈ Single LLM at L4/L5
   - 의미: 구조가 아니라 도구가 핵심임을 역설적으로 입증

3. **"Batfish 도구를 가진 NetAlly가 이 한계를 극복한다"**
   - 근거: Exp.5 (Table 7) — NetAlly L4 ~0.75+, L5 ~0.60+
   - 의미: 도구 활용형 MAS의 실용적 가치 입증

---

## 논문 내 Table 목록

| Table # | 내용 | Section | 상태 |
|:---:|---|---|:---:|
| Table I | Dataset Statistics (Lab별 × Level × Category) | III-B | ✅ 데이터 있음 |
| Table II | Dataset Verification Results (3-Method Hybrid) | III-C | ✅ Method 1-2 완료 |
| Table III | Single LLM Baseline — 7모델 TA-Acc | IV-A | ⬜ 실험 필요 |
| Table IV | Scalability — QA Pipeline (QA/Node 비율) | IV-B | ✅ 계산 완료 |
| Table V | Scalability — LLM 성능 vs 노드 수 | IV-B | ⬜ Exp.3 필요 |
| Table VI | Pure MAS vs Single LLM | IV-C | ⬜ Exp.4 필요 |
| Table VII | **3-Way: Single / Pure MAS / NetAlly** ⭐ | IV-D | ⬜ Exp.4/5 필요 |
| Table VIII | NetAlly Tool Usage Analysis | IV-D | ⬜ Exp.5 필요 |
| Table IX | Related Work Comparison | II | ✅ research_notes.md 완료 |

---

## 논문 내 Figure 목록

| Figure # | 내용 | 유형 |
|:---:|---|---|
| Fig. 1 | System Architecture (NetAlly + NetConfigQA2.0 파이프라인) | Diagram |
| Fig. 2 | QA Generation Pipeline (Dual-Path) | Flowchart |
| Fig. 3 | TA-Acc vs Difficulty Level (7모델 비교) | Bar Chart |
| Fig. 4 | **3-Way: Single / Pure MAS / NetAlly (L1~L5)** ⭐ | Grouped Bar |
| Fig. 5 | Scalability: TA-Acc vs Node Count | Line Chart |
| Fig. 6 | Error Analysis — L4/L5 실패 유형 분류 | Pie/Bar |

---

## Threats to Validity

| 위협 | 대응 |
|---|---|
| 단일 벤더 (Cisco IOS) | 명시적 한계로 기술 + Future Work |
| Batfish Ground Truth 순환 | **3-Method Hybrid**: Method 1 Independent Parser (99.5%), Method 2 Manual (97.7%), Method 3 PNETLab (대기) |
| NetAlly unfair advantage | Exp.4 Pure MAS로 도구 효과 분리 측정 — "도구가 핵심"임을 정량화 |
| 소규모 토폴로지 | Exp.3 Scalability (10→40노드) + QA/Node 선형성 입증 |
| 단일 언어 (한국어) | KO/EN 이중언어 데이터셋 생성 완료, 정답은 언어 중립 토큰 |
