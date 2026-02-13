# IEEE TNMS 논문 실험 설계서

> **목적**: 논문에 포함될 모든 실험의 상세 설계, 기대 결과, 비교 방법, 결과 테이블 형식을 사전 정의  
> **논문 Section**: IV. Experiments → V. Results → VI. Discussion

---

## 실험 전체 설계

### 실험 매트릭스 — 총 5개 실험

```
┌─────────────────────────────────────────────────────────────────┐
│                    IEEE TNMS 실험 체계                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Exp.1                  Exp.2              Exp.3                │
│  ┌──────────┐          ┌──────────┐       ┌──────────┐         │
│  │Dataset   │          │Single LLM│       │NetAlly   │         │
│  │Validation│          │Baseline  │       │MAS Eval  │         │
│  │(3-Layer) │          │(5 Models)│       │          │         │
│  └──────────┘          └────┬─────┘       └────┬─────┘         │
│       │                     │                   │               │
│       ▼                     ▼                   ▼               │
│  "Ground Truth"       "LLM의 한계"         "Agent의 효과"      │
│                                                                 │
│  Exp.4                  Exp.5                                   │
│  ┌──────────┐          ┌──────────────┐                         │
│  │Scalab-   │          │External      │                         │
│  │ility     │          │Benchmarks    │                         │
│  │(10→50)   │          │(NIKA+NetPress│                         │
│  │          │          │+NetConfEval) │                         │
│  └──────────┘          └──────────────┘                         │
│       ▼                     ▼                                   │
│  "파이프라인 범용성"    "Agent 일반화 능력"                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 실행 리베이스 (2026-02-13)

리스크 감사 결과를 반영해, 제출 직전 범위를 아래처럼 고정합니다.

| 구분 | 실험 | 제출 필수 여부 | 실행 기준 |
|---|---|:---:|---|
| Core | Exp.1 Dataset Validation | ✅ 필수 | L1~L5 기준 3-Layer 완료 |
| Core | Exp.2 Single LLM Baseline | ✅ 필수 | v2(1,128) 재실험 완료 |
| Core | Exp.3 NetAlly MAS Eval | ✅ 필수 | Lab-A 기준 비교표 완성 |
| Scale | Exp.4 Scalability | ✅ 최소 필수 | **Lab-B(20노드) 단일 증거** 확보 |
| External | Exp.5 External Benchmark | ⚠️ 선택 | **NIKA 우선 1개** |

### Scope Freeze

1. 제출 본문 데이터셋 범위는 **v2 공개본 L1~L5 (1,128)**로 고정
2. L6는 이번 논문에서는 **제외** (코드는 보존하되 결과/표/평가에 미포함)
   - 사유: fault별 snapshot/context 동시 관리 필요, single-LLM baseline 공정성 저하, 일정 내 재현성 확보 어려움
3. Lab-C/Lab-D, NetPress/NetConfEval은 잔여 시간 기반으로 선택

---

## Experiment 1: Dataset Validation (3-Layer 검증)

### 목적

> NetConfigQA2.0의 Ground Truth가 신뢰할 수 있음을 입증

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 v2 (1,128 QA, L1~L5) |
| 토폴로지 | Research_Institute_Internal_DC (10 nodes) |
| Layer 1 | Batfish 재실행 (전수 1,128건) |
| Layer 2 | PNETLab 실환경 비교 (L4 30건 + L5 20건) |
| Layer 3 | GPT-4o LLM-as-Judge (레벨별 20건 × 5 = 100건) |

### 결과 테이블 형식

**Table 1: Dataset Verification Results**

| Verification Layer | Method | Scope | Agreement (%) | Notes |
|:---:|---|:---:|:---:|---|
| Layer 1 | Batfish Re-execution | 1,128 (all) | ? | Internal Consistency |
| Layer 2a | PNETLab Traceroute | 30 (L4) | ? | Simulation ↔ Real |
| Layer 2b | PNETLab Link Failure | 20 (L5) | ? | What-If Accuracy |
| Layer 3 | LLM-as-Judge | 100 | ?/5 avg | Quality Assessment |

**Table 2: LLM-as-Judge Detailed Scores**

| Criterion | L1 | L2 | L3 | L4 | L5 | Overall |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Clarity | ? | ? | ? | ? | ? | ? |
| Correctness | ? | ? | ? | ? | ? | ? |
| Level Appropriateness | ? | ? | ? | ? | ? | ? |
| Educational Value | ? | ? | ? | ? | ? | ? |

---

## Experiment 2: Single LLM Baseline (KICS 확장)

### 목적

> LLM의 네트워크 설정 이해 한계를 계량적으로 입증 (특히 L4/L5)

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 v2 (1,128 QA, L1~L5) |
| 모델 | GPT-4o-mini, GPT-OSS-20B, Llama-3.1-8B, Mistral3-8B, Qwen3-8B |
| 평가 지표 | TA-Acc (Type-Aware Accuracy) |
| 프롬프트 | Zero-shot, 전체 설정 파일 제공 |
| 반복 | 3회 (평균 ± 표준편차) |

### KICS 2026 기존 결과 (10노드)

**Table 3: Single LLM Performance (TA-Acc) — Baseline**

| Model | L1 | L2 | L3 | L4 | L5 | Overall |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | 0.806 | 0.806 | 0.494 | 0.211 | 0.141 | 0.611 |
| GPT-OSS-20B | **0.873** | **0.873** | **0.605** | **0.266** | 0.134 | **0.672** |
| Llama-3.1-8B | 0.530 | 0.443 | 0.261 | 0.144 | 0.102 | 0.387 |
| Mistral3-8B | 0.663 | 0.557 | 0.389 | 0.174 | 0.134 | 0.477 |
| Qwen3-8B | 0.746 | 0.741 | 0.485 | 0.201 | **0.157** | 0.560 |

### 핵심 관찰

1. **L4 절벽**: 모든 모델이 L3→L4에서 급격한 성능 하락 (평균 0.45 → 0.20)
2. **L5 바닥**: 최고 모델도 0.157 — 사실상 랜덤 수준
3. **규모 효과**: L1-L3는 모델 크기가 클수록 유리, L4-L5에서는 크기 무관하게 실패
4. **BERTScore 무용**: 모든 레벨에서 0.9+ → 변별력 완전 부재

### 추가 실험 (IEEE TNMS)

- **v2 데이터셋** (1,128건)으로 재실험 → 동일 트렌드 확인
- **GPT-4o** 추가 실험 → 최대 모델도 L4/L5 실패 확인

---

## Experiment 3: NetAlly MAS Evaluation ⭐ 핵심

### 목적

> NetAlly(Multi-Agent + 도구)가 Single LLM의 L4/L5 한계를 극복할 수 있는가?

### 설정

| 항목 | 값 |
|---|---|
| 데이터셋 | NetConfigQA2.0 v2 (1,128 QA, L1~L5) |
| 시스템 | NetAlly (Orchestrator + Executor + Batfish/NSO/PNETLab) |
| 비교 대상 | Best Single LLM (GPT-OSS-20B) |
| 평가 지표 | TA-Acc, 도구 호출 성공률, 응답 시간 |
| 토폴로지 | Research_Institute_Internal_DC (10 nodes) |

### 기대 결과

**Table 4: NetAlly vs Best Single LLM**

| Level | Single LLM (GPT-OSS-20B) | NetAlly | Δ | p-value |
|:---:|:---:|:---:|:---:|:---:|
| L1 | 0.873 | 0.95+ | +0.08 | ? |
| L2 | 0.873 | 0.95+ | +0.08 | ? |
| L3 | 0.605 | 0.85+ | +0.25 | ? |
| L4 | 0.266 | **0.75+** ⭐ | **+0.48** | ? |
| L5 | 0.134 | **0.60+** ⭐ | **+0.47** | ? |
| Overall | 0.672 | 0.85+ | +0.18 | ? |

### 세부 분석 테이블

**Table 5: NetAlly Tool Usage Analysis**

| Level | Query Type | Primary Tool | Tool Call Success Rate | Avg. Response Time |
|:---:|---|---|:---:|:---:|
| L1 | Config Lookup | NSO / Parser | ? | ? |
| L2 | Aggregation | NSO + Logic | ? | ? |
| L3 | Cross-Check | Batfish + Logic | ? | ? |
| L4 | Reachability | **Batfish traceroute** | ? | ? |
| L5 | What-If | **Batfish fork_snapshot** | ? | ? |

**Table 6: Error Analysis — Where NetAlly Still Fails**

| Error Type | Count | Example | Root Cause |
|---|:---:|---|---|
| Tool Selection Error | ? | L4 질문에 NSO 호출 | Orchestrator 판단 오류 |
| Tool Execution Error | ? | Batfish 쿼리 파라미터 오류 | Executor 구문 생성 실패 |
| Answer Formatting Error | ? | 정답 추출 실패 | 출력 파싱 문제 |
| Genuine Reasoning Error | ? | 복합 경로 추론 실패 | LLM 추론 한계 |

---

## Experiment 4: Scalability Analysis

### 목적

> 네트워크 규모 증가에 따른 LLM과 NetAlly의 성능 변화를 관찰

### 설정

| Lab | Nodes | QA Count | Domain |
|---|:---:|:---:|---|
| Lab-A | 10 | ~1,128 | SP MPLS VPN |
| Lab-B | 20 | ~2,200 | SP MPLS VPN Extended |
| Lab-C (옵션) | 30 | ~3,500 | Security-Focused |

> 제출 최소 기준: **Lab-A + Lab-B** 비교 완료  
> Lab-C는 preliminary 결과가 있을 때만 본문에 포함

### 결과 테이블 형식

**Table 7: Scalability — Single LLM (GPT-OSS-20B)**

| Level | 10 nodes | 20 nodes | 30 nodes | Degradation Rate |
|:---:|:---:|:---:|:---:|:---:|
| L1 | 0.873 | ? | ? | ? |
| L2 | 0.873 | ? | ? | ? |
| L3 | 0.605 | ? | ? | ? |
| L4 | 0.266 | ? | ? | ? |
| L5 | 0.134 | ? | ? | ? |

**Table 8: Scalability — NetAlly**

| Level | 10 nodes | 20 nodes | 30 nodes | Degradation Rate |
|:---:|:---:|:---:|:---:|:---:|
| L1 | ? | ? | ? | ? |
| L2 | ? | ? | ? | ? |
| L3 | ? | ? | ? | ? |
| L4 | ? | ? | ? | ? |
| L5 | ? | ? | ? | ? |

**기대 그래프**: 

```
TA-Acc
  1.0 ┤
      │  ── NetAlly L1-L3 (안정적)
  0.8 ┤  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
      │  ── LLM L1-L3 (점진적 하락)
  0.6 ┤  ·───·───·
      │  ── NetAlly L4-L5 (도구 덕분에 안정)
  0.4 ┤  ─ ─ ─ · ─ ─ · ─ ─ · ─ ─
      │
  0.2 ┤  ── LLM L4-L5 (급격 하락)
      │  ·───·
  0.0 ┤───·──────────────────────
      10    20    30     Nodes
```

> **핵심 메시지**: "Single LLM은 규모 증가에 따라 L4/L5 성능이 더욱 하락하지만, NetAlly는 도구를 활용하므로 규모에 robust하다"

### Pipeline Scalability 분석

**Table 9: QA Generation Pipeline Performance**

| Lab | Nodes | Config Files | Total QA | Generation Time | QA/Node |
|---|:---:|:---:|:---:|:---:|:---:|
| Lab-A | 10 | 10 | 1,128 | ? | ~113 |
| Lab-B | 20 | 20 | ~2,200 | ? | ~110 |
| Lab-C | 30 | 30 | ~3,500 | ? | ~117 |

> "QA/Node 비율이 일정 → 파이프라인이 선형적으로 확장됨을 입증"

---

## Experiment 5: External Benchmark Evaluation

### 목적

> NetAlly가 내부 데이터셋뿐 아니라 외부 벤치마크에서도 우수한 성능을 보이는가?

> 제출 최소 기준: **NIKA 1종 우선**  
> NetPress/NetConfEval은 잔여 시간 확보 시 확장

### 5.1 NIKA — 장애 진단 벤치마크

| 항목 | 값 |
|---|---|
| 벤치마크 | NIKA (ACM SIGCOMM NGNO 2025) |
| 태스크 | 네트워크 장애 진단 (Detection → Localization → Root Cause) |
| 시나리오 수 | 5 (DC ~ ISP) |
| 인시던트 수 | 640 (54 fault types) |
| 평가 지표 | Detection Accuracy, Localization Accuracy, Root Cause Identification |
| 비교 대상 | GPT-4o, GPT-OSS-20B (NIKA 논문 기존 결과) |

**Table 10: NIKA Benchmark — NetAlly vs Baselines**

| Metric | GPT-4o (Published) | GPT-OSS-20B | NetAlly | Δ |
|---|:---:|:---:|:---:|:---:|
| Detection | ? | ? | ? | ? |
| Localization | ? | ? | ? | ? |
| Root Cause | ? | ? | ? | ? |

### 5.2 NetPress — 동적 벤치마크

| 항목 | 값 |
|---|---|
| 벤치마크 | NetPress (arXiv 2025) |
| 태스크 | 라우팅 오설정 진단 (Routing Misconfiguration) |
| 쿼리 수 | 1,000 (동적 생성) |
| 평가 지표 | Correctness, Safety, Latency |
| 비교 대상 | GPT-4o (~24% correctness, NetPress 논문) |

**Table 11: NetPress Benchmark — Routing Misconfiguration**

| Metric | GPT-4o (Published) | NetAlly | Δ |
|---|:---:|:---:|:---:|
| Correctness | ~24% | ? | ? |
| Safety | ? | ? | ? |
| Avg. Latency | ? | ? | ? |

### 5.3 NetConfEval — 설정 생성 + Batfish 검증

| 항목 | 값 |
|---|---|
| 벤치마크 | NetConfEval (ACM CoNEXT 2024) |
| 태스크 | Low-level Config Generation (Task 4) |
| 워크플로우 | Agent 생성 → Batfish 자동 검증 → Pass/Fail |
| 평가 지표 | Generation Accuracy, Batfish Validation Pass Rate |
| 비교 대상 | GPT-4 / GPT-4o (NetConfEval 논문 기존 결과) |

**Table 12: NetConfEval — Config Generation + Validation**

| Metric | GPT-4 (Published) | NetAlly | Δ |
|---|:---:|:---:|:---:|
| Syntax Correctness | ? | ? | ? |
| Semantic Correctness (Batfish) | ? | ? | ? |
| Task 4 Accuracy | ? | ? | ? |

---

## 논문 내 Figure 목록 (계획)

| Figure # | 내용 | 유형 |
|:---:|---|---|
| Fig. 1 | System Architecture (NetAlly + NetConfigQA2.0) | Diagram |
| Fig. 2 | QA Generation Pipeline (Dual-Path) | Flowchart |
| Fig. 3 | Difficulty Level vs TA-Acc (전 모델) | Bar Chart |
| Fig. 4 | Single LLM vs NetAlly (Level별) | Grouped Bar |
| Fig. 5 | Scalability: TA-Acc vs Node Count | Line Chart |
| Fig. 6 | Error Analysis (Pie/Bar) | Bar Charts |
| Fig. 7 | External Benchmark Comparison (Radar) | Radar Chart |

---

## 논문 내 Table 목록 (계획)

| Table # | 내용 | Section |
|:---:|---|---|
| Table I | Dataset Statistics (Level × Category × Answer Type) | III-B |
| Table II | Dataset Verification Results (3-Layer) | III-C |
| Table III | Single LLM Baseline (TA-Acc per Level) | IV-A |
| Table IV | NetAlly vs Best Single LLM | IV-B |
| Table V | NetAlly Tool Usage Analysis | IV-B |
| Table VI | Error Analysis | IV-C |
| Table VII | Scalability — Single LLM | IV-D |
| Table VIII | Scalability — NetAlly | IV-D |
| Table IX | Pipeline Scalability | IV-D |
| Table X-XII | External Benchmarks (NIKA, NetPress, NetConfEval) | IV-E |
| Table XIII | Related Work Comparison | II |

---

## 분석 계획 (Discussion)

### 핵심 주장 3가지

1. **"LLM은 L4/L5에서 구조적으로 실패한다"**
   - 근거: Exp.2 (Table III) — 모든 모델 ≤ 0.3
   - 원인 분석: Context Length vs Config Complexity, Data Plane 시뮬레이션 불가능

2. **"도구 활용형 Agent는 이 한계를 극복한다"**
   - 근거: Exp.3 (Table IV) — NetAlly L4 0.75+, L5 0.60+
   - 핵심: LLM이 직접 추론하는 것 vs 도구를 호출하여 결과를 해석하는 것의 차이

3. **"파이프라인과 Agent 모두 규모에 확장 가능하다"**
   - 근거: Exp.4 (Table VII-IX) — QA/Node 비율 일정, NetAlly 성능 안정
   - 의의: 연구 프로토타입이 아닌 실용적 도구로의 가능성

### Threats to Validity

| 위협 | 대응 |
|---|---|
| 단일 토폴로지 의존 | Exp.4에서 3개 토폴로지로 확장 |
| Batfish Ground Truth 순환 | Layer 2 (PNETLab 실환경) 교차 검증 |
| 단일 벤더 (Cisco IOS) | 명시적 한계로 기술 + Future Work |
| 소규모 데이터셋 | 확장성 입증 (10→30 노드), 동적 생성 파이프라인 |
| NetAlly unfair advantage | NetAlly는 Batfish를 도구로 사용하지만, Ground Truth도 Batfish로 생성됨 → 이를 논문에서 명시적으로 논의하고, 외부 벤치마크(Exp.5)에서 도구 편향 없는 평가 제공 |
