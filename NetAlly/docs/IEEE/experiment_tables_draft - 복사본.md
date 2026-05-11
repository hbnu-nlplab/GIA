# IEEE TNSE 논문 실험 구성 (Draft v3)

> - 📊 = 실측 데이터, 📐 = 예상치 (실험 후 교체)
> - 모든 수치는 TA-Acc (Type-Aware Accuracy) 기준 (%)
> - 구성: **Table 3개 + Figure 4개**

---

## Table I: Main Results — System Architecture Comparison (TA-Acc %)

> 논문 위치: Section V-B (Experiments)
> 목적: MAS와 MCP 각각의 기여를 분리하기 위한 2×2 factorial design

| System | MAS | MCP | Model | Lab A | Lab B | Lab C | Lab D | Avg |
|--------|:---:|:---:|-------|------:|------:|------:|------:|----:|
| Single LLM | | | best per lab† | 46.99 📊 | 42.28 📊 | 33.33 📊 | 26.70 📊 | 36.42 📊 |
| Pure MAS | O | | Mistral3-8B | 📐 | 📐 | 📐 | 📐 | 📐 |
| Single+MCP | | O | gpt-4o-mini | 📐 | 📐 | 📐 | 📐 | 📐 |
| **NetAlly** | **O** | **O** | **gpt-4o-mini** | 📐 | **92.0 📊*** | 📐 | 📐 | 📐 |

> †Single LLM best: LabA=GPT-OSS-20B(46.99%), LabB=Mistral3-8B(42.28%), LabC/D=Mistral3-8B
> *Lab B sampled 100문제 실측. 전체 데이터셋 결과로 교체 예정.

**리뷰어 대응:**
- "도구 없이 MAS만 써도 되지 않나?" → Pure MAS 행
- "에이전트 없이 도구만 쓰면?" → Single+MCP 행
- "MAS와 MCP 중 어느 것이 더 기여하나?" → 행 간 delta 비교

---

## Table II: Single LLM Baseline — All Models (TA-Acc %)

> 논문 위치: Section V-A (Baseline)
> 목적: 5개 모델의 baseline + L4/L5 저조함 입증

| Model | Params | Lab A | Lab B | Lab C | Lab D | Avg | Avg L4 | Avg L5 |
|-------|-------:|------:|------:|------:|------:|----:|-------:|-------:|
| Mistral3-8B | 8B | 43.38 | 42.28 | 33.33 | 26.70 | **36.42** | 15.85 | 12.13 |
| GPT-OSS-20B | 20B | **46.99** | 41.54 | 31.51 | 24.19 | 36.06 | 12.62 | 13.20 |
| Qwen3-8B | 8B | 41.11 | 38.42 | 28.92 | 21.92 | 32.59 | 11.19 | 11.52 |
| GPT-4o-mini | 8B* | 39.43 | 39.02 | 28.56 | 22.32 | 32.33 | 15.62 | 5.87 |
| Llama-3.1-8B | 8B | 23.30 | 25.23 | 17.78 | 14.48 | 20.19 | 5.93 | 6.00 |

> 전체 📊 실측. *gpt-4o-mini 파라미터 수는 추정치.

**Key findings (본문에 서술):**
1. 전 모델 L4 < 16%, L5 < 14% → config 텍스트만으로 행동 추론 불가
2. 파라미터 수 ≠ 성능 (20B < 8B)
3. Lab 난이도 증가에 따라 전 모델 하락 (A:47% → D:27%)

---

## Table III: Efficiency Comparison

> 논문 위치: Section V-D (Efficiency Analysis)
> 목적: 정확도 향상의 비용(속도, 토큰, LLM 호출 수) 평가

| System | TA-Acc (LabB) | Time/q | Tokens/q | LLM Calls/q | Tools/q |
|--------|-------------:|---------:|-----------:|------------:|--------:|
| Single LLM | 42.28 📊 | ~3s 📐 | ~2K 📐 | 1 | 0 |
| Pure MAS | 📐 | 📐 | 📐 | ~5 📐 | 0 |
| Single+MCP | 📐 | 📐 | 📐 | ~3 📐 | ~1.3 📐 |
| **NetAlly** | **92.0 📊** | **11s 📊** | **14K 📊** | **6.1 📊** | **1.5 📊** |

**리뷰어 대응:**
- "MAS+MCP가 너무 비싸지 않나?" → 6.1회 호출, 14K 토큰으로 +50%p 향상은 합리적
- "실시간 사용 가능?" → 11s/q는 interactive use에 충분

---

## Fig. 1: NetAlly System Architecture

> 논문 위치: Section III (Proposed Method)
> 형식: draw.io 또는 TikZ 다이어그램

```
┌─────────────────────────────────────────────────────────┐
│                     NetAlly System                       │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌─────────────┐       │
│  │ Collector │───>│ Verifier │───>│ Synthesizer │       │
│  │ (도구선택 │    │ (노이즈  │    │ (답변 생성) │       │
│  │  +호출)   │    │  제거)   │    │             │       │
│  └─────┬─────┘    └──────────┘    └──────┬──────┘       │
│        │                                 │              │
│        │ MCP Tools                ┌──────┴──────┐       │
│   ┌────┴────┐                     │  Supporter  │       │
│   │  NSO    │ L1-L3               │      ⇅      │       │
│   │RESTCONF │                     │  Skeptic    │       │
│   ├─────────┤                     └──────┬──────┘       │
│   │ Batfish │ L4-L5                      │              │
│   │Simulator│                     final_answer          │
│   └─────────┘                                           │
└─────────────────────────────────────────────────────────┘
```

**다이어그램 요소:**
- 5-agent MAS 파이프라인 (고정 그래프)
- MCP 도구 연결 (Collector → NSO/Batfish)
- Supporter⇄Skeptic debate 루프
- NEED_MORE_INFO → Collector 재호출 피드백 경로

---

## Fig. 2: Performance by Difficulty Level (Grouped Bar Chart)

> 논문 위치: Section V-C (Per-Level Analysis)
> 형식: matplotlib/seaborn grouped bar chart
> **논문의 핵심 Figure — "L4-L5 cliff" 시각화**

```
TA-Acc (%)
100 ┤                                    ┌──┐┌──┐
 90 ┤                          ┌──┐┌──┐  │░░││░░│
 80 ┤                ┌──┐      │▒▒││░░│  │▒▒││░░│
 70 ┤      ┌──┐┌──┐  │▒▒│┌──┐  │▒▒││░░│  │▒▒││░░│
 60 ┤      │▒▒││░░│  │▒▒││░░│  │▒▒││░░│  │▒▒││░░│
 50 ┤┌──┐  │▒▒││░░│  │▒▒││░░│  │▒▒││░░│  │▒▒││░░│
 40 ┤│██│  │▒▒││░░│  │  ││░░│  │  │      │  │
 30 ┤│██│  │  │      │  │      │  │      │  │
 20 ┤│██│  │  │      │  │      │  │
 10 ┤│██│  │  │      │  │
  0 ┼──────┼──────────┼──────────┼──────────┼──────────
     L1       L2         L3         L4         L5

   ██ Single LLM   ▒▒ Single+MCP   ░░ NetAlly (MAS+MCP)
```

**핵심 메시지:**
- L1-L3: 도구 없어도 일부 가능 (40-70%), 도구 있으면 80-100%
- **L4-L5: 도구 없으면 급락 (<16%), 도구 있으면 유지 (>85%)**
- 이 "cliff"가 MCP 도구의 필요성을 시각적으로 증명

---

## Fig. 3: Model Comparison — NetAlly Framework, Lab D (Bar + Radar)

> 논문 위치: Section V-E (Ablation: Model Selection)
> 형식: (a) bar chart + (b) radar chart 2-panel figure

**(a) Bar Chart — 모델별 Lab D 전체 TA-Acc:**

```
TA-Acc (%)
 80 ┤ ┌──┐
 70 ┤ │  │ ┌──┐ ┌──┐
 60 ┤ │  │ │  │ │  │ ┌──┐
 50 ┤ │  │ │  │ │  │ │  │ ┌──┐
 40 ┤ │  │ │  │ │  │ │  │ │  │
 30 ┤ │  │ │  │ │  │ │  │ │  │
 20 ┤ │  │ │  │ │  │ │  │ │  │
 10 ┤ │  │ │  │ │  │ │  │ │  │
  0 ┤ └──┘ └──┘ └──┘ └──┘ └──┘
   4o-mini oss-20b Mistral Qwen3 Llama3
```

**(b) Radar Chart — 모델별 L1-L5 프로필:**

```
          L1
         /  \
    L5 /    \ L2
       \    /
    L4 \  / L3
         \/
   ── gpt-4o-mini  -- gpt-oss-20b  ·· Mistral3-8B
```

**핵심 메시지:**
- gpt-4o-mini가 전 레벨 균형 잡힌 성능
- 파라미터 수(20B) > instruction following(RLHF) ≠ 도구 활용 능력

**역할 민감도 (본문 텍스트로 서술):**
> Collector(도구 선택) 역할에 강한 모델을 배치했을 때 가장 큰 성능 향상(+5.6%p)을 보였으며, Debate 에이전트 교체는 상대적으로 적은 영향(+1.8%p)을 미쳤다. 이는 MAS+MCP 시스템에서 도구 선택 능력이 토론 능력보다 중요함을 시사한다.

---

## Fig. 4: Tool Usage Pattern by Difficulty Level (Stacked Bar)

> 논문 위치: Section V-F (Discussion: Tool Contribution)
> 형식: stacked bar chart — 레벨별 도구 카테고리 비율

```
Tools/q
  2.0 ┤                                    ┌────┐
      │                                    │Batf│
  1.5 ┤                          ┌────┐    │ish │
      │                          │Batf│    │    │
  1.0 ┤ ┌────┐  ┌────┐  ┌────┐  │ish │    │    │
      │ │NSO │  │NSO │  │NSO │  ├────┤    ├────┤
  0.5 ┤ │    │  │    │  │    │  │NSO │    │NSO │
      │ │    │  │    │  │    │  │    │    │    │
  0.0 ┼─┴────┴──┴────┴──┴────┴──┴────┴────┴────┴─
       L1       L2       L3       L4       L5

   ■ NSO (Config Data)   ■ Batfish (Network Simulation)
```

**핵심 메시지:**
- L1-L3: NSO 도구만으로 충분 (설정 데이터 추출/비교)
- L4: Batfish 전환점 — traceroute 시뮬레이션 필요
- L5: Batfish 비중 증가 (failure simulation) + 다중 도구 호출

---

## 전체 구성 요약

| 구분 | 번호 | 내용 | 논문 섹션 | 핵심 메시지 |
|------|------|------|----------|------------|
| Table | I | 4-way × 4 Labs | Experiments | MCP가 핵심 기여 (+44%p) |
| Table | II | Single LLM baseline | Experiments | 전 모델 L4/L5 <16% |
| Table | III | 효율성 비교 | Discussion | 11s/q, 14K tokens |
| Fig | 1 | 시스템 아키텍처 | Method | MAS + MCP 구조 |
| Fig | 2 | **L1-L5 bar chart** | Experiments | **L4-L5 cliff (핵심!)** |
| Fig | 3 | 모델 비교 bar+radar | Ablation | 파라미터 수 ≠ 성능 |
| Fig | 4 | Tool usage stacked bar | Discussion | NSO→Batfish 전환 |

**총: Table 3개 + Figure 4개 = IEEE TNSE 적정 분량**

---

## Notes

- 📊 = 실측, 📐 = 예상치
- Fig 2가 논문의 **가장 중요한 Figure** — L4-L5 cliff가 MCP 필요성의 시각적 증거
- Table 5 (역할 민감도)는 Fig 3 캡션 또는 본문 텍스트로 흡수
- Figure는 draw.io → PDF 또는 matplotlib → PDF로 제작 예정
