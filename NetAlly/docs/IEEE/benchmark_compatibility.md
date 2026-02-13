# 외부 벤치마크 적합성 평가 & 검증 전략

> **작성일**: 2026-02-13  
> **목적**: Multi-Agent를 적용할 외부 벤치마크 선정 + 데이터셋 검증 전략 수립
>
> **실행 기준 (2026-02-13)**: 제출 필수는 **NIKA 1종**이며, NetPress/NetConfEval은 확장(옵션)으로 분리

---

## Part 1: 외부 벤치마크 적합성 분석

### 종합 비교표

| 벤치마크 | 학회 | 태스크 유형 | Agent 평가? | 코드 공개 | Multi-Agent 적용 가능성 |
|---|---|---|:---:|:---:|:---:|
| **NIKA** | SIGCOMM NGNO 2025 | 네트워크 장애 진단 (54종, 640 incident) | ✅ 전용 | ✅ [GitHub](https://github.com/sands-lab/nika) | ⭐⭐⭐⭐⭐ |
| **NetPress** | arXiv 2025 | DC 용량계획, 라우팅 오설정, 마이크로서비스 정책 | ✅ 가능 | ✅ [GitHub](https://github.com/Froot-NetSys/NetPress) | ⭐⭐⭐⭐☆ |
| **NetConfEval** | ACM CoNEXT 2024 | 설정 생성 (Intent→Config) 4종 | ❌ LLM만 | ✅ [Bitbucket](https://netconfeval.2over6.org/) | ⭐⭐⭐☆☆ |
| **NETLLMBENCH** | IEEE NFV-SDN 2024 | 네트워크 설정 + Kathara 에뮬레이션 검증 | ❌ LLM만 | ⚠️ 일부 | ⭐⭐⭐☆☆ |
| **NeMoEval** | ACM HotNets 2023 | LLM 코드생성 (트래픽 분석, 생명주기 관리) | ❌ 코드생성 | ✅ [GitHub](https://github.com/microsoft/NeMoEval) | ⭐⭐☆☆☆ |

---

### 1. NIKA — ⭐⭐⭐⭐⭐ 최적 후보

**arXiv:2512.16381, SIGCOMM NGNO Workshop 2025**

#### 왜 최적인가?

| 항목 | 설명 |
|---|---|
| **태스크** | 네트워크 장애 진단 + 트러블슈팅 (54종, 640 인시던트) |
| **환경** | 실제 네트워크 시나리오 (DC ~ ISP) |
| **Agent 인터페이스** | MCP 기반 30+ 도구 노출 (CLI, SDN API, INT, 스케치) |
| **평가 지표** | Detection Accuracy + Localization + Root Cause |
| **기존 결과** | GPT-5, GPT-OSS도 Root Cause 식별 실패 → Agent 필요성 입증 |

#### Multi-Agent 적용 방법

```
NIKA 인시던트 → Multi-Agent Orchestrator
  ├── Executor 1: CLI 도구 → show 명령 수집
  ├── Executor 2: Batfish → 경로 시뮬레이션
  ├── Executor 3: INT 데이터 분석
  └── Orchestrator: Root Cause 판정
→ Single LLM 대비 Localization/Root Cause 성능 향상 입증
```

#### 적합성 판단

> ✅ **가장 적합**. 이유:
> 1. Agent 평가용으로 설계되어 도구-Agent 인터페이스가 준비됨
> 2. 기존 LLM이 실패하는 영역(Root Cause) → Multi-Agent 효과 극대화
> 3. 오픈소스이므로 바로 실험 가능
> 4. 우리 논문의 "LLM 한계 → 도구 기반 Agent 필요" 주장과 완벽히 일치

#### ⚠️ 주의사항
- NIKA는 **실시간 네트워크 환경**이 필요 → Docker/Mininet 기반이므로 서버 자원 필요
- Multi-Agent를 NIKA의 MCP 인터페이스에 맞게 어댑터 작성 필요

---

### 2. NetPress — ⭐⭐⭐⭐☆ 강력 후보

**arXiv:2506.03231, 2025**

#### 왜 좋은가?

| 항목 | 설명 |
|---|---|
| **태스크** | DC 용량 계획, 라우팅 오설정 진단, 마이크로서비스 정책 |
| **특징** | 동적 벤치마크 생성 (런타임에 수백만 쿼리 생성 가능) |
| **에뮬레이터** | Mininet + Kubernetes 통합 |
| **평가 지표** | correctness + safety + latency |
| **기존 결과** | GPT-4o: ~24% correctness → 매우 낮음 |

#### Multi-Agent 적용 방법

```
NetPress 쿼리 → Multi-Agent
  ├── 라우팅 오설정 진단: Batfish + CLI 조합
  ├── 용량 계획: 에뮬레이터 데이터 분석
  └── 정책 트러블슈팅: 정책 규칙 추론
→ 24% → 50%+ 달성이면 강력한 결과
```

#### 적합성 판단

> ✅ **매우 적합**. 이유:
> 1. Agent correctness 24%로 개선 여지가 큼
> 2. 동적 생성이므로 데이터 오염 문제 없음
> 3. Leaderboard 존재 (netpress.ai) → 객관적 비교 가능
> 4. 라우팅 오설정 진단 태스크가 NetAlly의 강점과 일치

#### ⚠️ 주의사항
- Mininet + Kubernetes 환경 설정 필요
- 3가지 태스크 중 모두 할 필요 없이 라우팅 오설정 1개만 해도 충분

---

### 3. NetConfEval — ⭐⭐⭐☆☆ 보조 후보

**ACM CoNEXT 2024 (Proc. ACM Netw. 2)**

#### 태스크 4종

1. High-level requirement → Formal specification
2. High-level requirement → API/Function calls
3. High-level description → Routing algorithm
4. Documentation → Low-level config (P4 포함)

#### Multi-Agent 적용 가능성

태스크 특성상 **설정 생성**이 중심 → Multi-Agent의 "도달성 분석/장애 진단" 강점이 드러나기 어려움

#### 적합성 판단

> ⚠️ **보조적으로 적합**. 이유:
> 1. 태스크가 "생성"에 치우쳐 있음 → 우리 Agent의 "분석/검증" 역할과 맞지 않음
> 2. 하지만 "생성된 설정을 Batfish로 자동 검증"하는 파이프라인을 보여줄 수 있음
> 3. 논문에서는 "Agent-Generated Config → Batfish Validation" 워크플로우로 활용 가능

---

### 4. NETLLMBENCH — ⭐⭐⭐☆☆ 보조 후보

**IEEE NFV-SDN 2024**

#### 특징
- Kathara 에뮬레이션 기반 closed-loop 검증
- JSON 스키마 검증(문법) + 에뮬레이션 검증(의미)
- IP 주소/기본 게이트웨이 설정 등 기초적 태스크

#### 적합성 판단

> ⚠️ **보조적**. 이유:
> 1. 태스크가 비교적 기초적 (IP 할당 등) → L1-L2 수준
> 2. Multi-Agent 적용 시 overkill일 수 있음
> 3. 하지만 Kathara 기반 검증 방법론은 참고 가치 있음

---

### 5. NeMoEval — ⭐⭐☆☆☆ 비적합

**ACM HotNets 2023 (arXiv:2308.06261)**

#### 특징
- LLM 코드 생성 평가 (SQL, pandas, NetworkX)
- 트래픽 분석 + 생명주기 관리
- Microsoft Research 주도

#### 적합성 판단

> ❌ **비적합**. 이유:
> 1. 태스크가 "코드 생성"이어서 Multi-Agent의 도구 활용 능력과 관련 없음
> 2. 네트워크 설정/운용보다 데이터 분석에 가까움
> 3. Agent 프레임워크와의 인터페이스가 맞지 않음

---

## 추천 순위

### 🥇 1순위: **NIKA** + **NetPress** (둘 다 하면 최강)

```
NIKA → "장애 진단에서 Multi-Agent가 Single LLM을 압도"
NetPress → "동적 벤치마크에서도 Multi-Agent가 일관되게 우수"
```

### 🥈 2순위: **NIKA** 단독 (시간 부족 시)

가장 직접적으로 Multi-Agent의 가치를 입증 가능

### 🥉 3순위: **NetConfEval**을 보조적으로 추가

"Agent-Generated Config → Batfish Validation" 파이프라인 데모

---

## Part 2: 데이터셋 검증 전략

### 핵심 질문: "우리 데이터셋의 Ground Truth가 맞다는 걸 어떻게 증명하나?"

### 방법론: 3중 검증 체계 (Triple Verification)

> 제출 범위 고정(2026-02-13): 검증 대상은 L1~L5만 사용하며, L6는 이번 논문 실험에서 제외.

```
                    ┌──────────────────────┐
                    │  Ground Truth 신뢰성  │
                    └──────────────────────┘
                     /        |         \
          ┌───────────┐ ┌──────────┐ ┌──────────────┐
          │ 검증 1    │ │ 검증 2   │ │ 검증 3       │
          │ 자동 재실행│ │ 실환경   │ │ 교차 도구    │
          │ (Batfish) │ │ (PNETLab)│ │ (LLM-Judge)  │
          └───────────┘ └──────────┘ └──────────────┘
```

### 검증 1: Batfish 재실행 (자동, 전수검사)

**검증 코드 로직 (작성 필요)**:

```python
"""
NetConfigQA2.0 Dataset Verification Script
3단계 검증:
  1) 메타데이터 검증: 필수 필드 존재, 타입 정합
  2) 답변 재현 검증: Batfish 재실행 → 동일 답변?
  3) 통계 검증: 레벨/카테고리 분포, 이상치 탐지
"""

def verify_dataset(dataset_path, snapshot_path):
    results = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    
    for qa in load_dataset(dataset_path):
        # Phase 1: 메타데이터 검증
        meta_ok = verify_metadata(qa)  # id, level, category, answer_type 존재?
        
        # Phase 2: 답변 재현 (핵심)
        if qa["level"] in ["L1", "L2", "L3"]:
            # Rule-based 정답 → BuilderCore 재계산
            reproduced = builder_core.compute(qa["evidence"])
            match = compare_answers(qa["answer"], reproduced, qa["answer_type"])
        elif qa["level"] in ["L4", "L5"]:
            # Batfish 시뮬레이션 → 재실행
            reproduced = batfish.simulate(qa["evidence"])
            match = compare_answers(qa["answer"], reproduced, qa["answer_type"])
        else:
            results["SKIP"] += 1; continue
        
        # Phase 3: 판정
        results["PASS" if match else "FAIL"] += 1
    
    return results
```

**장점**: 전수검사 가능 (1,128개 전부)  
**한계**: "Batfish가 자기 자신을 검증" → 순환 논증 문제

> 💡 그래서 검증 2가 필요함

### 검증 2: PNETLab 실환경 교차 검증 (수동 + 반자동)

**대상**: L4 질문 30개 + L5 질문 20개 = 50개 샘플

```
for each L4 traceroute question:
    1. PNETLab 실제 장비에서 traceroute 실행
    2. 실제 결과 vs Batfish 정답 비교
    3. 일치 여부 기록
    → "Batfish 시뮬레이션 정확도: XX%" 보고
```

**장점**: 가장 강력한 검증 (시뮬레이션 ↔ 실제 네트워크)  
**한계**: 수동 작업 필요, L5(장애 시나리오)는 실제 장애 주입 필요

### 검증 3: LLM-as-Judge (보조적, 자동)

**대상**: 레벨별 20개씩 = 100개 샘플

```python
prompt = f"""
다음 네트워크 질문-정답 쌍을 검토하세요:

질문: {qa["question"]}
정답: {qa["answer"]}
난이도: {qa["level"]}
카테고리: {qa["category"]}

다음 3가지를 평가하세요 (각 1-5점):
1. 질문 명확성 (Clarity): 질문이 모호하지 않고 하나의 정답만 가능한가?
2. 정답 정확성 (Correctness): 제공된 정답이 합리적인가?
3. 난이도 적절성 (Level): L{level}에 적합한 난이도인가?
"""
```

**장점**: 대규모 자동 수행 가능, 전문가 없이도 품질 신호 확보  
**한계**: "LLM으로 만든 것을 LLM이 검증" → 논문에 한계 명시 필요

### 3중 검증 결과 보고 형식

| 검증 방법 | 대상 | 일치율 | 역할 |
|---|:---:|:---:|---|
| Batfish 재실행 | 1,128건 전수 | ?% | Ground Truth 내적 일관성 |
| PNETLab 실환경 | 50건 샘플 | ?% | 시뮬레이션 ↔ 실제 일치 |
| LLM-as-Judge | 100건 샘플 | 평균 ?/5 | 질문 품질 + 정답 합리성 |

---

## 검증 코드 작성 계획

### 구현할 파일

| 파일 | 역할 |
|---|---|
| `Make_Dataset/src/verify_dataset.py` | 메인 검증 스크립트 |
| `Make_Dataset/src/core_batfish/verifier.py` | Batfish 재실행 + 비교 로직 |
| `Make_Dataset/src/llm_judge.py` | LLM-as-Judge 평가 |

### 출력물

| 파일 | 내용 |
|---|---|
| `*_verification.md` | 검증 요약 보고서 |
| `*_verification_failures.csv` | 실패 건 상세 |
| `*_llm_judge_results.json` | LLM 판정 결과 |
