# NetConfigQA2.0 — Ground Truth 검증 계획서 (설계 단계)

> **목적**: IEEE TNMS 논문에서 데이터셋 정답(Ground Truth)의 신뢰성을 입증하기 위한 검증 체계 설계
> **대상**: 데이터셋 v2 (L1~L5, 1,128 QA pairs)
> **전략**: **Hybrid Validation** (독립 파서 + 수동 로직 검증 + 실환경 에뮬레이션)
> **최종 산출물**: 논문 Section IV "Dataset Verification"에 들어갈 근거 수치와 증빙 로그

---

## 0. 문서 상태 및 경계

### 0.1 Scope Freeze
- 본 제출 실험은 **L1~L5**로 고정한다.
- L6는 코드만 유지하고, 이번 제출의 실험/평가/표에서는 제외한다.

### 0.2 검증 축 구분 (중요)

| 구분 | 목적 | 현재 구현 상태 | 논문에서의 역할 |
|---|---|---|---|
| **Dataset Integrity QA** | 스키마/ID/evidence 품질 보장 | 구현 완료 (`validate_policies.py`, `validate_dataset_quality.py`, `run_dataset_pipeline.sh`) | 내부 품질 보증(보조 증거) |
| **Ground Truth Validation** | 정답 자체의 타당성 입증 | **설계 단계** (본 문서) | 핵심 증거 (본 증거) |

> 즉, 현재 자동 파이프라인은 **데이터셋 오류 검증**이고, 본 문서는 별도의 **Ground Truth 검증 설계 문서**다.

### 0.3 자동화 스크립트 범위
- 현 시점은 검증 설계 단계이므로 `run_verification_pipeline.sh`를 즉시 만들지 않는다.
- Method 1/2/3의 실험 프로토콜과 산출물 포맷을 먼저 확정한 뒤, 실행 자동화는 다음 단계에서 통합한다.

---

## 1. 문제 정의: "자동 생성 정답을 어떻게 신뢰할 것인가?"

### 1.1 핵심 리스크: 순환 논증 (Circular Reasoning)
NetConfigQA2.0은 Batfish로 정답을 생성한다.  
리뷰어의 핵심 공격 포인트는 **"Batfish로 만든 정답을 Batfish로만 다시 검증하면, 오류도 일치로 보일 수 있다"**는 점이다.

따라서 핵심 방어 전략은 **생성 도구와 독립적인 제2의 오라클(Independent Oracle)** 확보다.

---

## 2. 검증 전략: Hybrid Validation

단일 방식의 한계를 줄이기 위해 상호보완적인 3개 방법을 결합한다.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Hybrid Verification Strategy                      │
├──────────────────────┬────────────────────────┬─────────────────────────┤
│    (1) Code-based    │    (2) Logic-based     │    (3) Reality-based    │
│  Independent Parser  │  Metric-wise Manual    │    PNETLab Emulation    │
├──────────────────────┼────────────────────────┼─────────────────────────┤
│ 대상: L1/L2/L3       │ 대상: 복잡 로직 metric  │ 대상: L4/L5             │
│ 수단: Regex/Python   │ 수단: Expert checklist │ 수단: 실제 에뮬레이터   │
│ 초점: 독립성         │ 초점: 로직 타당성      │ 초점: 외적 타당성       │
└──────────────────────┴────────────────────────┴─────────────────────────┘
```

> 참고: `run_dataset_pipeline.sh` 결과는 Layer 0 성격의 내부 품질 무결성 증거이며, Ground Truth 본증거는 Method 1/2/3로 제시한다.

### 2.1 관련 연구 근거

| 연구 | 검증 방법 | 본 계획에서의 적용 |
|---|---|---|
| **TeleQnA** (2023) | Human Expert Verification | Method 2 (수동 로직 검증) |
| **NetConfEval** (2024) | Batfish Simulation Oracle | Method 1의 필요성 정당화 (독립 오라클 보완) |
| **NIKA** (2025) | Environment Telemetry | Method 3 (실환경 동작 비교) |

---

## 3. Method 1: Independent Config Parser

### 3.1 목적
Batfish를 사용하지 않는 별도 코드로 정답을 재도출해, 생성 오라클 편향을 줄인다.

### 3.2 설계
- 순수 Python + Regex 기반 파서 사용 (Batfish import 금지).
- 대상: L1/L2 + 일부 L3의 구조화 가능한 metric.
- 원칙: metric별 파싱 규칙과 실패 규칙을 명시하고, 파싱 불가 metric은 제외 사유를 문서화.

### 3.3 산출물
- `independent_parser_results.csv` (metric, qa_id, expected, parsed, match)
- `independent_parser_mismatch.md` (불일치 원인 분류)
- 커버리지 수치 (검증 가능 metric/전체 metric)

---

## 4. Method 2: Metric-wise Manual Verification

### 4.1 목적
자동화가 놓칠 수 있는 조건부/예외 로직을 사람 검증으로 보완한다.

### 4.2 설계
1. 층화 표본 추출: metric 단위 대표 샘플 선정
2. 검증 체크리스트 기반 육안 확인: cfg, evidence, answer를 동시에 대조
3. 불일치 분류: 데이터 문제/파서 문제/설계 모호성으로 라벨링

### 4.3 산출물
- `manual_checklist.csv` (검수 기록)
- `manual_disagreement_log.md` (판정 근거)
- 논문용 문구: human verification protocol 및 adjudication 규칙

---

## 5. Method 3: PNETLab Real-world Verification

### 5.1 목적
Batfish 예측이 실제 에뮬레이터 동작과 일치하는지 확인한다.

### 5.2 설계
- 대상: L4/L5 중심 샘플
- 절차:
1. L4: traceroute 경로/도달성 비교
2. L5: 링크 장애 주입 후 reroute/disconnect 상태 비교

### 5.3 산출물
- `pnetlab_validation_results.csv`
- CLI 로그 및 명령 기록 (`show ip route`, `traceroute`, interface shutdown/no shutdown)
- 불일치 케이스 상세 리포트

---

## 6. 논문용 결과 표 템플릿

| Method | Scope | Sample Size | Agreement | 95% CI | 역할 |
|---|---:|---:|---:|---:|---|
| (1) Independent Parser | L1-L3 subset | TBD | TBD | TBD | 독립성 |
| (2) Manual Check | metric-wise sample | TBD | TBD | TBD | 로직 타당성 |
| (3) PNETLab Emulation | L4-L5 sample | TBD | TBD | TBD | 외적 타당성 |

> Layer 0(데이터셋 품질 게이트) 결과는 Appendix의 Pipeline Integrity로 수록한다.

---

## 7. 실행 로드맵 (설계 단계 기준)

| 단계 | 내용 | 상태 |
|---|---|:---:|
| Stage A | Ground Truth 검증 프로토콜/산출물 형식 확정 | **진행 중** |
| Stage B | Method 1/2/3 개별 실행 및 로그 수집 | 대기 |
| Stage C | 필요 시 통합 실행 스크립트화 | 대기 |

> 정리: 지금은 Stage A이므로 문서 확정이 우선이며, 통합 `.sh` 자동화는 Stage B 완료 후 결정한다.

---

## 8. 리뷰어 예상 질문 대응

| 예상 질문 | 답변 전략 | 근거 |
|---|---|---|
| "Circular reasoning 아닌가?" | Layer 0는 내부 품질용, 핵심 증거는 Method 1/2/3에서 제시 | 독립 오라클 + 실환경 |
| "run_dataset_pipeline 결과만으로 충분한가?" | 아니오. 그것은 데이터 품질 검증이며 GT 본검증은 별도 수행 | 0.2 검증 축 구분 |
| "샘플 수 타당성은?" | method별 표본 추출 규칙과 CI를 함께 제시 | Section 6 템플릿 |
| "사람 검증 편향은?" | 체크리스트/판정 로그/불일치 분류로 재현 가능성 확보 | Method 2 산출물 |
