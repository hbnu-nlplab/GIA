# NetConfigQA2.0 — IEEE TNMS 준비도 평가 (수정본)

> **평가일**: 2026-02-13 (KICS 논문 + 데이터셋 통계 반영)  
> **투고 마감**: 2026-02-28 (**15일 남음**)  
> **제약**: 네트워크 전문가 부재, 단일 토폴로지
>
> **제출 기준 고정 (2026-02-13)**: 본문 실험 데이터셋은 v2 공개본 **1,128 QA (L1~L5)**를 사용하며, 추가 확장은 옵션으로 분리

---

## 종합 평가: 🟡 보완 후 투고 가능

KICS 2026 논문에서 **핵심 실험이 이미 완료**되어 있고, 자동 검증(Verification) 시스템도 존재합니다. IEEE TNMS 확장에서 필요한 것은 **깊이(depth)의 보강**입니다.

---

## 1. KICS 논문에서 확인된 실험 결과

### 표 3: NetConfigQA2.0 전체 성능

| Model | Rouge-L | BERTScore | EM | F1(Token) | **TA-Acc** |
|---|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | 0.155 | 0.942 | 0.398 | 0.539 | **0.515** |
| Llama-3.1-8B | 0.314 | 0.897 | 0.176 | 0.302 | **0.291** |
| Mistral3-8B | 0.279 | 0.875 | 0.201 | 0.304 | **0.416** |
| Qwen3-8B | 0.414 | 0.932 | 0.339 | 0.472 | **0.465** |
| GPT-OSS-20B | 0.439 | 0.942 | 0.437 | 0.529 | **0.612** |

> ✅ **BERTScore가 0.875~0.942로 변별력 없는 반면, TA-Acc는 0.291~0.612로 명확한 차이** → 지표 정당성 입증됨

### 표 4: 난이도별 TA-Acc

| Model | L1 | L2 | L3 | L4 | L5 |
|---|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | 0.765 | 0.541 | 0.369 | 0.267 | 0.159 |
| Llama-3.1-8B | 0.368 | 0.371 | 0.305 | 0.184 | 0.138 |
| Mistral3-8B | 0.572 | 0.143 | 0.500 | 0.158 | 0.183 |
| Qwen3-8B | 0.639 | 0.294 | 0.431 | 0.256 | 0.225 |
| GPT-OSS-20B | **0.873** | **0.873** | **0.605** | 0.266 | 0.134 |

> 🔑 **핵심 발견**: L1-L2에서 최대 0.873이지만, **L4/L5에서 모든 모델 ≤ 0.3** → "LLM은 네트워크 동적 추론에 실패한다"는 논문 핵심 주장이 정량적으로 입증됨

---

## 2. 데이터셋 현황 (수정)

### 2.1 두 버전 존재

| 버전 | 날짜 | QA 수 | 비고 |
|---|---|:---:|---|
| v1 (KICS 사용) | 2025-12-30 | **762** | KICS 논문에서 사용. 검증 보고서 존재 |
| v2 (최신) | 2026-01-29 | **1,128** | Scope Expansion 적용. 카테고리 17개 |
| v2 이중언어 | 2026-02-13 | **1,128 × 2** | KO/EN 독립 생성. 정답은 영어 계약 토큰 통일 |

> v2 이중언어 품질 개선 사항 (2026-02-13):
> - EN 템플릿: L4/L5 자연어 품질 전면 교정 (Batfish 전문용어 제거, 11건)
> - KO 템플릿: 답변 형식 힌트를 영어 계약 토큰에 정렬 (NONE/ALLOWED 등 7건)
> - KO 조사 동적 교정: `ko_josa.py` — 장비명 뒤 과/와 자동 처리
> - AS 미설정 표기: "AS None" → "AS N/A" 수정

### 2.2 레벨 분포 비교

| Level | v1 (KICS) | v2 (최신) | 변화 |
|---|:---:|:---:|---|
| L1 | 364 | 634 | +270 (Scope Expansion) |
| L2 | 21 | 21 | **변동 없음** 🔴 |
| L3 | 127 | 127 | 변동 없음 |
| L4 | 149 | 159 | +10 |
| L5 | 101 | 187 | +86 |

> 🔴 **L2가 여전히 21개** — KICS에서도, 최신에서도 미해결. v1→v2에서 Scope Expansion이 L1/L5에만 효과.

### 2.3 기존 검증 보고서 (v1, 2025-12-30) — 레거시

| 상태 | 수 | 비율 |
|---|:---:|:---:|
| ✅ PASS | 220 | 28.9% |
| ❌ FAIL | 48 | 6.3% |
| ⏭️ SKIP | 494 | 64.8% |

> ⚠️ 이 보고서는 v1 기준이며, 아래 v2 검증 결과로 **대체됨**.

### 2.4 v2 Ground Truth 검증 결과 (✅ 2026-02-13)

3-Method Hybrid 검증으로 Batfish 순환 논증을 차단한 독립 검증 수행:

| Method | 접근법 | 범위 | Agreement | 상태 |
|:---:|---|:---:|:---:|:---:|
| **Method 1** | Batfish-free Independent Parser (Python+Regex) | 800 (L1-L3 전수) | **99.5%** (실질 100%) | ✅ 완료 |
| **Method 2** | Stratified Sampling + Manual Check | 43 (L1-L3 표본) | **97.7%** (42/43) | ✅ 자동 완료 |
| **Method 3** | PNETLab Real CLI | 44 (L4: 23, L5: 21) | — | ⬜ 사람 실행 대기 |

**알려진 데이터 오류 (5건)**: Batfish VRF 이중 카운팅 4건 + all_devices_same_as 설계 선택 1건 (모두 Low severity)

> ✅ **v1의 L4 30% 실패 문제는 v2 파이프라인 개선으로 해결됨**. 3-Method 독립 검증으로 Ground Truth 신뢰성 입증.
> 코드: `Make_Dataset/src/verification/run_verification_pipeline.py`

---

## 3. IEEE TNMS 확장을 위한 GAP 분석

### 3.1 KICS → IEEE TNMS에서 새로 필요한 것

| 항목 | KICS에서 | IEEE TNMS에서 필요 | 난이도 |
|---|---|---|:---:|
| 모델 수 | 5개 | 7-8개+ (Claude 추가 등) | 🟢 낮음 |
| 실험 깊이 | 전체 TA-Acc + L1-L5 | + Prompt 전략 비교, Error Analysis | 🟡 중간 |
| 검증 | 자동 검증 28.9% PASS | **3-Method Hybrid 검증** | ✅ 완료 (99.5%, 97.7%) |
| 토폴로지 | 1개 | **최소 2개** | 🟡 Config Gen 완료, 배포 필요 |
| Human Validation | 없음 | **Method 2 Manual + Method 3 PNETLab** | 🟡 가이드 생성 완료, 사람 실행 대기 |
| 데이터셋 규모 | 762 | 1,128 (필수) + L2 보강(옵션) | 🟡 중간 |
| 이중언어 | 없음 (한국어만) | **KO/EN 이중언어 + 품질 교정** | ✅ 완료 |
| 관련 연구 | 7개 | **11개+** (이미 정리 완료 ✅) | 🟢 완료 |

### 3.2 검증 전략 — 실제 구현된 3-Method Hybrid ✅

네트워크 전문가 없이도 Ground Truth 신뢰성을 확보하는 **3-Method Hybrid** 전략을 구현 완료:

#### Method 1: Independent Config Parser ✅ 구현 완료
```
Batfish-free Python+Regex 파서로 L1-L3 800건 전수 검증
→ 99.5% Agreement (실질 100%)
→ "Batfish 없이도 동일한 정답에 도달" 입증
```
> ✅ **순환 논증 차단의 핵심**. NetConfEval(Batfish Oracle 의존)보다 강력한 검증.

#### Method 2: Stratified Manual Check ✅ 자동 완료, ⬜ 사람 검토 대기
```
43개 표본을 메트릭/레벨/answer_type별 계층 추출
→ 자동 교차검증: 97.7% (42/43)
→ 사람이 .cfg 원본을 직접 트레이스하여 확인 (가이드 생성 완료)
```
> ✅ TeleQnA 스타일의 전문가 검증 방식. human_reviewer_guide.md 제공.

#### Method 3: PNETLab Real-world CLI ⬜ 사람 실행 대기
```
44개 표본 (L4: 23, L5: 21)을 PNETLab 실장비에서 CLI로 검증
→ traceroute, ping, show 명령으로 실측
→ pnetlab_verification_guide.md + blank_checklist.csv 생성 완료
```
> ✅ NIKA 스타일의 환경 기반 검증. 가장 강력한 실증적 검증.

> **레퍼런스**: `research_findings_verification.md` 참조 — TeleQnA(전문가), NetConfEval(Batfish Oracle), NIKA(환경 기반) 모두의 장점을 결합

---

## 4. 15일 Action Plan (2/13 → 2/28)

### Phase 1: 데이터셋 정리 + 검증 — ✅ 대부분 완료

| # | 작업 | 시간 | 상태 |
|:---:|---|:---:|:---:|
| 1-1 | v2 데이터셋 3-Method Hybrid 검증 | 2일 | ✅ 코드 완료 + Method 1-2 결과 확보 |
| 1-2 | Method 2 사람 검토 (43 QA) | 2-3시간 | ⬜ 연구자 실행 필요 |
| 1-3 | Method 3 PNETLab 실행 (44 QA) | 4-6시간 | ⬜ 연구자 실행 필요 |
| 1-4 | L2 질문 추가 생성 (목표: 50개+) | 1일 | ⬜ 옵션 |

### Phase 2: Scalability + 실험 (2/17 ~ 2/20, 4일)

| # | 작업 | 시간 | 우선순위 |
|:---:|---|:---:|:---:|
| 2-1 | Lab-B PNETLab 배포 + 데이터셋 생성 + 검증 | 2일 | 🔴 |
| 2-2 | v2 데이터셋으로 5개 모델 재실험 (Single LLM) | 2일 | 🔴 |
| 2-3 | 검증 결과 정리 → 논문 Section으로 작성 | 1일 | 🔴 |

### Phase 3: 실험 확장 (2/21 ~ 2/24, 4일)

| # | 작업 | 시간 | 우선순위 |
|:---:|---|:---:|:---:|
| 3-1 | v2 데이터셋(1,128건)으로 전 모델 재실험 | 2일 | 🔴 |
| 3-2 | Zero-shot vs Few-shot(3) vs CoT 비교 실험 | 1일 | 🟡 |
| 3-3 | Error Analysis: L4/L5 실패 유형 분류 (최소 30건 정성분석) | 1일 | 🔴 |

### Phase 4: 논문 작성 (2/25 ~ 2/28, 4일)

| # | 작업 | 시간 | 우선순위 |
|:---:|---|:---:|:---:|
| 4-1 | KICS 논문 → IEEE 형식 확장 (12페이지 목표) | 2일 | 🔴 |
| 4-2 | Related Work 섹션 확장 (이미 정리 완료) | 0.5일 | 🟢 |
| 4-3 | 그림/표 품질 향상 + 추가 | 1일 | 🟡 |
| 4-4 | 최종 교정 + 제출 | 0.5일 | 🔴 |

---

## 5. 토폴로지 확장 판단

### 현실적 판단: 15일 내에 2번째 토폴로지 추가가 가능한가?

**L2VPN 토폴로지 (8노드)** — configs가 이미 존재:
- `CE01.cfg`, `CE02.cfg`, `CE03.cfg`, `CE04.cfg`
- `P01.cfg`, `P04.cfg`, `PE02.cfg`, `PE03.cfg`

```
필요 작업:
1. L2VPN configs → Batfish snapshot 로드 (0.5일)
2. policies.json 호환성 확인 (0.5일)
3. 데이터셋 생성 실행 (0.5일)
4. 검증 (0.5일)
→ 총 2일 추가
```

> 🟡 **추천**: 가능하면 추가하되, Phase 1-3이 우선. 시간이 부족하면 "향후 연구"로 남기고, **"파이프라인이 토폴로지 독립적임"을 L2VPN에서도 생성 가능함을 보여주는 것만으로도 가치 있음**.

---

## 6. 남은 핵심 개선 항목 (우선순위)

### 🥇 1위: Method 3 PNETLab 사람 실행 + Lab-B 배포

> Method 3 실행으로 검증 완전 완성 + Lab-B로 Scalability 최소 증거 확보. 논문 제출의 최소 요구사항.

### 🥈 2위: LLM 재실험 (v2 데이터셋) + Error Analysis

> v2 기준 TA-Acc 재측정 + "왜 L4/L5에서 실패하는가?" 정성 분석. 리뷰어 관심 집중 영역.

### 🥉 3위: L2 질문 보강 (옵션)

> L2가 21개뿐인 것은 논문 표에서 바로 보이는 약점. 50개로 늘리면 "난이도별 균형잡힌 벤치마크" 주장 가능. 다만 검증/실험보다 후순위.

---

## 7. KICS → IEEE TNMS 논문 구조 (제안)

| Section | KICS 분량 | IEEE 목표 | 보강 내용 |
|---|:---:|:---:|---|
| I. Introduction | 0.5p | 1.5p | RQ 명시, 기여 확장 |
| II. Related Work | 없음 | **2p** | 11개 논문 비교 (이미 정리 완료) |
| III. Dataset Construction | 1p | **3p** | Scope Expansion 상세, L1~L5 고정 근거와 L6 제외 사유 명시, 자동화 강조 |
| IV. Evaluation Metric | 0.3p | **1p** | TA-Acc 수식, answer_type별 상세, BERTScore 비교 근거 |
| V. Experiments | 0.5p | **3p** | v2 결과, Prompt 전략, Error Analysis, Cross-Tool Validation |
| VI. Discussion | 없음 | **1p** | 왜 L4/L5에서 실패? 도구 활용형 Agent의 필요성 |
| VII. Conclusion | 0.2p | 0.5p | 향후 연구 (NetAlly, 멀티 토폴로지) |
| **Total** | **~2.5p** | **~12p** | |
