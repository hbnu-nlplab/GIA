# IEEE TNMS 논문 계획 비판적 리뷰 및 리스크 평가

> **작성자**: Project Reviewer (AntiGravity)  
> **일자**: 2026-02-13  
> **대상**: `NetAlly/docs/IEEE/` 문서 전체 (v2 기준)

---

## 1. 총평 (Executive Summary)

**"논리적 완결성은 우수하나, 실행 가능성(Feasibility)에서 심각한 리스크가 존재함"**

현재 문서들은 IEEE TNMS 수준의 논문을 위한 스토리라인과 실험 설계를 매우 훌륭하게 갖추고 있습니다. 특히 `NetConfigQA2.0`의 **"Behavioral Inference"** 접근법과 **"3-Layer 검증"** 전략은 리뷰어에게 강력한 인상을 줄 수 있는 핵심 무기입니다.

그러나 **2월 28일 마감**까지 남은 시간(약 2주) 동안 계획된 **5가지 실험(Experiment 1~5)**을 모두 완수하는 것은 물리적으로 매우 어렵습니다. 특히 **Exp.4 (Scalability)**와 **Exp.5 (External Benchmark)**는 각각 별도 논문으로 써도 될 만큼의 분량과 엔지니어링이 요구됩니다.

**전략적 제언**: "선택과 집중"이 필수적입니다. Exp.1, 2, 3을 완벽하게 수행하여 Core Contribution을 확보하고, Exp.4, 5는 범위를 축소하거나 "Preliminary Results" 형태로 방어해야 합니다.

---

## 2. 강점 (Strengths) - "이 논문이 합격할 이유"

1.  **독창적인 문제 정의 (Behavioral Inference)**:
    -   기존 벤치마크(TeleQnA 등)가 "지식 검색"에 그친 반면, 본 연구는 "설정 파일 → 동작 추론"이라는 새로운 차원을 열었습니다. `research_notes.md`의 Quadrant Chart는 이 포지셔닝을 매우 효과적으로 시각화합니다.

2.  **논리적 완결성 (Problem-Solution Fit)**:
    -   [문제] LLM은 L4/L5(시뮬레이션 영역)에서 필연적으로 실패한다 (Context Window, 연산 한계).
    -   [해결] 따라서 도구(Batfish)를 사용하는 Agent가 필수적이다.
    -   [검증] NetConfigQA2.0으로 이를 증명한다.
    -   -> 이 흐름은 반박하기 어려운 탄탄한 논리 구조를 가짐.

3.  **3-Layer 검증 아키텍처**:
    -   "Batfish로 만든 문제를 Batfish로 푼다"는 순환 논증 공격을 **Layer 2 (실환경 교차검증)**로 방어한 것은 신의 한 수입니다. PNETLab 실측 데이터 50개는 1,000개의 시뮬레이션 데이터보다 강력한 설득력을 가집니다.

---

## 3. 약점 및 리스크 (Weaknesses & Risks) - "이 논문이 거절될 이유"

### 🚨 Risk 1: 시간 부족 (Time Crunch)
-   **현황**: 실험 설계는 완벽하지만, 코드는 아직 `Make_Dataset/src/` 일부만 존재.
-   **문제**:
    -   `verify_dataset.py` (Layer 1) 구현 및 1,128개 전수 검사 → **버그 수정에 예상보다 오래 걸릴 수 있음**.
    -   **Lab-B (20노드)** 구축: .cfg 파일을 PNETLab config에 붙여넣기로 바로 적용 가능하므로, 병목은 토폴로지 설계(IP 체계/AS 구조 등)이며 구현 자체는 빠름. **설계 1~2일 + 구현 반나절** 정도 소요 예상.
    -   **NIKA/NetPress 연동**: 외부 코드를 가져와서 우리 Agent에 맞게 어댑터를 짜는 건 생각보다 복잡함 (환경 설정 헬).

### 🚨 Risk 2: 검증의 순환 논증 (Circular Reasoning)
-   **비판**: "Layer 1(Batfish 재현) 비중이 너무 크다(90% 이상). Layer 2(실측) 50개로는 통계적 유의성이 부족하다."
-   **대응**: Layer 2 샘플을 늘리기엔 시간이 부족함.
-   **방어 논리**: "50개 샘플에서 100% 일치한다면, 나머지 데이터의 신뢰도도 담보할 수 있다"는 귀납적 논리를 강화해야 함.

### 🚨 Risk 3: Baseline의 단순함
-   **비판**: "왜 Single LLM과만 비교했나? RAG 기반 시스템이나 다른 Agent 프레임워크(CrewAI 등)와는 왜 비교하지 않았나?"
-   **문제**: Related Work에서 언급한 타 연구(Cisco, INTA 등)는 코드가 비공개라 직접 비교 불가.
-   **대응**: "오픈소스 중 비교 가능한 대상이 부재함"을 강조하고, **GPT-4o (SOTA)**와의 비교를 통해 방어.

---

## 4. 구체적 개선 제안 (Action Plan)

### Phase 1: Core (무조건 달성) - 마감 D-10

1.  **DataSet v2 확정 및 검증 (Exp.1 & Exp.2)**
    -   `verify_dataset.py`로 L1-L5 일관성 100% 확보.
    -   GPT-OSS-20B 등 5개 모델 Baseline 실험 완료.
    -   **Table II, III 완성**.

2.  **NetAlly Core 실험 (Exp.3)**
    -   기존 10노드 랩에서 NetAlly 돌려서 L4/L5 성능 0.7 이상 찍기.
    -   **Table IV 완성**.

### Phase 2: Scalability (타협 가능) - 마감 D-7

1.  **Lab-B (20노드)만 수행**
    -   Lab-C(30), Lab-D(50)는 과감히 포기하거나 "Simulation Only"로 대체 고려 (PNETLab 배포 없이 Batfish만으로 실험).
    -   논문에는 "Scalability to 20 nodes with full emulation, up to 50 nodes with simulation"으로 기술.

### Phase 3: External Benchmark (최후순위) - 마감 D-5

1.  **NIKA 1개만 선택**
    -   3개(NIKA, NetPress, NetConfEval) 다 하는 건 불가능.
    -   가장 임팩트 큰 **NIKA (장애 진단)** 하나만 제대로 연동해서 "우리 Agent가 Root Cause도 잡는다" 보여주기.

---

## 5. 문서별 리뷰 코멘트

| 문서 | 상태 | 리뷰 코멘트 |
|---|:---:|---|
| **research_notes.md** | ⭐⭐⭐⭐ | Related Work 분석은 매우 강함. 다만 L6는 이번 제출 제외로 결정되었으므로, "코드 보존/실험 제외" 표기를 문서 전반에 통일해야 함. |
| **experiment_design.md** | ⭐⭐⭐⭐ | 설계는 좋으나 **Exp.4, 5의 분량이 너무 방대함**. 현실적인 축소 필요. |
| **verification_plan.md** | ⭐⭐⭐⭐⭐ | 3-Layer 접근은 매우 훌륭. **Layer 2 구현이 병목**이 될 수 있으니 수동 검증 병행 추천. |
| **lab_scalability_design.md** | ⭐⭐⭐ | 설계는 좋으나 **실구현(Engineering)** 비용이 과소평가됨. PNETLab 노드 50개 띄우면 서버 터질 수도 있음. |

---

## 6. 결론: "선택과 집중"

프로젝트의 방향성은 IEEE TNMS 투고에 손색이 없습니다. 다만, **엔지니어링 리소스의 한계**를 인정하고 실험 계획을 현실적으로 조정해야 합니다.

**추천 우선순위**:
1.  **Dataset Verification Code** (당장 시작)
2.  **NetAlly Integration** (기존 랩에서 성능 입증)
3.  **Lab-B (20노드)** 구축 (Config Gen은 간단하게)
4.  **NIKA** 연동 (여유 생기면)

---

## 7. 추가 기술 감사 (Code/Data Cross-Check)

> **작성자 추가 의견 (Codex 리뷰어 관점)**  
> **감사 시점**: 2026-02-13  
> **근거 범위**: `Make_Dataset/src`, `Data/Pnetlab/.../Dataset`, `README.md`, `NetAlly/README.md`, `NetAlly/docs/IEEE/*`

### 7.1 기존 비판 문서의 타당성 판정

| 항목 | 기존 판단 | 추가 판정 |
|---|---|---|
| Time Crunch | 매우 높음 | ✅ 타당. 오히려 **과소평가**됨 (핵심 스크립트 부재 + 실행환경 정리 미완료) |
| Circular Reasoning | Layer 2 부족 시 공격 가능 | ✅ 타당. Layer 2 실측이 논문 방어의 핵심 |
| Baseline 단순성 | 외부 비교 부족 | ✅ 타당. 다만 현재는 **검증 신뢰성 확보가 1순위**, 외부 벤치마크는 2순위 |
| Exp.4/5 축소 필요 | 필요 | ✅ 매우 타당. 현재 구현 상태 기준으로 필수 전략 |

### 7.2 새롭게 확인된 고위험 리스크 (문서에 추가 필요)

#### 🚨 Risk 4: 설계 문서와 실제 구현의 간극 (Implementation Gap)

- 문서에서 계획한 핵심 파일이 현재 저장소에 없음:
  - `Make_Dataset/src/verify_dataset.py`
  - `Make_Dataset/src/core_batfish/verifier.py`
  - `Make_Dataset/src/llm_judge.py`
  - `Make_Dataset/src/pnetlab_cross_validation.py`
  - `Make_Dataset/config_generator/` (YAML/Jinja2 기반 대규모 Lab 생성기)
- 결과: 검증/확장 실험의 일정 추정이 실제보다 낙관적으로 보일 수 있음.

#### 🚨 Risk 5: 데이터셋 재현성 메타데이터 결함

- v2 데이터셋(`2026-01-29`) 기준:
  - **1,128 rows 중 고유 ID는 431개** (ID 중복 다수)
  - **760 rows에서 evidence에 플레이스홀더(`{host}` 등) 잔존**
- 의미:
  - Layer 1 재현검증에서 "evidence 기반 재실행" 신뢰도가 크게 저하될 수 있음
  - FAIL 분석 시 row-level traceability 약화

#### 🚨 Risk 6: L6 주장과 공개 데이터 불일치

- 코드에는 L6 생성 로직이 있으나, 현재 공개된 대표 데이터셋 통계/산출물은 **L1-L5 중심**.
- 논문/초안 일부는 "6단계, 1,128 QA"를 단정적으로 표현.
- 리뷰어 관점에서는 "버전 혼재" 또는 "과장"으로 보일 수 있으므로 즉시 정합화 필요.

**결정 (2026-02-13): 이번 TNMS 제출에서 L6 제외**

- 제외 사유 1: fault별 snapshot/context를 문제 단위로 관리해야 해 재현 실험 비용이 급증
- 제외 사유 2: single-LLM baseline은 정상 config 중심 입력이어서 L6와 공정 비교가 어려움
- 제외 사유 3: 마감 일정 내에 "정확성 + 재현성"을 동시에 만족시키기 어려움

**조치 항목**

1. 코드 기본값: L6 비활성화 (`--include-l6` opt-in)
2. 평가/분석 스크립트: L6 기본 제외 필터 적용
3. 논문/설계 문서: 범위를 L1~L5로 통일하고 제외 사유를 명시

#### ⚠️ Risk 7: 실행 워크플로우의 이식성(Portability) 문제

- 운영 스크립트 일부에 절대 Windows 경로가 하드코딩되어 있어 환경 독립 재현이 어려움.
- `3-Check_Connectivity.py`는 현재 첫 장비 1대만 점검하여 대규모 Lab 검증 지표로는 부족.
- `lab_scalability_design.md`의 실행 커맨드 일부는 현재 스크립트 인자와 불일치.

#### ⚠️ Risk 8: L2 질문 보강 난이도

- v2 기준 L2 질문이 **21개뿐** (L1: 634, L3: 127 대비 극히 적음)
- `rule_based_generator.py`의 Scope Expansion이 L1(DEVICE scope)과 L5에만 효과적이고, L2(GLOBAL scope 집계)에는 확장 메커니즘이 약함
- 목표 50개를 채우려면 `policies.json`에 L2용 메트릭을 수동 추가하거나, GLOBAL scope에서도 집계 변형을 자동 생성하는 로직이 필요

#### ⚠️ Risk 9: TA-Acc 채점 코드 위치 분산

- 채점 코드가 레거시 폴더(`Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py`)에 존재
- NetAlly 자동 평가(Exp.3)에서 이 채점 로직을 재사용하려면 별도 통합 작업 필요
- 추론 코드: `Experiment/code/NetConfigQA2/run_netconfigqa_eval_vllm.py`

#### 🚨 Risk 10: Exp.3 NetAlly 자동 평가 파이프라인 부재

- NetAlly는 현재 **채팅 인터페이스 기반** — 1,128건 QA를 자동으로 풀려면 batch evaluation harness가 필요
- `NetAlly/eval/` 디렉토리가 있으나 벤치마크 자동 평가 기능은 미구현
- 비판 문서에서 "기존 랩에서 NetAlly 돌려서 성능 찍기"라고 했으나, **자동화 파이프라인 구현이 Exp.3의 실질적 병목**

#### 🚨 Risk 11: 질문 모호성으로 인한 채점 불안정

- 기존 `compare_*`(L3) 문항이 자유서술(text) 형식이라 모델이 같은 의미를 다른 표기법으로 답하면 오답 처리될 수 있음.
- `ibgp_fullmesh_ok`도 단일 문항에 다중 의도(상태+누락쌍)가 섞여 있어 정답 비교 안정성이 낮음.

**완화 조치 (2026-02-13 반영 완료)**

1. `compare_bgp_neighbor_count`, `compare_interface_count`, `compare_vrf_count`를 `map_str_int` 구조화 출력으로 고정
2. `ibgp_fullmesh_ok`를 `deprecated: true`, `submission_excluded: true`로 전환
3. 정책/데이터셋 검증기 추가:
   - `Make_Dataset/src/validate_policies.py`
   - `Make_Dataset/src/validate_dataset_quality.py`
4. 분석기 map 채점 강화:
   - strict key 비교 + value 타입 정규화
   - legacy text fallback은 허용하되 경고(`legacy_map_fallback_count`) 기록

### 7.3 TNMS 리뷰어 관점에서의 예상 공격 포인트

1. "3-Layer 검증이 실제로 구현되었는가, 아니면 설계 문서만 있는가?"
2. "L6를 주장하는데 공개 데이터/표는 왜 L1-L5인가?"
3. "Dataset row를 재현할 수 있는 식별자(ID/evidence)가 충분히 엄밀한가?"
4. "20/30/50 노드 확장이 자동 생성 가능한지 실제 코드가 있는가?"

---

## 8. 수정된 실행 우선순위 (Reviewer Defense 중심)

### P0 (48시간 이내) — 논문 신뢰성 방어선 확보

1. `verify_dataset.py` 최소 기능 구현 (L1-L5 우선, PASS/FAIL/SKIP 재현)
2. ~~Dataset ID 고유화 + evidence 플레이스홀더 제거~~ ✅ **완료** (`main_batfish.py`에 `id_v2`, evidence placeholder 게이트, 품질 게이트 반영)
3. v2(2026-01-29) 기준 검증 보고서 재생성 (`*_verification.md`, `*_failures.csv`)

### P1 (3일) — Layer 2 실측 방어력 확보

1. L4 30건 + L5 20건 PNETLab 교차검증 수행
2. 불일치 원인 3분류(모델링 한계/수렴 타이밍/데이터 오류)로 정리

### P2 (3~4일) — Scalability 최소 증거 확보

1. Lab-B(20노드) 단일 성공 사례를 우선 완성
2. Lab-C/Lab-D는 "simulation-only preliminary" 또는 future work로 명시

### P3 (잔여 시간) — External Benchmark 최소화

1. NIKA 단일 벤치마크 우선
2. NetPress/NetConfEval은 확장 실험 또는 부록 처리

---

## 9. 최종 권고 (한 줄)

**현재 문서의 전략적 방향은 옳다. 다만 TNMS 통과를 위해서는 "범위 확장"보다 "검증 구현 완성 + 버전 정합성 회복"이 먼저다.**

---

## 10. 즉시 착수 체크 (Kickoff: 2026-02-13)

1. `Make_Dataset/src/verify_dataset.py` + `Make_Dataset/src/core_batfish/verifier.py` 뼈대 구현
2. `Make_Dataset/config_generator/generator.py` + Lab-B YAML 템플릿 뼈대 구현
3. v2(1,128) 대상 ID/evidence 위생 정리 후 Layer 1 첫 PASS/FAIL/SKIP 리포트 산출
