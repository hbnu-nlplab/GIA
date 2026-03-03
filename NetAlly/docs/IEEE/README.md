# IEEE TNMS 논문 준비 — 문서 인덱스

> **최종 업데이트**: 2026-03-02
> **프로젝트**: NetAlly + NetConfigQA2.0
> **학회**: IEEE Transactions on Network and Service Management (TNMS)
> **마감**: 2026-02-28

> **실행 기준 (Rebaseline, 2026-02-13 → 2026-02-18 갱신)**
> - 공개 v2 데이터셋 기준: **1,128 QA, L1~L5, 17 카테고리**
> - L6는 코드 경로는 유지하되, 이번 TNMS 제출에서는 **명시적으로 제외**
>   (이유: fault별 스냅샷/관측정보 관리 비용, single-LLM baseline 공정성 저하, 일정 내 재현성 리스크)
> - ~~구현 착수 항목~~: `verify_dataset.py` 계열 ✅, `Make_Dataset/config_generator/` 계열 ✅ (Lab-B/C/D 전부 생성 완료)
> - ~~배포 가이드~~ ✅: `deployment_guide.md` 대폭 업데이트 (Lab-D, NSO/NetAlly 연동, ASCII 배치 다이어그램, Remap 기능)
> - ~~Lab-D 버그 수정~~ ✅: P11/P12 관리 IP 충돌 해소, ASBR1/ASBR2 OSPF area 불일치 수정
> - ~~IP 충돌 검증~~ ✅: Lab-B/C/D 전체 CLEAN (관리 IP·루프백·서브넷 중복 없음)

---

## 문서 구조 (11개)

```
NetAlly/docs/IEEE/
├── README.md                ← 이 문서 (인덱스)
│
├── 연구 참조
│   └── research_notes.md        ← Related Work 16편, 연구 철학, TA-Acc, 아키텍처
│
├── 논문 초안
│   ├── paper_plan.md            ← 스토리라인 + 섹션 구성
│   ├── paper_draft.md           ← 영문 초안 (v1)
│   └── paper_draft_ko.md        ← 한글 초안 (v2)
│
├── 실험 설계
│   ├── experiment_design.md     ← 5개 실험 상세 (6모델, 4Lab, TA-Acc)
│   ├── lab_scalability_design.md ← Lab A→D 토폴로지 + Config Generator
│   └── verification_plan.md     ← 3-Method Ground Truth 검증
│
├── 실행 관리
│   └── TODO_execution_backlog.md ← 실행 체크리스트 + 우선순위
│
├── 외부 벤치마크
│   └── benchmark_compatibility.md ← NIKA, NetPress 등 5종 적합성
│
└── bare_jrnl.tex               ← IEEE 템플릿 (빈 껍데기)
```

---

## 📄 문서별 요약 & 읽는 순서

### 읽는 순서

| 순서 | 문서 | 내용 |
|:---:|---|---|
| ① | [research_notes.md](./research_notes.md) | Related Work 16편, 연구 철학, TA-Acc, 아키텍처 |
| ② | [experiment_design.md](./experiment_design.md) | 5개 실험 (Exp.1~5), 6모델, 4Lab, Table/Figure 형식 |
| ③ | [paper_plan.md](./paper_plan.md) | 논문 스토리라인 + 섹션 구성 |
| ④ | [lab_scalability_design.md](./lab_scalability_design.md) | Lab A→D 토폴로지, Config Generator |
| ⑤ | [verification_plan.md](./verification_plan.md) | 3-Method 검증 (Method 1-2 완료) |
| ⑥ | [benchmark_compatibility.md](./benchmark_compatibility.md) | 외부 벤치마크 5종 적합성 |
| ⑦ | [TODO_execution_backlog.md](./TODO_execution_backlog.md) | 실행 체크리스트 |

---

## 문서 관계

```
research_notes.md ──→ experiment_design.md ──→ verification_plan.md
       │                     │                       │
       ↓                     ↓                       ↓
  paper_plan.md    lab_scalability_design.md   benchmark_compatibility.md
       │
       ↓
  paper_draft.md / paper_draft_ko.md
```

---

## 📊 논문 핵심 수치 (Quick Reference)

### 데이터셋

| 항목 | 값 |
|---|---|
| Lab-A QA | **1,264** (L1:660, L2:104, L3:252, L4:146, L5:102) — 10노드 |
| Lab-B QA | **2,154** (L1:1230, L2:101, L3:255, L4:441, L5:127) — 20노드 |
| Lab-C QA | **2,673** (L1:1230, L2:80, L3:255, L4:954, L5:154) — 30노드 |
| Lab-D QA | **3,371** (L1:1230, L2:69, L3:253, L4:1657, L5:162) — 40노드 |
| **총 QA** | **9,462** (전 Lab 합산) |
| 언어 | 이중언어 (KO/EN) — 질문은 한국어/영어 선택, 정답은 영어 계약 토큰 |
| 난이도 레벨 | 5 (L1~L5) |
| 카테고리 | 17 |
| 메트릭 | 127 |
| Answer Type | 5 (text, numeric, set, map, bool) |
| 토폴로지 | Lab-A(10), Lab-B(20), Lab-C(30), Lab-D(40) — NCN 시리즈 (SP/MPLS/L2VPN/Multi-AS) |

### Ground Truth 검증 결과

| Method | Scope | Sample | Raw Agreement | Effective |
|---|---|---:|---:|---:|
| (1) Independent Parser | L1-L3 전수 | 800 | 99.5% | **100%** |
| (2) Manual Cfg Trace | L1-L3 표본 | 43 | 97.7% | 97.7% |
| (3) PNETLab Emulation | L4-L5 표본 | 44 | TBD | TBD |

### KICS 실험 결과 (Best: GPT-OSS-20B)

| Level | TA-Acc | 의미 |
|:---:|:---:|---|
| L1 | 0.873 | 대부분 정확 |
| L2 | 0.873 | L1과 유사 (소규모 샘플) |
| L3 | 0.605 | 교차 비교에서 성능 하락 시작 |
| **L4** | **0.266** | 급격한 절벽 ← 시뮬레이션 필요 |
| **L5** | **0.134** | 사실상 실패 ← What-If 불가 |

### Related Work

| 분류 | 논문 수 |
|---|:---:|
| 내부 벤치마크 비교 | 3 (TeleQnA, TeleQuAD, NetBench) |
| Agent 기반 네트워크 관리 | 5 (NIKA, INTA, Cisco, NetConfEval, KubeLLM) |
| 외부 벤치마크 | 3 (NetPress, NeMoEval, NETLLMBENCH) |
| 도메인 LLM / IBN | 4 (TelecomGPT, RAG-Intent, IntAgent, NetIntent) |
| 기타 | 1 (IETF Framework) |
| **총 참고문헌** | **16+** |

---

## ⏰ 마감까지 남은 작업

| 작업 | 상태 | 문서 참조 |
|---|:---:|---|
| 이중언어 템플릿 품질 교정 (EN L4/L5 + KO 조사 + 답변 힌트 정렬) | ✅ | docs/Policies.md |
| 검증 코드 구현 (Method 1-2) + 통합 파이프라인 | ✅ | verification_plan.md |
| 검증 Method 3 가이드 생성 | ✅ | verification_plan.md (44 QA 가이드 완료) |
| Method 2 사람 검토 (43 QA, ~2-3h) | ⬜ | verification/method2_manual_check/human_reviewer_guide.md |
| Method 3 PNETLab 실행 (44 QA, ~4-6h) | ⬜ | verification/method3_pnetlab/pnetlab_verification_guide.md |
| Config Generator + Lab-B/C/D cfg 생성 | ✅ | lab_scalability_design.md (20+30+40 = 90 configs) |
| Lab-D 버그 수정 (P11/P12 IP, ASBR OSPF area) | ✅ | config_generator/topologies/lab_d_40nodes.yaml |
| Remap 기능 + Sample CSV (Lab-B/C/D) | ✅ | config_generator/generator.py `--remap`, remap_samples/ |
| 배포 가이드 전면 업데이트 (Lab-D, NSO/NetAlly, 배치 다이어그램) | ✅ | config_generator/docs/deployment_guide.md |
| IP 충돌 검증 (Lab-B/C/D 전체) | ✅ | 관리 IP·루프백·서브넷 모두 CLEAN |
| Lab-B/C/D PNETLab 배포 + 데이터셋 생성 | ✅ **완료** (2026-03-02) | config_generator/docs/deployment_guide.md |
| v2 데이터셋 재실험 (5 Models) | ⬜ | experiment_design.md Exp.2 |
| NetAlly 데이터셋 평가 | ⬜ | experiment_design.md Exp.3 |
| NIKA 적용 실험 | ⬜ | benchmark_compatibility.md |
| 논문 본문 작성 | ⬜ | paper_plan.md |

---

## 🧭 실행 시작점

1. **검증 완료**: Method 2 사람 검토 + Method 3 PNETLab 실행 (병렬 가능, 총 6-9시간)
2. [TODO_execution_backlog.md](./TODO_execution_backlog.md)에서 P0 항목부터 실행
3. [lab_scalability_design.md](./lab_scalability_design.md)의 Lab-B 단일 성공 사례 확보

---

## ⚙️ 데이터셋 원샷 실행 (현재 권장)

아래 명령으로 정책 검증 → 데이터셋 생성 → 품질검증 → 통계요약까지 한 번에 실행합니다.

> **주의**: 이 원샷 파이프라인은 **Dataset Integrity QA(데이터 품질/스키마 무결성)** 용도이며,  
> Ground Truth 본검증(Method 1/2/3)은 `verification_plan.md`에 정의된 별도 절차로 수행합니다.

```bash
# Lab-A (✅ 완료 — 1,264 QA)
bash Make_Dataset/run_dataset_pipeline.sh
# Lab-B (✅ 완료 — 2,154 QA)
bash Make_Dataset/run_dataset_pipeline.sh --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes
# Lab-C (✅ 완료 — 2,673 QA)
bash Make_Dataset/run_dataset_pipeline.sh --lab-path Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes
# Lab-D (✅ 완료 — 3,371 QA)
bash Make_Dataset/run_dataset_pipeline.sh --lab-path Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes
```

산출물은 `Data/Pnetlab/<LabName>/Dataset/<timestamp>/` 하위에 실행별로 분리 저장되며, bilingual 모드에서는 `..._ko.json/csv`와 `..._en.json/csv`가 함께 생성됩니다.

## 🔬 Ground Truth 검증 파이프라인

데이터셋 생성 후 Ground Truth 검증을 단일 명령으로 실행합니다 (3가지 Method 통합):

```bash
# 전체 파이프라인: Method 1 (자동) + Method 2 가이드 + Method 3 가이드
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path Data/Pnetlab/Research_Institute_Internal_DC/

# 이미 Method 1을 돌린 경우
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path Data/Pnetlab/<LabName>/ --skip-method1
```

산출물: `Data/Pnetlab/<LabName>/Dataset/verification/` 하위에 Method별로 분리 저장됩니다.
