# IEEE TNSM 논문 — 실험 및 검증 체크리스트

> **마감**: 2026-02-28 (IEEE TNSM)  
> **갱신**: 2026-02-18  
> **범위**: L1~L5 (L6는 Future Work)

---

## 1. Ground Truth 검증

### Method 1: Independent Config Parser — 완료

- [x] Batfish-free Python+Regex 파서로 L1~L3 전수 800건 독립 재검증
- **결과**: 99.5% 일치 (796/800), 4건 불일치는 Batfish VRF 이중 카운팅 (실질 100%)
- 산출물: `verification/method1_independent_parser/`

### Method 2: 계층화 수동 검증 — 사람 실행 대기

- [x] 자동 교차검증 코드 실행 (97.7%, 42/43)
- [x] 사람 검토 가이드 + 빈 체크리스트 CSV 생성
- [ ] **연구자가 43건을 .cfg에서 직접 트레이스** (~2-3시간)
- [ ] 작성된 CSV 수거 → 논문 증거
- 경로: `verification/method2_manual_check/`

### Method 3: PNETLab CLI 검증 — 사람 실행 대기

- [x] 검증 가이드 + 빈 체크리스트 CSV 생성
- [ ] PNETLab 토폴로지 시작 + config 적용 + 프로토콜 수렴 확인
- [ ] L4 검증 23건 (traceroute/ping/show ip route)
- [ ] L5 검증 21건 (interface shutdown → 도달성 확인 → 원복)
- [ ] 작성된 CSV 수거 → 논문 증거
- 경로: `verification/method3_pnetlab/`
- 소요: 4-6시간 (Method 2와 병렬 가능)

---

## 2. 실험

### Exp.1: Dataset Statistics — 완료

- [x] Lab-A 1,029 QA, 5단계(L1~L5), 126 메트릭, 17 카테고리 정리 완료

### Exp.2: Single LLM Baseline — 재실험 필요

KICS 기존 결과 (참고):

| 모델 | L1 | L2 | L3 | L4 | L5 | 전체 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| GPT-4o-mini | 0.806 | 0.806 | 0.494 | 0.211 | 0.141 | 0.611 |
| GPT-OSS-20B | 0.873 | 0.873 | 0.605 | 0.266 | 0.134 | 0.672 |
| Llama-3.1-8B | 0.530 | 0.443 | 0.261 | 0.144 | 0.102 | 0.387 |
| Mistral3-8B | 0.663 | 0.557 | 0.389 | 0.174 | 0.134 | 0.477 |
| Qwen3-8B | 0.746 | 0.741 | 0.485 | 0.201 | 0.157 | 0.560 |

- [x] KICS 결과 확보
- [ ] v2 데이터셋(1,029건)으로 5개 모델 재실험
- [ ] GPT-4o 추가 실험 (가능한 경우)
- 코드: `Experiment/code/NetConfigQA2/run_netconfigqa_eval_vllm.py`
- 채점: `Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py`

### Exp.3: NetAlly MAS 평가 — 미착수 (핵심)

- [ ] NetAlly batch evaluation harness 구현 (현재 채팅 인터페이스만 존재)
- [ ] Lab-A 기준 NetAlly 평가 실행 (1,029건)
- [ ] TA-Acc per Level 비교표 작성 (vs GPT-OSS-20B)
- [ ] Tool Usage 분석 + Error 유형 분류
- 참고: NetAlly에 QA를 자동 투입하는 batch 파이프라인이 아직 없음 (`NetAlly/eval/` 구현 필요)

### Exp.4: Scalability — Lab-B 배포 필요

| Lab | 노드 | Config | PNETLab 배포 | 데이터셋 | LLM 실험 |
|---|:---:|:---:|:---:|:---:|:---:|
| Lab-A | 10 | 완료 | 완료 | 완료 (1,029) | 완료 (KICS) |
| Lab-B | 20 | 완료 | 미완 | 미완 | 미완 |
| Lab-C | 30 | 완료 | 미완 | 미완 | 미완 |
| Lab-D | 40 | 완료 (버그 수정 완료) | 미완 | 미완 | 미완 |

- [x] Config Generator + Lab-B/C/D cfg 전부 생성
- [x] Lab-D 버그 수정 (P11/P12 IP 충돌, ASBR OSPF area)
- [x] 배포 가이드 작성 (`config_generator/docs/deployment_guide.md`)
- [ ] Lab-B PNETLab 배포 + 수렴 확인
- [ ] `main_batfish.py`로 데이터셋 생성 + 검증
- [ ] Single LLM으로 Lab-B 평가 → Lab-A 대비 비교

### Exp.5: 외부 벤치마크 (NIKA) — 시간 여유 시

- [ ] NIKA 연동 + NetAlly 평가 (선택 사항)

---

## 3. Error Analysis — 미완

- [ ] Best Single LLM의 L4/L5 오답 30건 샘플링
- [ ] 오류 유형 분류 (경로 복잡도 / VRF 격리 미이해 / 장애 전파 / IP 혼동)
- [ ] 유형별 건수 집계

---

## 4. 논문 작성 현황

| 섹션 | 상태 | 비고 |
|---|:---:|---|
| Abstract | 완료 | L1~L5 범위 명시 필요 |
| I. Introduction | 완료 | — |
| II. Related Work | 완료 | — |
| III. NetConfigQA 2.0 | 완료 | Method 3 결과 추가 필요 |
| IV. NetAlly Architecture | 완료 | — |
| V-A. Single LLM Baseline | 완료 | v2 재실험 후 수치 교체 |
| V-B. NetAlly MAS 결과 | 미완 | Exp.3 후 작성 |
| V-C. Scalability 결과 | 미완 | Lab-B 후 작성 |
| V-D. Error Analysis | 미완 | 30건 분석 후 작성 |
| VI. Discussion | 완료 | 결과 반영 시 조정 |
| VII. Conclusion | 완료 | 결과 반영 시 조정 |
| Acknowledgment | 미완 | — |
| References | 초안 | DOI 추가 필요 |
| Biography (3인) | 미완 | 각자 작성 |

---

## 5. 실행 순서 (추천)

| 순서 | 작업 | 소요 | 비고 |
|:---:|---|:---:|---|
| 1 | Method 2 사람 검토 (43건) | 2-3h | 병렬 가능 |
| 1 | Method 3 PNETLab CLI (44건) | 4-6h | 병렬 가능 |
| 2 | Exp.2 재실험 (5개 모델) | 1-2일 | |
| 2 | Lab-B PNETLab 배포 + 데이터셋 | 1일 | |
| 3 | Exp.3 NetAlly 평가 (batch 구현 포함) | 2-3일 | 핵심 |
| 3 | Exp.4 Lab-B 성능 평가 | 1일 | |
| 4 | Error Analysis (30건) | 0.5일 | |
| 5 | 논문 본문 최종 작성 | 2-3일 | |

---

## 6. 코드 위치

```bash
# 데이터셋 생성
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/<LabName>/ \
  --question-lang ko

# Ground Truth 검증 (통합)
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path Data/Pnetlab/<LabName>/

# Config 생성
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml

# Config Remap (node_id 불일치 시)
python Make_Dataset/config_generator/generator.py \
  --remap Make_Dataset/config_generator/remap_samples/lab_b_remap.csv \
  --lab LabB_NCN_Basic_SP_20nodes

# LLM 평가
python Experiment/code/NetConfigQA2/run_netconfigqa_eval_vllm.py
python Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py
```
