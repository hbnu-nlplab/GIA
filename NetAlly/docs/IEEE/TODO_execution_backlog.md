# IEEE TNMS 실행 TODO 백로그

> **작성일**: 2026-02-13 | **최종 업데이트**: 2026-02-13
> **목적**: 설계 문서를 실제 구현/실험 작업으로 전환하기 위한 실행 체크리스트
> **원칙**: 제출 필수(Core) 먼저, 확장(Stretch) 나중

---

## 0. 제출 필수 범위 (Scope Freeze)

1. 데이터셋 기준: v2 공개본 **~1,048 QA / L1~L5**
2. 필수 실험: Exp.1 ~ Exp.3 + Exp.4 최소증거(Lab-B)
3. 외부 벤치마크: NIKA 1개 우선
4. Lab-C / Lab-D / NetPress / NetConfEval: 확장 항목
5. L6는 코드 유지 + 문서화만 수행 (이번 제출 실험/평가에서는 제외)

---

## 0.1 완료 항목 (2026-02-13)

### 데이터셋 파이프라인
- [x] `policies.json` 메타 정규화 (`schema_version: 3.1`, `submission_scope: L1-L5`)
- [x] L3 고위험 `compare_*` 구조화 계약(`map_str_int`) 반영
- [x] `ibgp_fullmesh_ok` deprecated + submission 제외 처리
- [x] `validate_policies.py` 신규 추가
- [x] `validate_dataset_quality.py` 신규 추가
- [x] `main_batfish.py` 품질 게이트 반영
- [x] `analyze_results_netconfigqa.py` map 채점 강화

### Ground Truth 검증 (Method 1-2 + 통합 파이프라인)
- [x] `independent_parser.py` — Batfish-free CfgParser + TopologyFacts (~2,100 lines)
- [x] `compare.py` — TA-Acc 비교 함수 (~300 lines)
- [x] `run_verification.py` — Method 1 진입점 (L1-L3 전수 검증)
- [x] `run_manual_verification.py` — Method 2 진입점 (계층화 표본 + 자동 보조)
- [x] `run_verification_pipeline.py` — **통합 파이프라인** (3 Method 한 번에 실행)
- [x] Method 1 실행: **99.5%** (796/800), 실질 100%
- [x] Method 2 자동 보조: **97.7%** (42/43)
- [x] Method 2 사람 검토 가이드 생성: `human_reviewer_guide.md` + `blank_checklist.csv`
- [x] Method 3 PNETLab 가이드 생성: `pnetlab_verification_guide.md` + `blank_checklist.csv`
- [x] 통합 요약: `verification_summary.json`

---

## 1. P0 — 검증 마무리 (사람 실행 필요)

### 1.1 Method 2: 사람 검토 (~2-3시간)

- [ ] `human_reviewer_guide.md`를 연구자에게 전달
- [ ] 연구자가 43 QA를 .cfg 파일에서 직접 트레이스
- [ ] `blank_checklist.csv`에 결과 기입
- [ ] 작성된 CSV 수거 → 논문 증거

실행 위치: `Data/Pnetlab/Research_Institute_Internal_DC/Dataset/verification/method2_manual_check/`

### 1.2 Method 3: PNETLab 실행 (~4-6시간)

- [ ] PNETLab 서버에서 토폴로지 시작 + config 적용
- [ ] 프로토콜 수렴 확인 (`show ip ospf neighbor`, `show ip bgp summary`)
- [ ] Phase 1: L4 검증 23 QA (traceroute/ping/show)
- [ ] Phase 2: L5 검증 21 QA (shutdown + 도달성 + 원복)
- [ ] `blank_checklist.csv`에 결과 기입
- [ ] 작성된 CSV 수거 → 논문 증거

실행 위치: `Data/Pnetlab/Research_Institute_Internal_DC/Dataset/verification/method3_pnetlab/`

> **Method 2와 Method 3는 서로 다른 사람이 병렬 실행 가능**

---

## 2. P1 — Config Generator 구현

### 2.1 코드 스캐폴딩

- [ ] `Make_Dataset/config_generator/generator.py` 생성
- [ ] `Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml` 생성
- [ ] `Make_Dataset/config_generator/templates/*.j2` 최소 템플릿 생성 (`pe`, `p`, `ce`)

완료 기준:
```bash
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml
```

### 2.2 Lab-B 배포/검증

- [ ] PNETLab에 Lab-B 노드/링크 배치
- [ ] 생성 cfg 적용 + OSPF/BGP/LDP 수렴 확인
- [ ] `main_batfish.py --lab-path Data/Pnetlab/Lab_B_20nodes/`로 데이터셋 생성
- [ ] `run_verification_pipeline.py --lab-path Data/Pnetlab/Lab_B_20nodes/`로 검증

완료 기준:
- [ ] Lab-B 데이터셋 생성 + 검증 리포트 산출
- [ ] Lab-A 대비 스케일 비교표 작성 가능

---

## 3. P1 — 실험 실행

### 3.1 Exp.2 재실험 (Single LLM Baseline)

- [ ] v2 데이터셋으로 5개 모델 재평가 실행
- [ ] Level별 TA-Acc 테이블 갱신 (Table V)

### 3.2 Exp.3 재실험 (NetAlly vs Baseline)

- [ ] Lab-A 기준 NetAlly vs GPT-OSS-20B 비교
- [ ] Tool call success rate, latency 수집

### 3.3 Exp.4 최소 증거 (Scalability)

- [ ] Lab-A vs Lab-B 성능 비교 완성
- [ ] Lab-C는 가능할 때만 preliminary 추가

---

## 4. P2 — 논문 작성

- [ ] Section IV: Dataset Verification (검증 결과 → verification_plan.md 참조)
- [ ] Section V: Experimental Results (Exp.2/3/4 결과)
- [ ] Section III: Dataset Construction (파이프라인 설명)
- [ ] Section I-II: Introduction + Related Work
- [ ] Abstract + Conclusion

---

## 5. 빠른 실행 순서 (추천)

```
[완료] 1. Ground Truth 검증 자동화 (Method 1-2 코드 + 통합 파이프라인)
[완료] 2. Method 3 가이드 생성
       3. ★ Method 2 사람 검토 + Method 3 PNETLab 실행 (병렬, 6-9시간)
       4. Config Generator Lab-B 구현
       5. Lab-B 데이터셋 생성 + 검증
       6. Exp.2/3/4 실험 실행
       7. 논문 본문 작성
```

---

## 6. 코드 사용법 빠른 참조

```bash
# 데이터셋 생성
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/<LabName>/ \
  --policies Make_Dataset/policies.json

# Ground Truth 검증 (통합 파이프라인)
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path Data/Pnetlab/<LabName>/

# Method 1만 실행
python Make_Dataset/src/verification/run_verification.py \
  --configs Data/Pnetlab/<LabName>/configs/ \
  --dataset Data/Pnetlab/<LabName>/Dataset/<dataset>.json

# Method 2만 실행
python Make_Dataset/src/verification/run_manual_verification.py \
  --configs Data/Pnetlab/<LabName>/configs/ \
  --dataset Data/Pnetlab/<LabName>/Dataset/<dataset>.json \
  --policies Make_Dataset/policies.json \
  --method1 Data/Pnetlab/<LabName>/Dataset/verification/method1_independent_parser/ \
  --output Data/Pnetlab/<LabName>/Dataset/verification/method2_manual_check/
```
