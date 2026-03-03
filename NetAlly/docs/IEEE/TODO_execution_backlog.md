# IEEE TNMS 실행 TODO 백로그

> **작성일**: 2026-02-13 | **최종 업데이트**: 2026-03-02
> **목적**: 설계 문서를 실제 구현/실험 작업으로 전환하기 위한 실행 체크리스트
> **원칙**: 제출 필수(Core) 먼저, 확장(Stretch) 나중

---

## 0. 제출 필수 범위 (Scope Freeze)

1. 데이터셋 기준: **Lab-A 1,264 / Lab-B 2,154 / Lab-C 2,673 / Lab-D 3,371 (총 9,462 QA, L1~L5)**
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

### 이중언어 품질 개선 (Bilingual Quality)
- [x] `policies.json` 영어 템플릿 L1-L5 전면 교정 (문법/의미 45+건)
- [x] L4/L5 영어 템플릿 자연어 개선 (root_cause_analysis, loop_detection 등 11건)
- [x] 한국어 답변 형식 힌트를 영어 계약 토큰에 정렬 (NONE/ALLOWED/YES/NO 등 7건)
- [x] `ko_josa.py` 신규 — 한국어 조사(과/와) 동적 교정 유틸리티
- [x] `batfish_builder.py` 조사 교정 통합 (`_format_question()` 메서드, 20개소)
- [x] `main_batfish.py` L1-L3 질문 생성 후 조사 교정 호출 추가
- [x] `builder_core.py` "AS None" → "AS N/A" 수정 (compare_bgp_as, all_devices_same_as)
- [x] `docs/Policies.md` 이중언어 템플릿 가이드 섹션 추가

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

### 2.1 코드 + Config 생성 ✅ (2026-02-13 완료) + 추가 작업 ✅ (2026-02-18 완료)

- [x] `Make_Dataset/config_generator/generator.py` — 메인 생성 엔진
- [x] `Make_Dataset/config_generator/templates/*.j2` — 4종 (`pe_router`, `p_router`, `asbr_router`, `leaf_switch`)
- [x] `Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml` — 20노드 (2 Region, AS 65000)
- [x] `Make_Dataset/config_generator/topologies/lab_c_30nodes.yaml` — 30노드 (3 Region, AS 65000+65001)
- [x] `Make_Dataset/config_generator/topologies/lab_d_40nodes.yaml` — 40노드 (4 Region, 3-AS, QoS, NetFlow, 의도적 오류 3종)
- [x] Lab-B: 20/20 cfg 생성 완료
- [x] Lab-C: 30/30 cfg 생성 완료 (Multi-AS, L2VPN, ACL, HSRP)
- [x] Lab-D: 40/40 cfg 생성 완료 (FW waypoint, QoS, NetFlow, 의도적 오류 검증 통과)
- [x] **Lab-D 버그 수정 (2026-02-18)**: P11/P12 관리 IP 충돌(→10.10.10.55/56), ASBR1/ASBR2 OSPF area 불일치(→area 2) 수정
- [x] **Remap 기능 (2026-02-18)**: `generator.py --remap --lab` 인자 추가 (PNETLab node_id 순서 불일치 시 txt 재매핑)
  - CSV 헤더 자동 스킵 (`pnetlab_node_id,hostname` 형식 지원)
- [x] **Sample Remap CSV (2026-02-18)**: `config_generator/remap_samples/` — lab_b_remap.csv(20), lab_c_remap.csv(30), lab_d_remap.csv(40)
- [x] **IP 충돌 검증 (2026-02-18)**: Lab-B/C/D 전체 CLEAN — 관리 IP(10.10.10.x), 루프백(10.255.x.x), 데이터 서브넷 중복 없음
  - Lab-C/D 의 HSRP 172.18.1.0/24 3-endpoint 패턴은 의도된 설계 (PE5/PE6/Leaf9)
- [x] **PNETLab 배포 가이드 전면 업데이트 (2026-02-18)**: `config_generator/docs/deployment_guide.md`
  - Lab-D 전체 반영 (하드웨어, Config 생성, device_info.json, 검증 체크리스트, Appendix A.3 배선 테이블 48링크)
  - ASCII 시각 배치 다이어그램 (Lab-B 2-Region, Lab-C 3-Region, Lab-D 4-Region 2×2)
  - Config 적용 방법 재구성: Import Startup Config(1위) → Startup Editor(2위) → SSH(3위) → Console(4위)
  - Remap 절차 포함 (node_id 불일치 시)
  - Section 7 신규: NSO/NetAlly 연동 (아키텍처 다이어그램, Docker Node 설정, 접속 방법)

### 2.2 PNETLab 배포 + 데이터셋 생성

- [x] ~~PNETLab에 Lab-B 노드/링크 배치~~ → Batfish 직접 연결로 대체
- [x] `run_dataset_pipeline.sh --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes` → **2,154 QA** (2026-03-02)
- [x] `run_dataset_pipeline.sh --lab-path Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes` → **2,673 QA** (2026-03-02)
- [x] `run_dataset_pipeline.sh --lab-path Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes` → **3,371 QA** (2026-03-02)
- [ ] `run_verification_pipeline.py` — Lab-B/C/D Ground Truth 검증 (옵션)

완료 기준:
- [x] Lab-B/C/D 데이터셋 생성 + Quality Gate 통과
- [x] Lab-A 대비 스케일 비교표 작성 가능 (1,264 → 2,154 → 2,673 → 3,371)

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
[완료] 3. Config Generator 구현 + Lab-B/C/D cfg 전부 생성 + 배포 가이드
[완료] 4. Lab-B/C/D 데이터셋 생성 (run_dataset_pipeline.sh, 2026-03-02)
           Lab-A: 1,264 QA | Lab-B: 2,154 QA | Lab-C: 2,673 QA | Lab-D: 3,371 QA
       5. ★ Method 2 사람 검토 + Method 3 PNETLab 실행 (병렬, 6-9시간)
       6. Exp.2/3/4 실험 실행
       7. 논문 본문 작성
```

---

## 6. 코드 사용법 빠른 참조

```bash
# 데이터셋 생성 (한국어/영어 선택)
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/<LabName>/ \
  --policies Make_Dataset/policies.json \
  --question-lang ko   # ko 또는 en

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
