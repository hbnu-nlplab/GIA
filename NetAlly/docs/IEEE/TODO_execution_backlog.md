# IEEE TNMS 실행 TODO 백로그

> **작성일**: 2026-02-13  
> **목적**: 설계 문서를 실제 구현/실험 작업으로 전환하기 위한 실행 체크리스트  
> **원칙**: 제출 필수(Core) 먼저, 확장(Stretch) 나중

---

## 0. 제출 필수 범위 (Scope Freeze)

1. 데이터셋 기준: v2 공개본 **1,128 QA / L1~L5**
2. 필수 실험: Exp.1 ~ Exp.3 + Exp.4 최소증거(Lab-B)
3. 외부 벤치마크: NIKA 1개 우선
4. Lab-C / Lab-D / NetPress / NetConfEval: 확장 항목
5. L6는 코드 유지 + 문서화만 수행 (이번 제출 실험/평가에서는 제외)

---

## 1. P0 — 검증 파이프라인 구현 (최우선)

### 1.1 Layer 1 검증 코드

- [ ] `Make_Dataset/src/verify_dataset.py` 신규 생성
- [ ] `Make_Dataset/src/core_batfish/verifier.py` 신규 생성
- [ ] L1~L3 재현 함수 (BuilderCore 기반) 구현
- [ ] L4~L5 재현 함수 (BatfishBuilder 기반) 구현
- [ ] PASS/FAIL/SKIP 판정 및 CSV/MD 보고서 출력 구현

완료 기준:
- [ ] `*_verification.md` 생성
- [ ] `*_verification_failures.csv` 생성
- [ ] 1,128건 전체에 대해 status가 산출됨

### 1.2 데이터셋 메타데이터 위생 정리

- [ ] ID 고유화 규칙 적용 (`id` 중복 제거)
- [ ] evidence 내 `{host}` 등 placeholder 제거
- [ ] `answer_type` 정규화 규칙 점검 (`text/number/numeric/set/map/bool`)

완료 기준:
- [ ] 고유 ID 개수 = 총 row 수
- [ ] evidence placeholder 포함 row = 0

---

## 2. P1 — Layer 2/3 검증 구현

### 2.1 Layer 2 (PNETLab 교차검증)

- [ ] `Make_Dataset/src/pnetlab_cross_validation.py` 신규 생성
- [ ] L4 30건 traceroute 비교 자동화
- [ ] L5 20건 link-failure 비교 자동화
- [ ] 불일치 원인 분류(모델링/수렴/데이터) 리포트 컬럼 추가

완료 기준:
- [ ] 50건 결과표(일치/불일치) 생성
- [ ] 논문 Table용 요약 수치(%) 산출

### 2.2 Layer 3 (LLM-as-Judge)

- [ ] `Make_Dataset/src/llm_judge.py` 신규 생성
- [ ] L1~L5 각 20건 샘플링
- [ ] 점수 JSON 및 평균표 생성

완료 기준:
- [ ] `*_llm_judge_results.json` 생성
- [ ] Clarity/Correctness/Level/Educational 평균 산출

---

## 3. P1 — Config Generator 구현 (지금부터 착수)

### 3.1 코드 스캐폴딩

- [ ] `Make_Dataset/config_generator/generator.py` 생성
- [ ] `Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml` 생성
- [ ] `Make_Dataset/config_generator/templates/*.j2` 최소 템플릿 생성 (`pe`, `p`, `ce`)

완료 기준:
- [ ] 아래 명령으로 cfg 자동 생성

```bash
python Make_Dataset/config_generator/generator.py \
  --topology Make_Dataset/config_generator/topologies/lab_b_20nodes.yaml
```

### 3.2 Lab-B 배포/검증

- [ ] PNETLab에 Lab-B 노드/링크 배치
- [ ] 생성 cfg 적용
- [ ] OSPF/BGP/LDP 수렴 확인
- [ ] `main_batfish.py --lab-path Data/Pnetlab/Lab-B`로 데이터셋 생성

완료 기준:
- [ ] Lab-B 데이터셋 CSV/JSON 산출
- [ ] Lab-A 대비 스케일 비교표 작성 가능

---

## 4. P2 — 실험 실행

### 4.1 Exp.2 재실험 (Single LLM)

- [ ] v2(1,128) 재평가 실행
- [ ] Level별 TA-Acc 테이블 갱신

### 4.2 Exp.3 재실험 (NetAlly)

- [ ] Lab-A 기준 NetAlly vs GPT-OSS-20B 비교
- [ ] Tool call success rate, latency 수집

### 4.3 Exp.4 최소 증거

- [ ] Lab-A vs Lab-B 성능 비교 완성
- [ ] Lab-C는 가능할 때만 preliminary 추가

---

## 5. P3 — 문서 정합성 정리

- [ ] README/계획서에서 "L1~L5 제출 범위" 통일
- [ ] L6는 "이번 제출 제외"로 통일하고 제외 사유(스냅샷 관리/공정성/재현성) 명시
- [ ] 구현 완료된 파일명/경로를 문서에 실제 경로로 반영
- [ ] 최종 제출 직전 문서 날짜/버전 일괄 업데이트

---

## 6. 빠른 실행 순서 (추천)

1. Layer 1 검증 코드 작성 (`verify_dataset.py`, `verifier.py`)
2. 데이터셋 위생 정리 (ID/evidence)
3. Layer 1 전수검증 리포트 생성
4. Config Generator Lab-B 최소버전 구현
5. Layer 2 교차검증 50건
6. Exp.2/Exp.3/Exp.4 표 작성
