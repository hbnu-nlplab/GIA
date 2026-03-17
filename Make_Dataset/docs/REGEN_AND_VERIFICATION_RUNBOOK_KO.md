# NetConfigQA 재생성 및 검증 Runbook

## 목적

이 문서는 다음 작업을 처음부터 끝까지 다시 수행하는 방법을 정리한다.

- 데이터셋 재생성
- 자동 검증 실행
- Method 3 외부 검증 준비
- Method 3 결과 반영

대상 경로는 현재 저장소 기준이다.

- repo root: `/home/kilab_pyj/codespace/GIA`
- policies: `/home/kilab_pyj/codespace/GIA/Make_Dataset/policies.json`

## 언제 다시 생성해야 하나

다음 중 하나라도 바뀌면 dataset을 다시 만드는 것이 맞다.

- `Make_Dataset/policies.json`
- `Make_Dataset/src/main_batfish.py`
- `Make_Dataset/src/core_batfish/*`
- 정답 canonicalization 로직
- 질문 템플릿

이번 경우는 `policies.json`의 질문 템플릿이 바뀌었으므로 재생성이 필요하다.

## 전체 흐름

작업 순서는 항상 아래처럼 간다.

1. dataset 생성
2. quality gate 확인
3. Method 1 실행
4. Method 2 실행
5. Method 3 가이드 생성
6. Method 4 실행
7. `verification_summary.json` 확인
8. 필요하면 Method 3 사람 검토 결과 반영

## 사전 조건

### 1. Batfish 컨테이너 실행 확인

예상 상태:

- host: `localhost`
- API: `9996`
- service: `batfish/allinone`

간단 확인:

```bash
docker ps | grep batfish
```

### 2. Python 환경

repo root에서 실행:

```bash
cd /home/kilab_pyj/codespace/GIA
```

### 3. Lab 경로 확인

예시:

- `/home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabA_Research_Institute_DC_10nodes`
- `/home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabB_NCN_Basic_SP_20nodes`
- `/home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes`
- `/home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes`

## 단일 Lab 재생성 + 검증

여기서는 `LabD`를 예시로 든다.

### Step 1. dataset 재생성

```bash
cd /home/kilab_pyj/codespace/GIA

bash Make_Dataset/run_dataset_pipeline.sh \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --policies /home/kilab_pyj/codespace/GIA/Make_Dataset/policies.json \
  --batfish-host localhost \
  --question-lang ko
```

이 단계가 끝나면 보통 아래가 생성된다.

- `Dataset/<timestamp>/*_dataset_batfish_*.json`
- `Dataset/<timestamp>/*_dataset_batfish_*.csv`
- `Dataset/<timestamp>/*_quality_report.json`
- `Dataset/<timestamp>/*_statistics.md`

### Step 2. 통합 검증 실행

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --batfish-host localhost
```

이 단계가 끝나면 아래가 생성된다.

- `Dataset/verification/method1_independent_parser/`
- `Dataset/verification/method2_manual_check/`
- `Dataset/verification/method3_pnetlab/`
- `Dataset/verification/method4_l45_replay/`
- `Dataset/verification/verification_summary.json`

### Step 3. 핵심 결과 확인

확인 파일:

- `Dataset/verification/verification_summary.json`

중점 항목:

- `method1_independent_parser.match == total_verified`
- `method4_l45_replay.match == total_verified`
- `method4_l45_replay.quarantined == 0`

## LabA-D 전체 재생성 + 검증

아래 루프를 그대로 쓰면 된다.

```bash
cd /home/kilab_pyj/codespace/GIA

for LAB in \
  /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabA_Research_Institute_DC_10nodes \
  /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabB_NCN_Basic_SP_20nodes \
  /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabC_NCN_Security_L2VPN_30nodes \
  /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes
do
  bash Make_Dataset/run_dataset_pipeline.sh \
    --lab-path "$LAB" \
    --policies /home/kilab_pyj/codespace/GIA/Make_Dataset/policies.json \
    --batfish-host localhost \
    --question-lang ko

  python Make_Dataset/src/verification/run_verification_pipeline.py \
    --lab-path "$LAB" \
    --batfish-host localhost
done
```

## 부분 재실행

전체를 다시 돌릴 필요가 없을 때 쓴다.

### Method 3만 다시 생성

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --skip-method1 --skip-method2 --skip-method4
```

### Method 4만 다시 실행

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --skip-method1 --skip-method2 --skip-method3 \
  --batfish-host localhost
```

### 기존 결과를 유지한 채 Method 3 결과만 반영

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --skip-method1 --skip-method2 --skip-method4 \
  --method3-review /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/Dataset/verification/method3_pnetlab/reviewed_checklist.csv
```

## Method 3 실무 절차

### 생성되는 파일

각 Lab의 아래 디렉터리를 본다.

- `Dataset/verification/method3_pnetlab/`

주요 파일:

- `pnetlab_verification_guide.md`
- `blank_checklist.csv`
- `sample_manifest.json`
- `sample_selection.md`
- `review_protocol.md`

### 사람이 해야 하는 일

1. `blank_checklist.csv`를 복사
2. 이름을 `reviewed_checklist.csv`로 저장
3. guide를 보며 PNETLab에서 실제 명령 실행
4. `my_result`, `verdict`, `memo` 기입

`verdict` 허용값:

- `AGREE`
- `DISAGREE`
- `SKIP`

### 결과 반영

위에서 소개한 `--method3-review` 명령으로 통합 summary에 반영한다.

반영 후 생성/갱신 파일:

- `Dataset/verification/method3_pnetlab/method3_verification_summary.json`
- `Dataset/verification/verification_summary.json`

## 어떤 문서를 먼저 보면 되나

### 운영 순서

- [VERIFICATION_PIPELINE_USAGE_KO.md](/home/kilab_pyj/codespace/GIA/Make_Dataset/docs/VERIFICATION_PIPELINE_USAGE_KO.md)

### Method 3 우선순위

- [METHOD3_EXTERNAL_VALIDATION_PRIORITY_KO.md](/home/kilab_pyj/codespace/GIA/Make_Dataset/docs/METHOD3_EXTERNAL_VALIDATION_PRIORITY_KO.md)

### 검증 방법론 설명

- [GROUND_TRUTH_VALIDATION_METHODOLOGY.md](/home/kilab_pyj/codespace/GIA/Make_Dataset/docs/GROUND_TRUTH_VALIDATION_METHODOLOGY.md)

### 논문 초안

- [PAPER_VALIDATION_SECTION_DRAFT_KO.md](/home/kilab_pyj/codespace/GIA/Make_Dataset/docs/PAPER_VALIDATION_SECTION_DRAFT_KO.md)

### 정책 템플릿 점검 메모

- [POLICY_TEMPLATE_REVIEW_KO.md](/home/kilab_pyj/codespace/GIA/Make_Dataset/docs/POLICY_TEMPLATE_REVIEW_KO.md)

## 재채점 주의

현재는 기존 평가 결과를 그대로 쓰면 안 된다.

이유:

- dataset 정답이 일부 수정되었음
- 질문 템플릿도 수정되었음
- verification summary와 paper-ready dataset도 다시 생성되었음

즉 평가를 다시 하려면 반드시 최신 dataset 기준으로 입력을 다시 맞춰야 한다.

## 빠른 체크리스트

### 자동 검증 완료 조건

- Method 1 `100%`
- Method 4 `100%`
- Method 4 `quarantined = 0`

### 외부 검증 완료 조건

- `reviewed_checklist.csv` 작성 완료
- `method3_verification_summary.json` 생성 완료
- `DISAGREE` 항목이 있으면 별도 분석

## 추천 운영 방식

### 1. 지금 바로 할 일

- LabA-D 전체 재생성
- LabA-D 전체 통합 검증

### 2. 그 다음

- Method 3 Tier 1 샘플부터 PNETLab 확인

### 3. 마지막

- Method 3 결과 반영
- 필요한 경우 mismatch metric만 재분석
