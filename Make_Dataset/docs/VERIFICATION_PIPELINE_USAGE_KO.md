# NetConfigQA 검증 파이프라인 사용법

## 목적

이 문서는 NetConfigQA 데이터셋의 정답 검증 파이프라인을 실제로 어떻게 사용하는지 정리한다.

재생성부터 검증까지 한 번에 다시 수행하는 상세 절차는 아래 문서를 함께 본다.

- [REGEN_AND_VERIFICATION_RUNBOOK_KO.md](/home/kilab_pyj/codespace/GIA/Make_Dataset/docs/REGEN_AND_VERIFICATION_RUNBOOK_KO.md)

현재 파이프라인은 네 가지 검증 방법을 하나로 묶는다.

- Method 1: `L1-L3` 독립 parser 전수 검증
- Method 2: `L1-L3` 사람 기반 표본 검증
- Method 3: `L4-L5` PNETLab 실환경 표본 검증
- Method 4: `L4-L5` Batfish replay 전수 검증

## 핵심 원칙

- `L1-L3`는 config parsing 기반 사실 추출 문제다.
- `L4-L5`는 reachability, traceroute, what-if, root cause 같은 네트워크 의미론 문제다.
- 따라서 `L4-L5`는 Batfish replay와 PNETLab 외부 검증을 함께 본다.
- 논문용 retained set은 전수 자동 검증을 통과한 row 기준으로 관리한다.

## 기본 실행 순서

### 1. 데이터셋 생성

```bash
bash Make_Dataset/run_dataset_pipeline.sh \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --policies /home/kilab_pyj/codespace/GIA/Make_Dataset/policies.json \
  --batfish-host localhost \
  --question-lang ko
```

### 2. 전체 검증 실행

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --batfish-host localhost
```

이 명령은 다음을 만든다.

- `Dataset/verification/method1_independent_parser/`
- `Dataset/verification/method2_manual_check/`
- `Dataset/verification/method3_pnetlab/`
- `Dataset/verification/method4_l45_replay/`
- `Dataset/verification/verification_summary.json`

## 부분 실행

이미 일부 결과가 있을 때는 필요한 방법만 다시 돌릴 수 있다.

### Method 3만 다시 생성

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --skip-method1 --skip-method2 --skip-method4
```

### Method 4만 다시 검증

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --skip-method1 --skip-method2 --skip-method3 \
  --batfish-host localhost
```

## Method 3 운영 절차

Method 3는 `L4-L5`를 실제 PNETLab에서 표본 검증하는 단계다.

생성되는 주요 파일:

- `pnetlab_verification_guide.md`
- `blank_checklist.csv`
- `sample_manifest.json`
- `review_protocol.md`

### 검토 절차

1. `blank_checklist.csv`를 복사해 `reviewed_checklist.csv`로 저장
2. PNETLab에서 guide를 따라 ping/traceroute/shutdown 테스트 수행
3. `my_result`, `verdict`, `memo`를 기입
4. `verdict`는 `AGREE`, `DISAGREE`, `SKIP`만 사용

### Method 3 결과를 통합 summary에 반영

```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes \
  --skip-method1 --skip-method2 --skip-method4 \
  --method3-review /home/kilab_pyj/codespace/GIA/Data/Pnetlab/LabD_NCN_MultiAS_Complex_40nodes/Dataset/verification/method3_pnetlab/reviewed_checklist.csv
```

성공 시:

- `method3_verification_summary.json`
- `verification_summary.json`

에 외부 검증 집계가 반영된다.

## Method 4 의미

Method 4는 `L4-L5` 정답을 다시 Batfish로 재실행하는 단계다.

즉 다음을 검증한다.

- dataset row에 저장된 `metric`, `scope`, `scenario`, `query_contract`만으로
- 정답이 다시 재현되는가

이건 `정답 생성 코드의 hidden state`나 일회성 버그를 잡기 위한 검증이다.

## 논문용 retained set

Method 4가 끝나면 다음 파일이 생성된다.

- `method4_l45_replay/paper_ready_dataset.json`

이 파일은 `L4-L5 replay 검증` 결과를 반영한 retained row 집합이다.

## 재채점 주의사항

이번 ground truth 정비 이후에는 **기존 평가 결과를 그대로 재사용하면 안 된다**.

이유:

- 일부 dataset answer가 실제로 수정되었다.
- 특히 `LabB/C/D`에서 기존 stale answer가 교체되었다.
- 따라서 모델 점수를 다시 계산하려면 **최신 dataset JSON/CSV 기준으로 평가 입력을 맞춰야 한다**.

즉 다음 둘 중 하나를 기준으로 평가해야 한다.

- 최신 `Dataset/<timestamp>/*_dataset_batfish_*.json`
- 또는 검증 이후의 `paper_ready_dataset.json`

## 현재 권장 해석

- Method 1/4: 전수 자동 검증
- Method 2/3: 표본 수동/외부 검증

따라서 논문에서는 다음처럼 설명하는 것이 적절하다.

- `L1-L3 were exhaustively verified by an independent parser.`
- `L4-L5 were exhaustively replay-verified using Batfish row contracts.`
- `A stratified subset of L4-L5 was externally validated in PNETLab.`

## 현재 남은 필수 작업

코드와 자동 검증 기준으로는 현재 known blocking issue가 없다.

즉 실제로 남은 필수 작업은 다음 하나다.

- `Method 3 reviewed_checklist.csv`를 사람이 채워 외부 검증을 완료하는 것

다만 이것은 `버그가 절대 0개`라는 뜻이 아니다.
현재 상태는 다음처럼 이해해야 한다.

- 내부 정합성: 확보됨
- replay 가능성: 확보됨
- 외부 현실 검증: 아직 사람이 수행해야 함
