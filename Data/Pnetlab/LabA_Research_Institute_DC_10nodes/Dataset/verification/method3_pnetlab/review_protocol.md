# Method 3 Review Protocol

## 목적
- PNETLab에서 실제 CLI 결과를 확인한 뒤 L4-L5 표본 QA의 외부 타당성을 기록한다.
- `blank_checklist.csv`를 복사해 `reviewed_checklist.csv`로 저장한 뒤 결과를 채운다.

## 파일 규칙
- 입력 템플릿: `blank_checklist.csv`
- 권장 결과 파일명: `reviewed_checklist.csv`
- 파이프라인 연동: `--method3-review <csv>` 또는 같은 디렉터리의 `reviewed_checklist.csv` 자동 감지

## verdict 허용값
- `AGREE`: dataset answer와 실환경 결과가 일치
- `DISAGREE`: dataset answer와 실환경 결과가 불일치
- `SKIP`: 장비 문제, 시간 부족, 조건 불충분 등으로 판정 보류

## my_result 작성 규칙
- 실제 CLI 결과를 간결하게 적는다.
- 경로형 답변은 hop 순서를 유지한다.
- 장애 주입이 필요한 경우 `memo`에 shutdown/no shutdown 여부를 기록한다.

## 권장 판정 기준
- 경로 질문: source와 destination이 같고 핵심 hop 순서가 같으면 `AGREE`
- reachability 질문: reachable/unreachable 판정이 같으면 `AGREE`
- root cause 질문: blocking point 또는 원인 장비가 같으면 `AGREE`
- what-if 질문: 장애 후 `NONE/REROUTED/DISCONNECTED` 판정이 같으면 `AGREE`

## 파이프라인 반영
```bash
python Make_Dataset/src/verification/run_verification_pipeline.py \
  --lab-path Data/Pnetlab/<LAB_NAME> \
  --skip-method1 --skip-method2 --skip-method4 \
  --method3-review Data/Pnetlab/<LAB_NAME>/Dataset/verification/method3_pnetlab/reviewed_checklist.csv
```

성공 시 `method3_verification_summary.json`과 `verification_summary.json`에 외부 검증 수치가 반영된다.
