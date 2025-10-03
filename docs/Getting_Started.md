# Getting Started

이 문서는 NetConfigQA 데이터셋 생성 파이프라인(LLM 미사용, 규칙 기반)의 빠른 시작 가이드를 제공합니다.

## 요구 사항

- Python 3.9+
- 추가 패키지 없이 실행 가능(기본 경로는 표준 라이브러리만 사용)

## 디렉토리 구조(요약)

- `Make_Dataset/src/main.py` — 메인 실행 스크립트
- `Make_Dataset/policies.json` — 질문 생성을 위한 정책 정의
- `Data/Pnetlab/Net1` — 샘플 XML 데이터 (예시)

## 실행 예시

샘플 XML로 데이터셋 생성:

```
python Make_Dataset/src/main.py \
  --xml-dir Data/Pnetlab/Net1 \
  --output-dir output/logic_only \
  --verbose
```

성공 시 `output/logic_only/dataset_logic_only_YYYYMMDD_HHMMSS.json` 파일이 생성됩니다.

## 주요 옵션

- `--xml-dir` 입력 XML 디렉토리 경로
- `--output-dir` 생성된 데이터셋 저장 디렉토리
- `--categories` 생성 대상 카테고리(공백 구분으로 복수 지정 가능). 미지정 시 `policies.json`의 모든 카테고리 사용
- `--basic-per-category` 카테고리별 최대 항목 수 제한(0=무제한)
- `--policies` 정책 파일 경로(기본값: `Make_Dataset/policies.json`)
- `--verbose` 상세 로그 출력

## 결과물

- JSON 파일(예: `dataset_logic_only_20250101_120000.json`) 내에 `train`, `validation`, `test` 세 분할로 저장됩니다.
- 샘플 수 비율은 8:1:1 입니다.

자세한 항목 구조는 [Dataset Format](Dataset_Format.md) 문서를 참고하세요.

