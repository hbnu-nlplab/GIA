# Getting Started

NetConfigQA 데이터셋 생성 파이프라인을 처음 실행하는 연구원용 빠른 안내입니다. 자세한 배경과 구조는 루트 README와 `Paper/HCLT` 폴더를 참고하세요.

## 1. 환경 준비
- Python 3.9 이상 (추가 라이브러리 필요 없음)
- XML 예제 데이터: `Data/Pnetlab/Net1`
- 정책 파일: `Make_Dataset/policies.json` (필요시 수정 가능)

프로젝트 루트 예시는 다음과 같습니다.
```
NetConfigQA/
├─ Make_Dataset/
│  ├─ src/
│  │  ├─ main.py
│  │  ├─ core/             # parser, rule-based generator, builder
│  │  └─ legacy/           # 과거 에이전트/LLM 모듈 보관
│  ├─ policies.json
│  └─ docs/
└─ Data/
   └─ Pnetlab/Net1/*.xml
```

## 2. 가장 간단한 실행
```bash
python Make_Dataset/src/main.py \
  --xml-dir Data/Pnetlab/Net1 \
  --output-dir output/net1_run \
  --verbose
```

실행이 끝나면 다음 파일이 생성됩니다.
- `facts_YYYYMMDD_HHMMSS.json`: 파싱된 장비 facts
- `dataset_logic_only_YYYYMMDD_HHMMSS.json`: train/validation/test 분할된 전체 질문
- `dataset_logic_only_YYYYMMDD_HHMMSS.csv`: 동일 내용을 CSV로 저장

## 3. 실행 옵션 요약
| 옵션 | 설명 |
| --- | --- |
| `--categories` | 특정 카테고리만 생성 (미지정 시 전체) |
| `--basic-per-category` | 카테고리별 생성 상한 설정 (0 = 제한 없음) |
| `--no-split` | train/val/test 분할 없이 단일 리스트로 저장 |
| `--shuffle` | train/val/test 분할 시 순서 랜덤화 |
| `--policies` | 다른 정책 파일 사용 |
| `--verbose` | DSL 항목 수, facts 저장 경로 등 추가 로그 |

## 4. 결과물 구조
### JSON (기본)
```json
{
  "train": [{...}],
  "validation": [{...}],
  "test": [{...}]
}
```
각 항목은 `id`, `question`, `ground_truth`, `ground_truth_raw`, `explanation`, `category`, `answer_type`, `evidence_hint`, `source_files` 등을 포함합니다. `ground_truth_raw`는 리스트/딕셔너리 등 원본 구조를 유지하므로, 평가 시 그대로 활용할 수 있습니다.

### CSV
CSV 파일은 `id, category, answer_type, level, question, ground_truth, explanation, source_files` 열을 포함합니다. `ground_truth_raw`가 필요하면 JSON을 참고하세요.

## 5. 다음 단계
- 정책 편집: [Policies](Policies.md)
- 항목 구조 상세: [Dataset Format](Dataset_Format.md)
- 연구 배경 및 아키텍처: 루트 `README.md`, `Paper/HCLT/*`

필요한 경우 `--shuffle` 옵션으로 분할을 무작위화하거나, `--basic-per-category`로 특정 카테고리 수를 조정하여 실험 목적에 맞게 데이터 분포를 맞출 수 있습니다.
