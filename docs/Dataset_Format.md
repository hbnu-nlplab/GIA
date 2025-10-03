# Dataset Format

생성된 데이터셋은 JSON으로 저장되며, 상위 키는 `train`, `validation`, `test`로 구성됩니다. 각 분할에는 동일한 항목 스키마의 리스트가 들어있습니다.

## 상위 구조

```json
{
  "train": [ { /* item */ }, ... ],
  "validation": [ { /* item */ }, ... ],
  "test": [ { /* item */ }, ... ]
}
```

## 항목 필드(대표)

- `id`/`test_id`: 항목 식별자(정책/메트릭/스코프 조합 기반)
- `question`: 자연어 질문
- `ground_truth`: 정답(사람이 읽기 쉬운 문자열로 평문화됨)
- `explanation`: 간단한 생성/계산 근거 설명
- `category`: 정책 카테고리
- `answer_type`: 정답 타입 힌트(예: `boolean`, `numeric`, `set`, `map`, `text`)
- `level`: 난이도 정보(정책에서 전파)
- `evidence_hint`: 정답 계산에 사용된 스코프/메트릭 힌트(디버깅/추적용)
- `source_files`: 관련 원본 XML 파일 목록
- `origin`: 생성 출처 표기(정책/도메인 식별용)

주의
- 본 파이프라인은 LLM을 사용하지 않으며, `ground_truth`는 엔진이 계산한 값을 간단 문자열로 변환한 결과입니다.
- 평가(Evaluation) 관련 스키마/지표는 본 문서에서 다루지 않습니다.

