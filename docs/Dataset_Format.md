# Dataset Format Guide

NetConfigQA 파이프라인은 JSON/CSV 두 가지 형태로 결과물을 출력합니다. 이 문서는 각 필드의 의미와 활용 방법을 정리합니다.

## 1. 저장 파일
| 파일 | 설명 |
| --- | --- |
| `dataset_logic_only_YYYYMMDD_HHMMSS.json` | train/validation/test 리스트 구조 |
| `dataset_logic_only_YYYYMMDD_HHMMSS.csv` | 동일 데이터를 테이블 형태로 저장 |
| `facts_YYYYMMDD_HHMMSS.json` | (참고) XML 파싱 결과, 질문 생성 시 활용된 facts |

## 2. JSON 구조
```json
{
  "train": [{...}, ...],
  "validation": [{...}, ...],
  "test": [{...}, ...]
}
```
각 항목 객체는 다음 키를 포함합니다.

| 키 | 설명 |
| --- | --- |
| `id` | `{METRIC}_{번호}` 형태의 고유 ID |
| `category` | 정책 카테고리 (`BGP_Consistency`, `System_Inventory` 등) |
| `answer_type` | `boolean`, `numeric`, `set`, `list`, `map`, `text` |
| `level` | 정책에서 정의한 난이도 레벨 (문자열/정수) |
| `question` | 자연어 질문 + `[답변 형식: …]` 힌트 |
| `ground_truth` | 사람이 읽기 쉬운 문자열 (예: `host1, host2`, `key=value`, `정보 없음`) |
| `ground_truth_raw` | 원본 자료형 (리스트/딕셔너리/숫자 등). 자동 채점 시 이 값을 쓰면 편리 |
| `explanation` | `metric`과 `scope` 기반 계산 요약 (`metric xxx on host=CE1 → ...`) |
| `evidence_hint` | `{ "metric": str, "scope": dict }` 형태. 어떤 범위에 어떤 메트릭을 적용했는지 기록 |
| `source_files` | 해당 질문에 사용된 XML 파일 목록 |
| `evaluation_method` | 현재는 `exact_match` 고정 (향후 확장 대비) |

> `ground_truth`와 `ground_truth_raw`를 모두 보존하므로, LLM 평가나 자동 스코어링에서 원하는 형식을 자유롭게 사용할 수 있습니다.

## 3. CSV 구조
CSV는 질문과 문자열 `ground_truth`만을 사용하기 때문에 정밀 채점에는 JSON을 권장합니다. 컬럼은 다음과 같습니다.

```
id,category,answer_type,level,question,ground_truth,explanation,source_files
```

- `source_files`는 쉼표로 연결된 문자열입니다.
- `ground_truth`가 `없음`, `정보 없음`으로 표시되어 있으면 JSON의 `ground_truth_raw`를 참고하세요.

## 4. 답변 형식 힌트
질문 끝의 `[답변 형식: …]` 힌트는 평가 LLM이 정해진 형식으로 답변하도록 돕기 위한 장치입니다.
- `boolean` → `true/false (소문자)`
- `numeric` → 정수
- `set/list` → “쉼표로 구분된 항목 목록 (없으면 '없음')”
- `map` → “키=값 형식 목록 (없으면 '없음')”
- `text` → “단답 텍스트 (없으면 '정보 없음')”

## 5. 예시 항목
```json
{
  "id": "CMD_SSH_PROXY_JUMP_0001",
  "category": "Command_Generation",
  "answer_type": "text",
  "level": 2,
  "question": "admin 계정으로 CE1를 거쳐 CE2 장비에 SSH 접속하는 명령어는 무엇입니까?\n[답변 형식: 단답 텍스트 (없으면 '정보 없음')]",
  "ground_truth": "ssh -J admin@172.16.1.40 admin@172.16.1.41",
  "ground_truth_raw": "ssh -J admin@172.16.1.40 admin@172.16.1.41",
  "explanation": "metric `cmd_ssh_proxy_jump` on destination_host=172.16.1.41, hosts=['CE1', 'CE2'], jump_host=172.16.1.40, type=DEVICE → ssh -J admin@172.16.1.40 admin@172.16.1.41",
  "evidence_hint": {"metric": "cmd_ssh_proxy_jump", "scope": {"type": "DEVICE", "host": "CE2", "destination_host": "172.16.1.41", "jump_host": "172.16.1.40", "hosts": ["CE1", "CE2"], "user": "admin"}},
  "source_files": ["ce1.xml", "ce2.xml"],
  "evaluation_method": "exact_match"
}
```

## 6. FAQ
- **왜 `ground_truth_raw`가 필요한가요?**
  - 문자열로 변환된 값만 사용하면, JSON을 다시 파싱하거나 LLM이 엉뚱한 형식으로 답할 때 처리하기 어렵습니다. `ground_truth_raw`는 평가 스크립트에서 그대로 비교하기 위한 안전장치입니다.
- **빈 결과는 어떻게 표시되나요?**
  - 집합/목록이 비어 있으면 `ground_truth`에 “없음”, 텍스트가 없으면 “정보 없음”으로 표시하고, `ground_truth_raw`에는 빈 리스트/None을 그대로 보관합니다.
- **다른 평가 지표는 없나요?**
  - 현재는 exact_match 전용입니다. 필요한 경우 `ground_truth_raw`를 사용해 F1, 부분 점수 등을 연구자가 직접 구현하면 됩니다.

## 7. 관련 문서
- 실행 방법: [Getting Started](Getting_Started.md)
- 정책 구조: [Policies](Policies.md)
- 상위 개요/배경: 프로젝트 루트 `README.md`, `Paper/HCLT/*`
