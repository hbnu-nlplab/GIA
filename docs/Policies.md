# Policies & Categories

`policies.json`은 생성할 질문의 카테고리와 목표(Goal), 타깃(Scope), 주요 메트릭 등을 선언적으로 정의하는 파일입니다. 메인 스크립트는 이 정책을 DSL로 컴파일한 뒤, 엔진이 정답을 계산하여 최종 질문을 만듭니다.

## 위치

- 기본 경로: `Make_Dataset/policies.json`
- 실행 시 `--policies` 옵션으로 다른 경로를 지정할 수 있습니다.

## 카테고리 자동 추출

- `--categories`를 지정하지 않으면 `policies.json`에서 정의된 모든 `category`가 자동 사용됩니다.

## 정책 구조(개요)

아래는 단순화된 구조 예시입니다.

```json
{
  "defaults": {
    "mix": {"boolean": 1, "set": 1, "numeric": 1, "map": 1}
  },
  "policies": [
    {
      "category": "BGP_Consistency",
      "levels": {
        "2": [
          {
            "goal": "completeness",
            "targets": ["AS"],
            "primary_metric": "ibgp_missing_pairs"
          }
        ]
      }
    }
  ]
}
```

- `category`: 질문 그룹(예: `BGP_Consistency`, `VRF_Consistency`, `Security_Policy` 등)
- `levels`: 난이도 등급별 항목 리스트(문자 키: "1"/"2"/"3" 등)
- 각 항목의 주요 키
  - `goal`: 생성 목표(가시성, 완전성, 일관성 등). 내부적으로 관련 메트릭 그룹과 매핑됩니다.
  - `targets`: 적용 범위(예: `GLOBAL`, `AS`, `DEVICE`, `VRF` 등)
  - `primary_metric`: 질문 생성의 중심이 되는 메트릭(선택)

정책에서 선언된 카테고리와 메트릭은 `generators/rule_based_generator.py`와 `utils/builder_core.py`의 지원 범위 내에서만 사용됩니다.

