# Policies & Categories Guide

`Make_Dataset/policies.json`은 어떤 카테고리의 질문을 얼마나, 어떤 메트릭으로 생성할지를 정의하는 핵심 설정 파일입니다. 이 문서는 정책 구조를 이해하고, 안전하게 수정하는 방법을 정리합니다.

## 1. 파일 구조
```json
{
  "defaults": {
    "scenarios": [...],
    "min_per_category": 15
  },
  "policies": [
    {
      "category": "BGP_Consistency",
      "levels": {
        "1": [
          {"goal": "visibility", "targets": ["DEVICE"], "primary_metric": "neighbor_list_ibgp"}
        ],
        "2": [...]
      }
    },
    ...
  ]
}
```
- `defaults.scenarios`: 질문 시나리오 레이블 (출력 데이터에는 크게 영향 없음)
- `defaults.min_per_category`: 참고용 기본값 (현재 파이프라인은 직접 사용하지 않음)
- `policies`: 카테고리별 정책 목록

## 2. 항목별 주요 키 설명
| 키 | 설명 |
| --- | --- |
| `category` | 질문 묶음 이름 (예: `BGP_Consistency`, `Command_Generation` 등)
| `levels` | 난이도별 항목 묶음. key는 문자열(“1”,”2”…), value는 정책 리스트 |
| `goal` | 생성 목적(가시성, 완전성, 일관성 등). 내부적으로 관련 메트릭 그룹을 가져올 때 사용 |
| `targets` | 질문이 적용될 스코프. `GLOBAL`, `AS`, `DEVICE`, `VRF`, `DEVICE_VRF`, `DEVICE_IF` 등 |
| `primary_metric` | 꼭 포함할 핵심 메트릭. 없으면 `goal`과 연계된 메트릭 목록만 사용 |
| `notes` | 추가 문서용 메모 (필수 아님) |

> 현재 파이프라인은 정책에 정의된 모든 메트릭을 `utils/builder_core.py`에서 계산할 수 있도록 구현되어 있습니다.

## 3. 정책 수정 시 팁
1. **메트릭 확인**: 새로운 메트릭을 추가하려면 `BuilderCore._answer_for_metric`에 계산 로직이 있는지 반드시 확인하세요.
2. **스코프 적절성**: 예를 들어 `DEVICE_IF`를 사용하면 모든 장비-인터페이스 조합으로 질문이 급증할 수 있으니 주의합니다.
3. **Command_Generation 주의**: 해당 카테고리는 DSL이 아닌 전용 로직(명령어 템플릿)으로 생성됩니다. 정책에서 수정할 필요는 거의 없습니다.
4. **카테고리 제한**: 실험 시 특정 카테고리만 필요하면 CLI의 `--categories` 또는 `--basic-per-category`로 제한하세요.
5. **시나리오 레이블**: 보고서나 발표자료에는 시나리오명을 활용하지만, 실제 생성 로직에는 영향이 없습니다.

## 4. 자주 묻는 질문
- **정책에만 있고 결과에 없는 메트릭이 있나요?** → 현재는 없습니다. 모든 메트릭이 질문으로 생성됩니다.
- **카테고리 하나만 테스트하고 싶어요.** → `--categories BGP_Consistency` 등으로 실행하세요.
- **메트릭 결과가 0/없음 등 빈 값일 때는?** → 파이프라인이 자동으로 `ground_truth_raw`와 문자열 `ground_truth`를 함께 저장합니다. 빈 목록은 “없음”으로, 텍스트는 “정보 없음”으로 표시됩니다.

## 5. 더 알아보기
- 데이터 생성 파이프라인 전체: `README.md`
- 실행 옵션: [Getting Started](Getting_Started.md)
- 메트릭 설명: [Metrics Reference](Metrics.md)
- 출력 데이터 구조: [Dataset Format](Dataset_Format.md)
