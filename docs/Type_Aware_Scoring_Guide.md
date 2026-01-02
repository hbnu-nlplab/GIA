# NetConfigQA Type-Aware Scoring 완전 가이드

> **이 문서의 목적**: 왜 EM/F1/BERTScore/ROUGE 대신 Type-Aware Scoring을 사용하는지, 각 타입별 비교 로직이 어떻게 동작하는지 완벽히 이해하기

---

## 1. 핵심 개념: 왜 Type-Aware인가?

### 1.1 네트워크 설정 데이터의 특성

네트워크 설정 데이터는 **자유 형식 텍스트가 아니라 구조화된 정형 데이터**입니다:

| 특성   | 자연어 텍스트                          | 네트워크 설정 데이터                       |
| ------ | -------------------------------------- | ------------------------------------------ |
| 유연성 | "서울", "Seoul", "수도" → 다 정답 가능 | `10.0.0.1` ≠ `10.0.0.2` (완전히 다른 장비) |
| 순서   | 문장 순서 중요                         | JSON 키 순서 무관                          |
| 형식   | 동의어/표현 다양                       | `true` = `True` = `yes` (같은 의미)        |
| 정확성 | 의미만 맞으면 OK                       | **한 글자 차이가 치명적 오류**             |

### 1.2 기존 메트릭의 치명적 문제

```
질문: "PE1 장비의 관리 IP 주소는?"
정답: 10.0.0.1
예측: 10.0.0.2  ← 완전히 다른 장비를 가리킴!

각 메트릭의 점수:
┌─────────────┬────────┬─────────────────────────────────┐
│ 메트릭       │ 점수    │ 문제점                          │
├─────────────┼────────┼─────────────────────────────────┤
│ Exact Match │ 0%     │ ✓ 정확히 0점 (올바름)             │
│ Token F1    │ 85.7%  │ ✗ 6/7 토큰 일치 → 높은 점수!      │
│ BERTScore   │ ~90%   │ ✗ 둘 다 "IP 주소"라서 유사하다고 판단 │
│ ROUGE-L     │ ~86%   │ ✗ 문자열 유사도 높음             │
│ Type-Aware  │ 0%     │ ✓ 숫자가 다르면 0점 (올바름)     │
└─────────────┴────────┴─────────────────────────────────┘
```

**결론**: Token F1, BERTScore, ROUGE는 **네트워크에서 치명적인 오류를 정답으로 처리**합니다.

---

## 2. Type-Aware Scoring 상세 설명

### 2.1 핵심 원리

> **"Answer Type에 따라 적절한 비교 방식을 선택한다"**

```
데이터셋 구조:
┌──────────────────────────────────────────────────────────────┐
│ question: "P3 장비의 SSH 서비스가 활성화되어 있습니까?"        │
│ answer: "true"                                               │
│ answer_type: "boolean"  ← 이 타입을 보고 비교 방식 결정!      │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 지원하는 5가지 Answer Type

| Answer Type | 의미            | 예시 정답 (실제 데이터셋)          |
| ----------- | --------------- | ---------------------------------- |
| `boolean`   | 참/거짓         | `true`, `false`                    |
| `numeric`   | 숫자            | `1`, `15.7`, `5`                   |
| `set`       | 순서 없는 집합  | `["admin"]`, `["Loopback0"]`       |
| `map`       | 키-값 쌍 (JSON) | `{"Gi0/0": "up", "Gi0/1": "down"}` |
| `text`      | 일반 텍스트     | `"leaf1"`, `"Cisco IOS"`           |

---

## 3. 각 타입별 비교 로직 상세

### 3.1 Boolean Type (참/거짓)

#### 왜 특별한 처리가 필요한가?

LLM은 불리언 값을 다양한 형태로 출력합니다:

- `true`, `True`, `TRUE`
- `yes`, `Yes`, `YES`
- `enabled`, `on`, `1`

모두 **같은 의미**이므로 정답으로 처리해야 합니다.

#### 비교 알고리즘

```python
def score_boolean(pred: str, gold: str) -> float:
    # Step 1: 정규화 (대소문자 무시, 동의어 통일)
    TRUE_VALUES = {'true', 'yes', 'on', 'enabled', '1'}
    FALSE_VALUES = {'false', 'no', 'off', 'disabled', '0'}

    pred_lower = pred.strip().lower()
    gold_lower = gold.strip().lower()

    # Step 2: True/False로 변환
    pred_bool = pred_lower in TRUE_VALUES
    gold_bool = gold_lower in TRUE_VALUES

    # Step 3: 비교
    return 1.0 if pred_bool == gold_bool else 0.0
```

#### 예시

```
질문: "p3 장비의 SSH 서비스가 활성화되어 있습니까?" (ID: 112)
정답(Gold): true

┌────────────┬─────────────┬───────────────┬───────────┐
│ LLM 예측    │ Exact Match │ Type-Aware   │ 이유       │
├────────────┼─────────────┼───────────────┼───────────┤
│ true       │ ✓ 1.0       │ ✓ 1.0         │ 완전 일치  │
│ True       │ ✗ 0.0       │ ✓ 1.0         │ 대소문자   │
│ yes        │ ✗ 0.0       │ ✓ 1.0         │ 동의어    │
│ enabled    │ ✗ 0.0       │ ✓ 1.0         │ 동의어    │
│ 1          │ ✗ 0.0       │ ✓ 1.0         │ 숫자형    │
│ false      │ ✗ 0.0       │ ✗ 0.0         │ 실제 오답 │
└────────────┴─────────────┴───────────────┴───────────┘
```

---

### 3.2 Numeric Type (숫자)

#### 왜 특별한 처리가 필요한가?

LLM은 숫자를 다양한 형식으로 출력합니다:

- `5` vs `"5"` vs `5.0` → 같은 숫자
- `15.7` vs `15.70` → 같은 숫자
- `3명` vs `3` → 숫자 추출 필요

#### 비교 알고리즘

```python
import re

def extract_number(val: str) -> float:
    """문자열에서 숫자만 추출"""
    # 정규식: 음수, 정수, 소수 모두 매칭
    match = re.search(r'-?\d+(\.\d+)?', val)
    if match:
        return float(match.group())
    return None  # 숫자가 없으면 None

def score_numeric(pred: str, gold: str) -> float:
    # Step 1: 숫자 추출
    pred_num = extract_number(pred)  # "5명" → 5.0
    gold_num = extract_number(gold)  # "5" → 5.0

    # Step 2: 둘 다 숫자면 비교
    if pred_num is not None and gold_num is not None:
        return 1.0 if pred_num == gold_num else 0.0

    # Step 3: 숫자 추출 실패시 문자열 비교
    return 1.0 if pred.lower() == gold.lower() else 0.0
```

#### 예시

```
질문: "p4 장비에 등록된 로컬 사용자는 총 몇 명입니까?" (ID: 42)
정답(Gold): 1

┌────────────┬─────────────┬───────────────┬─────────────────┐
│ LLM 예측    │ Exact Match │ Type-Aware   │ 이유            │
├────────────┼─────────────┼───────────────┼─────────────────┤
│ 1          │ ✓ 1.0       │ ✓ 1.0         │ 완전 일치       │
│ "1"        │ ✗ 0.0       │ ✓ 1.0         │ 따옴표 제거 후 1 │
│ 1.0        │ ✗ 0.0       │ ✓ 1.0         │ 1.0 == 1       │
│ 1명        │ ✗ 0.0       │ ✓ 1.0         │ 숫자 추출 → 1   │
│ one        │ ✗ 0.0       │ ✗ 0.0         │ 숫자 없음      │
│ 2          │ ✗ 0.0       │ ✗ 0.0         │ 실제 오답      │
└────────────┴─────────────┴───────────────┴─────────────────┘
```

---

### 3.3 Set Type (집합) - F1 Score 사용

#### 왜 특별한 처리가 필요한가?

집합의 핵심 특성:

1. **순서가 없음**: `["a", "b"]` = `["b", "a"]`
2. **부분 정답 가능**: 4개 중 2개 맞추면 0점이 아님
3. **다양한 형식**: `["a"]`, `['a']`, `a` 모두 같은 의미

#### 비교 알고리즘: F1 Score

```
F1 Score = 2 × (Precision × Recall) / (Precision + Recall)

Precision = (맞춘 요소 수) / (예측한 요소 수)  → "예측 중 얼마나 맞았나?"
Recall    = (맞춘 요소 수) / (정답 요소 수)    → "정답 중 얼마나 맞췄나?"
```

```python
import json

def parse_set(val: str) -> set:
    """문자열을 집합으로 변환"""
    val = val.strip()

    # JSON 배열 형식 시도
    try:
        val = val.replace("'", '"')  # 작은따옴표 → 큰따옴표
        if val.startswith('[') and val.endswith(']'):
            items = json.loads(val)
            return set(str(i).strip().lower() for i in items)
    except:
        pass

    # 쉼표로 분리
    if val:
        return set(i.strip().lower() for i in val.split(','))

    return set()

def score_set(pred: str, gold: str) -> float:
    # Step 1: 집합으로 변환
    pred_set = parse_set(pred)  # {"gi0/0", "gi0/1"}
    gold_set = parse_set(gold)  # {"gi0/0", "gi0/1", "gi0/2", "loopback0"}

    # Step 2: 빈 집합 처리
    if not gold_set and not pred_set:
        return 1.0  # 둘 다 비었으면 정답

    # Step 3: F1 계산
    intersection = len(pred_set & gold_set)  # 교집합 크기

    precision = intersection / len(pred_set) if pred_set else 0.0
    recall = intersection / len(gold_set) if gold_set else 0.0

    if precision + recall == 0:
        return 0.0

    f1 = 2 * precision * recall / (precision + recall)
    return f1
```

#### 예시 1: 순서 무관

```
질문: "p1 장비의 OSPF Area 0에 연결된 인터페이스 목록을 알려주세요." (ID: 271)
정답(Gold): ["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"]

┌───────────────────────────────────────────────┬───────────────┬─────────────────────┐
│ LLM 예측                                       │ Exact Match  │ Type-Aware (F1)     │
├───────────────────────────────────────────────┼───────────────┼─────────────────────┤
│ ["GigabitEthernet0/0", "GigabitEthernet0/1",   │ ✓ 1.0         │ ✓ 1.0               │
│  "Loopback0"]                                 │               │                     │
├───────────────────────────────────────────────┼───────────────┼─────────────────────┤
│ ["Loopback0", "GigabitEthernet0/1",           │ ✗ 0.0         │ ✓ 1.0 (순서 무관!)   │
│  "GigabitEthernet0/0"]                        │               │                     │
├───────────────────────────────────────────────┼───────────────┼─────────────────────┤
│ ['gigabitethernet0/0', 'gigabitethernet0/1',  │ ✗ 0.0         │ ✓ 1.0 (대소문자 무시) │
│  'loopback0']                                 │               │                     │
└───────────────────────────────────────────────┴───────────────┴─────────────────────┘
```

#### 예시 2: 부분 점수

```
질문: "p1 장비의 OSPF Area 0에 연결된 인터페이스 목록을 알려주세요." (ID: 271)
정답(Gold): ["GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"] (3개)

┌─────────────────────────────────┬────────────────────────────────────────┐
│ LLM 예측                         │ F1 Score 계산                          │
├─────────────────────────────────┼────────────────────────────────────────┤
│ ["GigabitEthernet0/0",          │ 교집합: 2                              │
│  "GigabitEthernet0/1"]          │ Precision: 2/2 = 1.0                   │
│ (2개 예측)                       │ Recall: 2/3 = 0.67                     │
│                                 │ F1 = 2×1.0×0.67/(1.0+0.67) = 0.8 (80%) │
├─────────────────────────────────┼────────────────────────────────────────┤
│ ["GigabitEthernet0/0", ...,     │ 교집합: 3                              │
│  "Loopback0", "Gi0/3"]          │ Precision: 3/4 = 0.75 (1개 오답 포함)  │
│ (4개 예측, 1개 틀림)              │ Recall: 3/3 = 1.0                      │
│                                 │ F1 = 2×0.75×1.0/(0.75+1.0) = 0.86 (86%)│
├─────────────────────────────────┼────────────────────────────────────────┤
│ ["GigabitEthernet0/3"]          │ 교집합: 0                              │
│ (완전히 틀린 답)                  │ F1 = 0.0 (0%)                          │
└─────────────────────────────────┴────────────────────────────────────────┘
```

---

### 3.4 Map Type (JSON/Dictionary)

#### 왜 특별한 처리가 필요한가?

JSON의 핵심 특성:

1. **키 순서 무관**: `{"a":1, "b":2}` = `{"b":2, "a":1}`
2. **키와 값 모두 중요**: 키만 맞고 값이 틀리면 부분 점수
3. **따옴표 스타일**: `{"a": "1"}` = `{'a': '1'}`

#### 비교 알고리즘

```
점수 = (키 일치 점수 × 0.5) + (값 일치 점수 × 0.5)

키 일치 점수 = (공통 키 수) / (전체 키 수)
값 일치 점수 = (값도 일치하는 키 수) / (공통 키 수)
```

```python
import json

def score_map(pred: str, gold: str) -> float:
    # Step 1: JSON 파싱
    try:
        pred_obj = json.loads(pred.replace("'", '"'))
        gold_obj = json.loads(gold.replace("'", '"'))
    except:
        # 파싱 실패시 문자열 비교
        return 1.0 if pred.lower() == gold.lower() else 0.0

    # Step 2: 딕셔너리 확인
    if not isinstance(pred_obj, dict) or not isinstance(gold_obj, dict):
        return 1.0 if str(pred_obj) == str(gold_obj) else 0.0

    # Step 3: 키 분석
    pred_keys = set(pred_obj.keys())
    gold_keys = set(gold_obj.keys())
    common_keys = pred_keys & gold_keys  # 교집합
    all_keys = pred_keys | gold_keys     # 합집합

    if not all_keys:
        return 1.0  # 둘 다 빈 딕셔너리

    # Step 4: 점수 계산
    # 키 일치 점수 (50%)
    key_score = len(common_keys) / len(all_keys) * 0.5

    # 값 일치 점수 (50%)
    if common_keys:
        value_matches = sum(
            1 for k in common_keys
            if str(pred_obj[k]).lower() == str(gold_obj[k]).lower()
        )
        value_score = value_matches / len(common_keys) * 0.5
    else:
        value_score = 0

    return key_score + value_score
```

#### 예시

```
질문: "leaf4 장비의 각 인터페이스 상태를 알려주세요." (ID: 92)
정답(Gold): {"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "down", "GigabitEthernet0/2": "up", "GigabitEthernet0/3": "down"}

┌─────────────────────────────────────────────┬───────────────┬─────────────┐
│ LLM 예측                                     │ Exact Match  │ Type-Aware  │
├─────────────────────────────────────────────┼───────────────┼─────────────┤
│ {"GigabitEthernet0/0":"up",                 │ ✓ 1.0         │ ✓ 1.0       │
│  "GigabitEthernet0/1":"down",               │               │             │
│  "GigabitEthernet0/2":"up",                 │               │             │
│  "GigabitEthernet0/3":"down"}               │               │             │
├─────────────────────────────────────────────┼───────────────┼─────────────┤
│ {"GigabitEthernet0/3":"down",               │ ✗ 0.0         │ ✓ 1.0       │
│  "GigabitEthernet0/2":"up",                 │ (키 순서 다름) │ (순서 무관!) │
│  "GigabitEthernet0/1":"down",               │               │             │
│  "GigabitEthernet0/0":"up"}                 │               │             │
├─────────────────────────────────────────────┼───────────────┼─────────────┤
│ {"GigabitEthernet0/0":"up",                 │ ✗ 0.0         │ 0.875       │
│  "GigabitEthernet0/1":"down",               │               │ 공통키 3/4  │
│  "GigabitEthernet0/2":"up"}                 │               │ = 37.5%     │
│ (키 1개 누락)                                │               │ 값일치 3/3  │
│                                             │               │ = 50%       │
├─────────────────────────────────────────────┼───────────────┼─────────────┤
│ {"GigabitEthernet0/0":"down",               │ ✗ 0.0         │ 0.625       │
│  "GigabitEthernet0/1":"down",               │               │ 키 4/4=50%  │
│  "GigabitEthernet0/2":"up",                 │               │ 값 3/4=37.5%│
│  "GigabitEthernet0/3":"down"}               │               │             │
│ (값 1개 틀림: GigabitEthernet0/0)            │               │             │
└─────────────────────────────────────────────┴───────────────┴─────────────┘
```

---

### 3.5 Text Type (일반 텍스트)

#### 왜 특별한 처리가 필요한가?

단순하지만 중요한 처리:

1. **대소문자 무시**: `"Leaf1"` = `"leaf1"` = `"LEAF1"`
2. **따옴표 제거**: `"leaf1"` → `leaf1`
3. **공백 정리**: `" leaf1 "` → `leaf1`

#### 비교 알고리즘

```python
def score_text(pred: str, gold: str) -> float:
    # Step 1: 정규화
    pred_clean = pred.strip().lower()
    gold_clean = gold.strip().lower()

    # Step 2: 따옴표 제거
    for quote in ['"', "'"]:
        if pred_clean.startswith(quote) and pred_clean.endswith(quote):
            pred_clean = pred_clean[1:-1]
        if gold_clean.startswith(quote) and gold_clean.endswith(quote):
            gold_clean = gold_clean[1:-1]

    # Step 3: 비교
    return 1.0 if pred_clean == gold_clean else 0.0
```

#### 예시

```
질문: "leaf1 장비의 호스트네임은 무엇입니까?" (ID: 2)
정답(Gold): "leaf1"

┌────────────┬─────────────┬───────────────┬─────────────────┐
│ LLM 예측    │ Exact Match │ Type-Aware   │ 이유            │
├────────────┼─────────────┼───────────────┼─────────────────┤
│ "leaf1"    │ ✓ 1.0       │ ✓ 1.0         │ 완전 일치       │
│ leaf1      │ ✗ 0.0       │ ✓ 1.0         │ 따옴표 없어도 OK │
│ Leaf1      │ ✗ 0.0       │ ✓ 1.0         │ 대소문자 무시   │
│ LEAF1      │ ✗ 0.0       │ ✓ 1.0         │ 대소문자 무시   │
│ " leaf1 "  │ ✗ 0.0       │ ✓ 1.0         │ 공백 제거       │
│ leaf2      │ ✗ 0.0       │ ✗ 0.0         │ 실제 오답       │
└────────────┴─────────────┴───────────────┴─────────────────┘
```

---

## 4. Negative Testing (할루시네이션 탐지)

### 4.1 개념

**Negative Testing**은 **설정되지 않은 값**에 대한 질문입니다:

```
질문: "Leaf1 장비의 Timezone은 무엇입니까?"
정답: ""  (빈 값)
상태: NOT_CONFIGURED
```

목적: **LLM이 없는 정보를 만들어내는지(할루시네이션) 테스트**

### 4.2 비교 로직

"없음"을 나타내는 다양한 표현을 정답으로 인정:

```python
EMPTY_VALUES = {'', 'null', 'none', 'n/a', 'not configured', 'not found'}

def is_empty(val: str) -> bool:
    return val.strip().lower() in EMPTY_VALUES
```

### 4.3 예시

```
질문: "p4 장비의 시간대(Timezone)는 무엇입니까?" (ID: 22)
정답(Gold): null (설정 안 됨)

┌──────────────────┬───────────────┬─────────────────────────────┐
│ LLM 예측          │ Type-Aware   │ 해석                        │
├──────────────────┼───────────────┼─────────────────────────────┤
│ null             │ ✓ 1.0         │ 정확히 "없음" 표현           │
│ None             │ ✓ 1.0         │ "없음" 인식                  │
│ not configured   │ ✓ 1.0         │ 명시적 "없음" 표현           │
│ n/a              │ ✓ 1.0         │ 약어도 인식                  │
│ ""               │ ✓ 1.0         │ 빈 문자열도 인식              │
│ UTC              │ ✗ 0.0         │ 🚨 할루시네이션! (없는 정보 생성) │
│ Asia/Seoul       │ ✗ 0.0         │ 🚨 할루시네이션!               │
└──────────────────┴───────────────┴─────────────────────────────┘
```

---

## 5. 전체 흐름 정리

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Scoring Pipeline                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 입력 정리 (공통)                                                │
│     ├─ <think>...</think> 태그 제거                                 │
│     ├─ 따옴표 정규화                                                │
│     └─ 공백/개행 정리                                               │
│                                                                     │
│  2. Answer Type 확인                                                │
│     │                                                               │
│     ├─ boolean  → 동의어 정규화 후 True/False 비교                  │
│     ├─ numeric  → 숫자 추출 후 수치 비교                            │
│     ├─ set      → 집합 변환 후 F1 Score 계산                        │
│     ├─ map      → JSON 파싱 후 Key-Value 매칭                       │
│     └─ text     → 대소문자 무시 Exact Match                         │
│                                                                     │
│  3. 점수 반환 (0.0 ~ 1.0)                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Type-Aware vs EM vs F1 비교 분석

Type-Aware Scoring은 단순히 하나의 메트릭이 아니라, 데이터의 구조를 이해하고 EM(Exact Match)과 F1의 장점을 결합한 방식입니다.

### 6.1 메트릭 간 상관관계 요약

| Answer Type | Type-Aware vs EM | Type-Aware vs Token F1 | 핵심 차이점 |
| :--- | :--- | :--- | :--- |
| **Boolean** | **높음 (Lenient)** | **높음** | "yes", "1", "true"를 모두 동일하게 처리 (Semantic EM) |
| **Numeric** | **높음 (Lenient)** | **비슷함** | "1명", "1.0", "1"에서 숫자 '1'만 추출하여 비교 |
| **Set** | **높음** | **높음** | 순서 무관 + **요소 단위** 비교 (Token 단위가 아님) |
| **Map** | **훨씬 높음** | **높음** | JSON 구조 이해, Key/Value 분리 채점, 순서 무관 |
| **Text** | **높음** | **비슷하거나 낮음** | 동의어 정규화 후 F1 계산. 단순 토큰 겹침보다 엄격할 수 있음 |

### 6.2 왜 점수 차이가 발생하는가?

#### 1) Set Type: Token F1 vs Element F1
- **Token F1**: `GigabitEthernet0/0`을 `Gigabit`, `Ethernet`, `0`, `/`, `0`으로 쪼개서 채점합니다.
- **Type-Aware (Set)**: `GigabitEthernet0/0` 전체를 하나의 **의미 있는 단위(Element)**로 봅니다.
- **결과**: 인터페이스 이름의 일부만 맞춘 경우 Token F1은 점수를 주지만, Type-Aware는 0점을 줍니다. 반면, 순서가 바뀌었을 때 EM은 0점이지만 Type-Aware는 만점을 줍니다.

#### 2) Map Type: Structural Credit
- **Exact Match**: JSON 문자열이 한 글자만 달라도(공백, 순서 등) 0점입니다.
- **Type-Aware (Map)**: 
    - **Key Score (50%)**: 정답의 키를 얼마나 포함했는가?
    - **Value Score (50%)**: 포함된 키의 값이 얼마나 정확한가?
- **결과**: 10개의 인터페이스 상태 중 9개만 맞춰도 EM은 0점이지만, Type-Aware는 약 0.9점을 부여하여 모델의 실제 능력을 정확히 반영합니다.

#### 3) Text Type: Semantic Normalization & Hybrid Scoring
- **로직**: 먼저 정규화된 EM을 시도하고, 실패하면 Token F1을 계산합니다.
- **결과**: 한국어 조사나 단위 표현("개", "대", "명") 때문에 발생하는 EM의 한계를 극복합니다. 다만, 단순 Token F1은 정규화 없이도 우연히 겹치는 토큰에 점수를 주므로, Type-Aware가 더 보수적(엄격)일 수 있습니다.

---

## 7. 관련 연구 / 인용 근거

교수님께 관련 연구로 언급할 수 있는 것들:

### 6.1 유사한 접근을 사용하는 벤치마크

| 벤치마크              | 도메인       | 평가 방식          | 이유                                   |
| --------------------- | ------------ | ------------------ | -------------------------------------- |
| **Spider**            | Text-to-SQL  | Execution Accuracy | SQL 결과가 같으면 정답 (문자열 비교 X) |
| **KILT**              | Knowledge QA | Normalized EM      | 정규화 후 Exact Match                  |
| **TriviaQA**          | QA           | Normalized EM      | 대소문자/공백 등 정규화                |
| **Natural Questions** | QA           | Token-level F1     | 하지만 구조화 데이터엔 부적합          |

### 6.2 핵심 인용 문구

> "For structured data extraction tasks, token-level metrics like F1 or ROUGE are insufficient because they fail to capture semantic equivalence of structured outputs."
> — 관련 연구들의 공통 주장

> "In network configuration domain, a single character difference in IP address represents a completely different device, making partial match metrics inappropriate."
> — NetConfigQA의 Type-Aware Scoring 정당화

---

## 8. 결론: 교수님께 설명할 때

### 한 문장 요약

> "EM/F1/BERT/ROUGE는 **자연어 텍스트용**이고, 저희 데이터는 **구조화된 정형 데이터**라서 **데이터 타입별 정확성 비교**를 사용했습니다."

### 3가지 핵심 근거

1. **Token F1의 한계**: IP 주소 `10.0.0.1` vs `10.0.0.2`가 85% 정답으로 처리됨 → 네트워크에서 치명적 오류
2. **순서 불변성 필요**: JSON `{"a":1, "b":2}` = `{"b":2, "a":1}`이지만 ROUGE는 다르게 처리
3. **형식 불변성 필요**: `true` = `True` = `yes`이지만 EM은 다 다르게 처리

### 관련 연구

- Spider (Text-to-SQL): **Execution Accuracy** 사용
- KILT: **Normalized Exact Match** 사용
- 둘 다 구조화된 답변에 단순 문자열 비교가 부적합하다는 문제의식에서 출발
