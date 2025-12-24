# NetConfigQA Type-Aware Scoring 가이드

> 왜 일반적인 NLP 메트릭(EM, F1, BERTScore, ROUGE)을 사용하지 않고 Type-Aware Scoring을 사용하는지 설명합니다.

## 1. 문제 정의

네트워크 설정 데이터는 **구조화된 데이터**입니다. 일반적인 텍스트와 다르게:

- 값의 **정확성**이 중요 (IP 주소 한 자리 차이 = 완전히 다른 장비)
- **순서가 무관한** 데이터 존재 (집합, JSON)
- **형식 차이**가 있지만 **의미는 동일**한 경우 많음

---

## 2. 일반 메트릭의 한계

### 2.1 Exact Match (EM)

**정의**: 예측값과 정답이 완전히 일치하면 1, 아니면 0

**문제점**:

| Gold | Prediction | EM | 실제로는? |
|------|------------|:--:|----------|
| `"leaf1"` | `leaf1` | ❌ 0 | ✅ 같은 값 (따옴표 차이) |
| `15.7` | `"15.7"` | ❌ 0 | ✅ 같은 숫자 |
| `["a", "b"]` | `["b", "a"]` | ❌ 0 | ✅ 같은 집합 |
| `true` | `True` | ❌ 0 | ✅ 같은 불리언 |

→ **형식 차이에 너무 민감**

---

### 2.2 Token-level F1

**정의**: 예측과 정답의 토큰 겹침으로 Precision, Recall, F1 계산

**문제점**:

```
질문: "PE1 장비의 Loopback0 IP 주소는?"

Gold: 10.255.0.1
Pred: 10.255.0.2

토큰 분리: 
  Gold = ["10", ".", "255", ".", "0", ".", "1"]
  Pred = ["10", ".", "255", ".", "0", ".", "2"]

겹치는 토큰: 6개 / 전체: 7개
F1 = 85.7%  ← 완전히 다른 IP인데 높은 점수!
```

→ **네트워크에서 IP 한 자리 차이는 치명적인 오류**

---

### 2.3 BERTScore

**정의**: BERT 임베딩으로 의미적 유사도 측정

**문제점**:

```
질문: "PE1의 관리 IP는?"

Gold: 10.0.0.1
Pred: 192.168.1.1

BERTScore ≈ 0.85+
```

둘 다 "IP 주소"라는 의미적 유사성 때문에 높은 점수!

→ **의미적 유사성 ≠ 정확한 값 일치**

---

### 2.4 ROUGE-1, ROUGE-L

**정의**: n-gram 오버랩 기반 (텍스트 요약용)

**문제점**:

```
질문: "Leaf1의 인터페이스 상태는?"

Gold: {"Gi0/0": "up", "Gi0/1": "down"}
Pred: {"Gi0/1": "down", "Gi0/0": "up"}

ROUGE-L ≈ 0.6  ← 순서가 달라서 낮은 점수
실제로는 완전히 동일한 JSON!
```

→ **순서 무관한 구조화 데이터에 부적합**

---

## 3. Type-Aware Scoring 설명

### 핵심 아이디어

> **Answer Type에 따라 적절한 비교 방식을 적용한다**

| Answer Type | 비교 방식 | 이유 |
|-------------|-----------|------|
| `boolean` | 정규화 후 Exact Match | true/yes/enabled = 동일 의미 |
| `numeric` | 숫자 추출 후 비교 | "15.7" = 15.7 = 15.70 |
| `number` | 정수 추출 후 비교 | "5개" → 5 |
| `set` | 집합 F1 Score | 순서 무관, 부분 정답 인정 |
| `map` | Key-Value 매칭 | JSON 키 순서 무관 |
| `text` | 대소문자 무시 Exact Match | "Leaf1" = "leaf1" |

---

## 4. 실제 예시로 이해하기

### 4.1 Boolean Type

```
질문: "P3 장비의 SSH 서비스가 활성화되어 있습니까?"
정답: true
```

| LLM 예측 | 일반 EM | Type-Aware | 설명 |
|----------|:-------:|:----------:|------|
| `true` | ✅ 1.0 | ✅ 1.0 | 완전 일치 |
| `True` | ❌ 0.0 | ✅ 1.0 | 대소문자 정규화 |
| `yes` | ❌ 0.0 | ✅ 1.0 | 동의어 인식 |
| `enabled` | ❌ 0.0 | ✅ 1.0 | 동의어 인식 |
| `1` | ❌ 0.0 | ✅ 1.0 | 불리언 변환 |
| `false` | ❌ 0.0 | ❌ 0.0 | 오답 |

**정규화 규칙**:
- `true`, `yes`, `on`, `enabled`, `1` → **True**
- `false`, `no`, `off`, `disabled`, `0` → **False**

---

### 4.2 Numeric Type

```
질문: "P4에 등록된 로컬 사용자는 몇 명입니까?"
정답: 1
```

| LLM 예측 | 일반 EM | Type-Aware | 설명 |
|----------|:-------:|:----------:|------|
| `1` | ✅ 1.0 | ✅ 1.0 | 완전 일치 |
| `"1"` | ❌ 0.0 | ✅ 1.0 | 따옴표 제거 |
| `1.0` | ❌ 0.0 | ✅ 1.0 | 동일 숫자 |
| `1명` | ❌ 0.0 | ✅ 1.0 | 숫자 추출 |
| `2` | ❌ 0.0 | ❌ 0.0 | 오답 |

**처리 방식**:
```python
def _extract_number(val: str) -> float:
    match = re.search(r'-?\d+(\.\d+)?', val)
    return float(match.group()) if match else None
```

---

### 4.3 Set Type

```
질문: "P3에 등록된 로컬 사용자 이름을 알려주세요. [답변 형식: 리스트]"
정답: ["admin"]
```

| LLM 예측 | 일반 EM | Type-Aware | 설명 |
|----------|:-------:|:----------:|------|
| `["admin"]` | ✅ 1.0 | ✅ 1.0 | 완전 일치 |
| `['admin']` | ❌ 0.0 | ✅ 1.0 | 따옴표 스타일 차이 |
| `["Admin"]` | ❌ 0.0 | ✅ 1.0 | 대소문자 정규화 |
| `admin` | ❌ 0.0 | ✅ 1.0 | 단일 값 → 집합 변환 |

**더 복잡한 예시**:

```
질문: "PE1 장비의 활성화된 인터페이스 목록은?"
정답: ["Gi0/0", "Gi0/1", "Gi0/2", "Loopback0"]
```

| LLM 예측 | F1 Score | 설명 |
|----------|:--------:|------|
| `["Gi0/0", "Gi0/1", "Gi0/2", "Loopback0"]` | 1.0 | 완전 일치 |
| `["Loopback0", "Gi0/2", "Gi0/1", "Gi0/0"]` | 1.0 | **순서 무관!** |
| `["Gi0/0", "Gi0/1"]` | 0.57 | 부분 정답 (2/4) |
| `["Gi0/0", "Gi0/1", "Gi0/2", "Loopback0", "Gi0/3"]` | 0.89 | 오답 포함 |
| `["Gi0/3"]` | 0.0 | 완전 오답 |

**F1 Score 계산**:
```python
def _score_set(pred: str, gold: str) -> float:
    p_set = parse_set(pred)  # {"gi0/0", "gi0/1"}
    g_set = parse_set(gold)  # {"gi0/0", "gi0/1", "gi0/2", "loopback0"}
    
    intersection = len(p_set & g_set)  # 겹치는 요소 수
    precision = intersection / len(p_set)  # 2/2 = 1.0
    recall = intersection / len(g_set)     # 2/4 = 0.5
    f1 = 2 * precision * recall / (precision + recall)  # 0.67
    
    return f1
```

---

### 4.4 Map Type (JSON)

```
질문: "Leaf4 장비의 각 인터페이스 상태를 알려주세요."
정답: {"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "down", 
       "GigabitEthernet0/2": "up", "GigabitEthernet0/3": "down"}
```

| LLM 예측 | 일반 EM | Type-Aware | 설명 |
|----------|:-------:|:----------:|------|
| 정답과 동일 | ✅ 1.0 | ✅ 1.0 | 완전 일치 |
| 키 순서만 다름 | ❌ 0.0 | ✅ 1.0 | **JSON 순서 무관!** |
| 3개 키 일치, 1개 누락 | ❌ 0.0 | 0.75 | 부분 점수 |
| 값 1개 틀림 | ❌ 0.0 | 0.875 | 부분 점수 |

**점수 계산**:
```python
def _score_map(pred: dict, gold: dict) -> float:
    common_keys = set(pred.keys()) & set(gold.keys())
    all_keys = set(pred.keys()) | set(gold.keys())
    
    key_score = len(common_keys) / len(all_keys) * 0.5
    value_matches = sum(1 for k in common_keys if pred[k] == gold[k])
    value_score = value_matches / len(common_keys) * 0.5
    
    return key_score + value_score
```

---

### 4.5 Text Type

```
질문: "Leaf1 장비의 호스트네임은 무엇입니까?"
정답: "leaf1"
```

| LLM 예측 | 일반 EM | Type-Aware | 설명 |
|----------|:-------:|:----------:|------|
| `"leaf1"` | ✅ 1.0 | ✅ 1.0 | 완전 일치 |
| `leaf1` | ❌ 0.0 | ✅ 1.0 | 따옴표 제거 |
| `Leaf1` | ❌ 0.0 | ✅ 1.0 | 대소문자 무시 |
| `LEAF1` | ❌ 0.0 | ✅ 1.0 | 대소문자 무시 |
| `leaf2` | ❌ 0.0 | ❌ 0.0 | 오답 |

---

## 5. Negative Testing (NOT_CONFIGURED)

```
질문: "Leaf1 장비의 Timezone은 무엇입니까?"
정답: "" (빈 값 - 설정되지 않음)
상태: NOT_CONFIGURED
```

| LLM 예측 | Type-Aware | 설명 |
|----------|:----------:|------|
| `""` | ✅ 1.0 | 정확히 "없음" 표현 |
| `null` | ✅ 1.0 | null도 "없음" |
| `None` | ✅ 1.0 | None도 "없음" |
| `not configured` | ✅ 1.0 | 명시적 표현 |
| `n/a` | ✅ 1.0 | 약어도 인식 |
| `UTC` | ❌ 0.0 | **할루시네이션!** |

**Negative Testing의 의미**:
- 모델이 "정보가 없다"를 정확히 인식하는지 평가
- 없는 정보를 만들어내면 (할루시네이션) **False Positive**

---

## 6. 요약 비교표

| 상황 | Exact Match | Token F1 | BERTScore | Type-Aware |
|------|:-----------:|:--------:|:---------:|:----------:|
| `"leaf1"` vs `leaf1` | ❌ | ~0.7 | ~0.9 | ✅ |
| `true` vs `True` | ❌ | ❌ | ~0.95 | ✅ |
| `["a","b"]` vs `["b","a"]` | ❌ | 1.0 | ~0.95 | ✅ |
| `10.0.0.1` vs `10.0.0.2` | ❌ | 0.86 | ~0.9 | ❌ |
| `{}` (JSON 순서) | ❌ | ~0.8 | ~0.9 | ✅ |
| 부분 정답 (집합) | ❌ | 부분 | ~0.7 | F1 |
| 빈 값 vs `null` | ❌ | ❌ | ~0.5 | ✅ |

---

## 7. 결론

### Type-Aware Scoring의 장점

1. **도메인 특화**: 네트워크 설정 데이터의 특성 반영
2. **형식 불변성**: 따옴표, 대소문자, 순서 차이 처리
3. **의미적 동등성**: 표현이 달라도 의미가 같으면 정답
4. **부분 점수**: 집합/맵에서 완전 오답 vs 부분 정답 구분
5. **Negative Testing**: 할루시네이션 탐지 가능

### 언제 사용해야 하는가?

✅ **Type-Aware Scoring 권장**:
- 구조화된 데이터 (JSON, 리스트, 숫자)
- 정확한 값이 중요한 도메인 (네트워크, 설정, 데이터베이스)
- Negative Testing이 필요한 경우

❌ **일반 메트릭 권장**:
- 자유 형식 텍스트 생성 (요약, 번역, 대화)
- 의미적 유사성이 중요한 경우
- 창의적 답변이 허용되는 경우

