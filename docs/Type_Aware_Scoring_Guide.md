# NetConfigQA Type-Aware Scoring 완전 가이드

> **이 문서의 목적**: 왜 EM/F1/BERTScore/ROUGE 대신 Type-Aware Scoring을 사용하는지, 각 타입별 비교 로직이 어떻게 동작하는지 완벽히 이해하기
>
> **코드 참조**: `Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py`

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
│ question: "PE1 장비에 설정된 VRF 목록을 알려주세요."           │
│ answer: "[\"VRF_AI\", \"VRF_BIO\", \"VRF_HPC\"]"              │
│ answer_type: "set"  ← 이 타입을 보고 비교 방식 결정!          │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 지원하는 4가지 Answer Type

| Answer Type | 의미            | 예시 정답 (실제 데이터셋)           | 별칭 (코드 호환) |
| ----------- | --------------- | ----------------------------------- | --------------- |
| `numeric`   | 숫자            | `1`, `15.7`, `5`                    | `number`, `scalar_int` |
| `set`       | 순서 없는 집합  | `["admin"]`, `["Loopback0"]`        | `set_str`, `list` |
| `map`       | 키-값 쌍 (JSON) | `{"Gi0/0": "up", "Gi0/1": "down"}`  | `map_str_str`, `dictionary`, `json` |
| `text`      | 일반 텍스트     | `"leaf1"`, `"Cisco IOS"`            | (기본값) |

> [!IMPORTANT]
> **Boolean 타입은 별도로 존재하지 않습니다.** `true`/`false` 답변은 `text` 타입으로 처리됩니다.

---

## 3. 각 타입별 비교 로직 상세

### 3.1 Numeric Type (숫자) - `number`, `numeric`, `scalar_int`

#### 왜 특별한 처리가 필요한가?

LLM은 숫자를 다양한 형식으로 출력합니다:

- `5` vs `"5"` vs `5.0` → 같은 숫자
- `15.7` vs `15.70` → 같은 숫자
- `3명` vs `3` → 숫자 추출 필요
- `five` → 영어 숫자 단어도 인식

#### 비교 알고리즘

```python
def _extract_number(self, val: str) -> float:
    """Extract number from string, including word-to-digit conversion."""
    # First try direct digit extraction
    match = re.search(r'-?\d+(\\.\\d+)?', val)
    if match:
        return float(match.group())
    
    # If no digit found, try to extract number words
    word_to_num = {
        'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4,
        'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9,
        'ten': 10, 'eleven': 11, 'twelve': 12, ...
    }
    
    # Look for patterns like "totaling five network interfaces"
    patterns = [
        r'totaling\\s+(\\w+)',
        r'has\\s+exactly\\s+(\\w+)',
        r'total\\s+of\\s+(\\w+)',
    ]
    # ... extract and convert
    
    return None

def _score_numeric(self, pred: str, gold: str) -> Dict[str, float]:
    p_num = self._extract_number(pred)
    g_num = self._extract_number(gold)
    if p_num is None or g_num is None:
        return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
    return {"score": 1.0 if p_num == g_num else 0.0}
```

#### 예시

```
질문: "p4 장비에 등록된 로컬 사용자는 총 몇 명입니까?"
정답(Gold): 1

┌────────────────────┬─────────────┬───────────────┬─────────────────┐
│ LLM 예측            │ Exact Match │ Type-Aware   │ 이유            │
├────────────────────┼─────────────┼───────────────┼─────────────────┤
│ 1                  │ ✓ 1.0       │ ✓ 1.0         │ 완전 일치       │
│ "1"                │ ✗ 0.0       │ ✓ 1.0         │ 따옴표 제거 후 1 │
│ 1.0                │ ✗ 0.0       │ ✓ 1.0         │ 1.0 == 1       │
│ 1명                │ ✗ 0.0       │ ✓ 1.0         │ 숫자 추출 → 1   │
│ one                │ ✗ 0.0       │ ✓ 1.0         │ 영어 단어 변환  │
│ 2                  │ ✗ 0.0       │ ✗ 0.0         │ 실제 오답      │
└────────────────────┴─────────────┴───────────────┴─────────────────┘
```

---

### 3.2 Set Type (집합) - F1 Score 사용

#### 왜 특별한 처리가 필요한가?

집합의 핵심 특성:

1. **순서가 없음**: `["a", "b"]` = `["b", "a"]`
2. **부분 정답 가능**: 4개 중 2개 맞추면 0점이 아님
3. **다양한 형식**: `["a"]`, `['a']`, `{"a"}`, `(a)` 모두 같은 의미

#### 비교 알고리즘: F1 Score

```
F1 Score = 2 × (Precision × Recall) / (Precision + Recall)

Precision = (맞춘 요소 수) / (예측한 요소 수)  → "예측 중 얼마나 맞았나?"
Recall    = (맞춘 요소 수) / (정답 요소 수)    → "정답 중 얼마나 맞췄나?"
```

```python
def _parse_set(self, val: str) -> Set[str]:
    """
    Parse set from various formats:
    - JSON array: ["item1", "item2"]
    - Set notation: {"item1", "item2"}
    - Tuple: ("item1", "item2")
    - Comma-separated: item1, item2
    """
    val = val.strip()
    
    try:
        # 1. JSON 형식 파싱 시도 (대괄호, 중괄호, 소괄호 모두 지원)
        val_normalized = val.replace("'", '"')
        if (val_normalized.startswith('[') and val_normalized.endswith(']')) or \
           (val_normalized.startswith('{') and val_normalized.endswith('}')) or \
           (val_normalized.startswith('(') and val_normalized.endswith(')')):
            # 중괄호/소괄호를 대괄호로 변환
            val_normalized = val_normalized.replace('{', '[').replace('}', ']')
            val_normalized = val_normalized.replace('(', '[').replace(')', ']')
            items = json.loads(val_normalized)
            return set(str(i).strip().lower() for i in items)
    except:
        pass
    
    # 2. Fallback: 쉼표 구분 파싱
    val_cleaned = val.strip('[]{}()"\\' ').strip()
    if ',' in val_cleaned:
        return set(i.strip().lower() for i in val_cleaned.split(',') if i.strip())
    elif val_cleaned:
        return {val_cleaned.lower()}
    
    return set()

def _score_set(self, pred: str, gold: str) -> Dict[str, float]:
    p_set = self._parse_set(pred)
    g_set = self._parse_set(gold)
    if not g_set and not p_set:
        return {"score": 1.0, "f1": 1.0}
    
    intersection = len(p_set & g_set)
    precision = intersection / len(p_set) if p_set else 0.0
    recall = intersection / len(g_set) if g_set else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"score": f1, "f1": f1, "precision": precision, "recall": recall}
```

#### 예시 1: 순서 무관

```
질문: "PE1 장비의 OSPF Area 0에 연결된 인터페이스 목록을 알려주세요."
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
│ {'gigabitethernet0/0', 'gigabitethernet0/1',  │ ✗ 0.0         │ ✓ 1.0 (대소문자 무시) │
│  'loopback0'}                                 │               │                     │
└───────────────────────────────────────────────┴───────────────┴─────────────────────┘
```

#### 예시 2: 부분 점수

```
질문: "PE1 장비의 OSPF Area 0에 연결된 인터페이스 목록을 알려주세요."
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

### 3.3 Map Type (JSON/Dictionary)

#### 왜 특별한 처리가 필요한가?

JSON의 핵심 특성:

1. **키 순서 무관**: `{"a":1, "b":2}` = `{"b":2, "a":1}`
2. **키와 값 모두 중요**: 키만 맞고 값이 틀리면 부분 점수
3. **따옴표 스타일**: `{"a": "1"}` = `{'a': '1'}`
4. **네트워크 특화**: IP 정규화, 상태 정규화 (shutdown → down)

#### 비교 알고리즘

```
점수 = (공통 키 수 / 전체 키 수) × 0.5 + (값 일치 수 / 공통 키 수) × 0.5
```

```python
def _normalize_ip_value(self, value: str) -> str:
    """
    Normalize IP address or status value for comparison.
    - "10.0.0.1/31" -> "10.0.0.1"  (CIDR 제거)
    - "shutdown" -> "down"        (상태 정규화)
    """
    value = str(value).strip().lower()
    if value == 'shutdown':
        return 'down'
    if '/' in value:
        value = value.split('/')[0].strip()
    return value

def _score_map(self, pred: str, gold: str) -> Dict[str, float]:
    try:
        p_obj = json.loads(pred.replace("'", '"'))
        g_obj = json.loads(gold.replace("'", '"'))
    except:
        return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
    
    if not isinstance(p_obj, dict) or not isinstance(g_obj, dict):
        return {"score": 1.0 if str(p_obj) == str(g_obj) else 0.0}
         
    common = set(p_obj.keys()) & set(g_obj.keys())
    all_k = set(p_obj.keys()) | set(g_obj.keys())
    if not all_k:
        return {"score": 1.0}
    
    # Compare values with IP normalization
    val_matches = 0
    for k in common:
        pred_val = self._normalize_ip_value(p_obj[k])
        gold_val = self._normalize_ip_value(g_obj[k])
        if pred_val == gold_val:
            val_matches += 1
    
    return {"score": (len(common)/len(all_k)*0.5) + (val_matches/len(common)*0.5 if common else 0)}
```

#### 예시

```
질문: "Leaf4 장비의 각 인터페이스 상태를 알려주세요."
정답(Gold): {"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "down", 
            "GigabitEthernet0/2": "up", "GigabitEthernet0/3": "down"}

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
│ {"GigabitEthernet0/1":"shutdown",           │ ✗ 0.0         │ ✓ 1.0       │
│ ...}                                        │               │ shutdown=down│
│ (shutdown → down 정규화)                     │               │  자동 변환!  │
└─────────────────────────────────────────────┴───────────────┴─────────────┘
```

---

### 3.4 Text Type (일반 텍스트) - **Hybrid Scoring**

#### 왜 특별한 처리가 필요한가?

Text 타입은 가장 일반적이면서 복잡합니다:

1. **대소문자 무시**: `"Leaf1"` = `"leaf1"` = `"LEAF1"`
2. **따옴표 제거**: `"leaf1"` → `leaf1`
3. **공백 정리**: `" leaf1 "` → `leaf1`
4. **한국어 카운터 제거**: `"3개"` → `"3"`
5. **동의어 매핑**: `shutdown` → `down`, `true` → `예`
6. **부분 점수 (Token F1)**: 완전 일치 실패 시 토큰 기반 F1 계산

#### 비교 알고리즘 (2단계 Hybrid)

```python
def _normalize_for_comparison(self, text: str) -> str:
    """
    Normalize text for comparison:
    1. Extract numbers (remove Korean counters like 개, 대, 명)
    2. Map synonyms (diff -> 차이, etc.)
    """
    synonyms = {
        'diff': '차이', 'difference': '차이',
        'count': '개수', 'total': '합계',
        'yes': '예', 'no': '아니오',
        'true': '예', 'false': '아니오',
        'shutdown': 'down',
    }
    
    text = text.lower().strip()
    
    # Apply synonym mapping
    for eng, kor in synonyms.items():
        text = text.replace(eng, kor)
    
    # Normalize numbers: "0개" -> "0", "1대" -> "1"
    text = re.sub(r'(\\d+)\\s*[개대명건번째]', r'\\1', text)
    
    return text

def _score_text(self, pred: str, gold: str) -> Dict[str, float]:
    """
    Score text answers using Type-Aware logic + Token F1 for robustness.
    Strategy:
    1. Exact Match (normalized): 1.0
    2. Token F1 with normalization: Partial match
    """
    # Handle 'false' or '0' which some models use for NOT_CONFIGURED text fields
    if pred.lower() in ['false', '0']:
        pred = ""
        
    # Apply normalization
    pred_norm = self._normalize_for_comparison(pred)
    gold_norm = self._normalize_for_comparison(gold)
    
    # 1. Exact Match (Primary)
    if pred_norm == gold_norm:
        return {"score": 1.0}
        
    # 2. Token F1 (Secondary - Robustness)
    pred_tokens = set(pred_norm.split())
    gold_tokens = set(gold_norm.split())
    
    if not gold_tokens:
        return {"score": 1.0 if not pred_tokens else 0.0}
        
    common = pred_tokens & gold_tokens
    if common:
        precision = len(common) / len(pred_tokens) if pred_tokens else 0
        recall = len(common) / len(gold_tokens)
        f1 = 2 * (precision * recall) / (precision + recall)
        return {"score": f1}
        
    return {"score": 0.0}
```

#### 예시

```
질문: "PE1 장비의 호스트네임은 무엇입니까?"
정답(Gold): "PE1"

┌────────────────────┬─────────────┬───────────────┬─────────────────┐
│ LLM 예측            │ Exact Match │ Type-Aware   │ 이유            │
├────────────────────┼─────────────┼───────────────┼─────────────────┤
│ "PE1"              │ ✓ 1.0       │ ✓ 1.0         │ 완전 일치       │
│ pe1                │ ✗ 0.0       │ ✓ 1.0         │ 대소문자 무시   │
│ PE1                │ ✗ 0.0       │ ✓ 1.0         │ 따옴표 없어도 OK │
│ " PE1 "            │ ✗ 0.0       │ ✓ 1.0         │ 공백 제거       │
│ 호스트네임은 PE1   │ ✗ 0.0       │ 0.5 (Token F1)│ 부분 일치       │
│ PE2                │ ✗ 0.0       │ ✗ 0.0         │ 실제 오답       │
└────────────────────┴─────────────┴───────────────┴─────────────────┘
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
# clean_gold 및 clean_prediction에서 처리
if gold.lower() in ['null', 'none', 'n/a', 'not configured', 'not found', '']:
    gold = ""
```

### 4.3 예시

```
질문: "p4 장비의 시간대(Timezone)는 무엇입니까?"
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
│     ├─ assistantfinal 구분자 처리                                   │
│     ├─ Markdown 코드 블록 제거                                      │
│     ├─ 따옴표 정규화                                                │
│     └─ 공백/개행 정리                                               │
│                                                                     │
│  2. Answer Type 확인 (canonical_answer_type으로 정규화)              │
│     │                                                               │
│     ├─ numeric/number/scalar_int → 숫자 추출 후 수치 비교           │
│     ├─ set/set_str/list         → 집합 변환 후 F1 Score 계산        │
│     ├─ map/map_str_str/json     → JSON 파싱 후 Key-Value 매칭       │
│     └─ text (기본값)            → 정규화 EM → Token F1 폴백         │
│                                                                     │
│  3. 점수 반환 (0.0 ~ 1.0)                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Type-Aware vs EM vs Token F1 비교 분석

### 6.1 메트릭 간 상관관계 요약

| Answer Type | Type-Aware vs EM | Type-Aware vs Token F1 | 핵심 차이점 |
| :--- | :--- | :--- | :--- |
| **Numeric** | **높음 (Lenient)** | **비슷함** | "1명", "1.0", "one"에서 숫자 추출 비교 |
| **Set** | **높음** | **높음** | 순서 무관 + **요소 단위** 비교 |
| **Map** | **훨씬 높음** | **높음** | JSON 구조 이해, Key/Value 분리 채점, IP 정규화 |
| **Text** | **높음** | **비슷하거나 낮음** | EM 우선 + Token F1 폴백 (Hybrid) |

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
    - **IP 정규화**: CIDR 제거, shutdown→down 매핑
- **결과**: 10개의 인터페이스 상태 중 9개만 맞춰도 EM은 0점이지만, Type-Aware는 약 0.9점을 부여합니다.

#### 3) Text Type: Hybrid Scoring
- **로직**: 먼저 정규화된 EM을 시도하고, 실패하면 Token F1을 계산합니다.
- **결과**: 한국어 조사나 단위 표현("개", "대", "명") 때문에 발생하는 EM의 한계를 극복합니다.

---

## 7. 관련 연구 / 인용 근거

### 7.1 유사한 접근을 사용하는 벤치마크

| 벤치마크              | 도메인       | 평가 방식          | 이유                                   |
| --------------------- | ------------ | ------------------ | -------------------------------------- |
| **Spider**            | Text-to-SQL  | Execution Accuracy | SQL 결과가 같으면 정답 (문자열 비교 X) |
| **KILT**              | Knowledge QA | Normalized EM      | 정규화 후 Exact Match                  |
| **TriviaQA**          | QA           | Normalized EM      | 대소문자/공백 등 정규화                |
| **Natural Questions** | QA           | Token-level F1     | 하지만 구조화 데이터엔 부적합          |

### 7.2 핵심 인용 문구

> "For structured data extraction tasks, token-level metrics like F1 or ROUGE are insufficient because they fail to capture semantic equivalence of structured outputs."
> — 관련 연구들의 공통 주장

> "In network configuration domain, a single character difference in IP address represents a completely different device, making partial match metrics inappropriate."
> — NetConfigQA의 Type-Aware Scoring 정당화

---

## 8. 결론: 교수님께 설명할 때

### 한 문장 요약

> "EM/F1/BERT/ROUGE는 **자연어 텍스트용**이고, 저희 데이터는 **구조화된 정형 데이터**라서 **데이터 타입별 정확성 비교**를 사용했습니다."

### 4가지 핵심 근거

1. **Token F1의 한계**: IP 주소 `10.0.0.1` vs `10.0.0.2`가 85% 정답으로 처리됨 → 네트워크에서 치명적 오류
2. **순서 불변성 필요**: JSON `{"a":1, "b":2}` = `{"b":2, "a":1}`이지만 ROUGE는 다르게 처리
3. **형식 불변성 필요**: `one` = `1` = `1.0`이지만 EM은 다 다르게 처리
4. **네트워크 특화**: CIDR 제거, shutdown→down 매핑 등 도메인 지식 반영

### 관련 연구

- Spider (Text-to-SQL): **Execution Accuracy** 사용
- KILT: **Normalized Exact Match** 사용
- 둘 다 구조화된 답변에 단순 문자열 비교가 부적합하다는 문제의식에서 출발

---

**문서 업데이트**: 2026-02-05  
**코드 기준**: `analyze_results_netconfigqa.py` (NetConfigQAScorer 클래스)
