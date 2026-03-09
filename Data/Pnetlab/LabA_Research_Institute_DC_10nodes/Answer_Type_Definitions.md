# NetConfigQA2.0 답변 유형 정의서

본 문서는 `Research_Institute_Internal_DC` 데이터셋(총 **762개** 질문)에서 사용되는 **4가지 핵심 답변 유형(Answer Types)**에 대한 정의와 실제 통계, 채점 방식을 정리합니다.

> **코드 참조**: `Experiment/code/NetConfigQA2/analyze_results_netconfigqa.py`

---

## 📊 네트워크 환경 정보

| 항목 | 값 |
|:---|:---|
| **네트워크명** | Research Institute Internal DC |
| **장비 수** | **10대** (PE 2대, P 4대, Leaf 4대) |
| **장비 목록** | PE1, PE2, P1, P2, P3, P4, Leaf1, Leaf2, Leaf3, Leaf4 |
| **라우팅 프로토콜** | OSPF + BGP (MPLS L3VPN) |
| **VRF** | AI, BIO, HPC (3개) |

---

## 📈 질문 분포 통계 (실제 데이터)

### 난이도별 분포

| Level | 설명 | 개수 | 비율 |
|:---:|:---|---:|---:|
| **L1** | Single Device Extraction | 364 | 47.8% |
| **L2** | Multi-Device Aggregation | 21 | 2.8% |
| **L3** | Cross-Device Comparison | 127 | 16.7% |
| **L4** | Reachability Analysis | 149 | 19.6% |
| **L5** | What-If Analysis | 101 | 13.3% |
| **Total** | | **762** | **100%** |

### 답변 유형별 분포

| Answer Type | 개수 | 비율 | 설명 | 코드 별칭 |
|:---|---:|---:|:---|:---|
| **text** | 392 | 51.4% | 일반 텍스트 (기본값) | - |
| **set** | 162 | 21.3% | 순서 없는 집합 | `set_str`, `list` |
| **numeric** | 101 | 13.3% | 수치 (L1-L3) | `scalar_int` |
| **number** | 67 | 8.8% | 수치 (L4-L5) | `int`, `integer` |
| **map** | 40 | 5.2% | 키-값 쌍 (JSON) | `map_str_str`, `dictionary`, `json` |
| **Total** | **762** | **100%** | | |

> [!IMPORTANT]
> **`numeric`과 `number`의 관계**
> 
> 두 타입은 **동일한 채점 로직**을 사용합니다. `canonical_answer_type()` 함수에서 다양한 별칭을 정규화하여 처리합니다:
> ```python
> if answer_type in ["numeric", "scalar_int", "number"]:
>     return self._score_numeric(pred, gold)
> ```

---

## 📝 4가지 핵심 Answer Type 상세

### 1. numeric / number (수치형)
**채점 클래스**: `_score_numeric()`

**특징**:
- 정규식으로 숫자 추출: `r'-?\d+(\.\d+)?'`
- 영어 숫자 단어 변환 지원 (one → 1, five → 5, ...)
- 한국어 카운터 무시 ("3개" → 3)

**채점 로직**:
```python
def _score_numeric(pred, gold):
    p_num = extract_number(pred)  # "총 5개입니다" → 5.0
    g_num = extract_number(gold)  # "5" → 5.0
    
    if p_num is None or g_num is None:
        return 1.0 if pred.lower() == gold.lower() else 0.0
    
    return 1.0 if p_num == g_num else 0.0
```

**예시**:
| 정답 | LLM 응답 | 추출 | 점수 |
|:---|:---|:---|:---:|
| `"3"` | `"3"` | 3 == 3 | ✅ 1.0 |
| `"3"` | `"총 3개"` | 3 == 3 | ✅ 1.0 |
| `"5"` | `"five"` | 5 == 5 | ✅ 1.0 |
| `"3"` | `"4"` | 3 ≠ 4 | ❌ 0.0 |

---

### 2. set (집합형)
**채점 클래스**: `_score_set()`

**특징**:
- **순서 무관**: `["a", "b"]` = `["b", "a"]`
- **부분 점수 (F1 Score)**: 일부만 맞아도 점수 부여
- 다양한 형식 지원: `[]`, `{}`, `()`, 쉼표 구분
- 대소문자 무시

**채점 로직**:
```python
def _score_set(pred, gold):
    p_set = parse_set(pred)  # 소문자 정규화된 집합
    g_set = parse_set(gold)
    
    intersection = len(p_set & g_set)
    precision = intersection / len(p_set) if p_set else 0.0
    recall = intersection / len(g_set) if g_set else 0.0
    
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"score": f1}
```

**예시**:
| 정답 | LLM 응답 | 계산 | 점수 |
|:---|:---|:---|:---:|
| `["A", "B", "C"]` | `["A", "B", "C"]` | P=1.0, R=1.0 | ✅ **1.0** |
| `["A", "B", "C"]` | `["C", "B", "A"]` | 순서 무관 | ✅ **1.0** |
| `["A", "B", "C"]` | `["A", "B"]` | P=1.0, R=0.67 | ⚠️ **0.80** |
| `["A", "B", "C"]` | `["X", "Y"]` | 교집합=0 | ❌ **0.0** |

---

### 3. map (맵/딕셔너리형)
**채점 클래스**: `_score_map()`

**특징**:
- **키 순서 무관**: `{"a":1, "b":2}` = `{"b":2, "a":1}`
- **부분 점수**: 키 50% + 값 50%
- **IP 정규화**: CIDR 제거 (`10.0.0.1/31` → `10.0.0.1`)
- **상태 정규화**: `shutdown` → `down`

**채점 로직**:
```python
def _score_map(pred, gold):
    p_obj = json.loads(pred)
    g_obj = json.loads(gold)
    
    common = set(p_obj.keys()) & set(g_obj.keys())
    all_k = set(p_obj.keys()) | set(g_obj.keys())
    
    # Value 비교 시 IP 정규화 적용
    val_matches = sum(1 for k in common if normalize(p_obj[k]) == normalize(g_obj[k]))
    
    key_score = len(common) / len(all_k) * 0.5
    val_score = val_matches / len(common) * 0.5 if common else 0
    
    return {"score": key_score + val_score}
```

**예시**:
| 정답 | LLM 응답 | 계산 | 점수 |
|:---|:---|:---|:---:|
| `{"a":"up", "b":"down"}` | `{"a":"up", "b":"down"}` | 키 2/2, 값 2/2 | ✅ **1.0** |
| `{"a":"up", "b":"down"}` | `{"b":"down", "a":"up"}` | 순서 무관 | ✅ **1.0** |
| `{"a":"up", "b":"down"}` | `{"a":"up"}` | 키 1/2, 값 1/1 | ⚠️ **0.75** |
| `{"a":"10.0.0.1/31"}` | `{"a":"10.0.0.1"}` | CIDR 정규화 | ✅ **1.0** |
| `{"a":"shutdown"}` | `{"a":"down"}` | 상태 정규화 | ✅ **1.0** |

---

### 4. text (텍스트형) - Hybrid Scoring
**채점 클래스**: `_score_text()`

**특징**:
- **2단계 채점**: ① 정규화 EM → ② Token F1 폴백
- **정규화**: 대소문자, 한국어 카운터, 동의어 매핑
- **부분 점수**: Exact Match 실패 시 Token F1

**정규화 규칙**:
```python
# 동의어 매핑
synonyms = {
    'true': '예', 'false': '아니오',
    'yes': '예', 'no': '아니오',
    'shutdown': 'down',
}

# 한국어 카운터 제거
"3개" → "3"
"5대" → "5"
```

**채점 로직**:
```python
def _score_text(pred, gold):
    pred_norm = normalize(pred)
    gold_norm = normalize(gold)
    
    # 1. Exact Match (Primary)
    if pred_norm == gold_norm:
        return {"score": 1.0}
    
    # 2. Token F1 (Secondary)
    pred_tokens = set(pred_norm.split())
    gold_tokens = set(gold_norm.split())
    
    common = pred_tokens & gold_tokens
    if common:
        precision = len(common) / len(pred_tokens)
        recall = len(common) / len(gold_tokens)
        f1 = 2 * precision * recall / (precision + recall)
        return {"score": f1}
    
    return {"score": 0.0}
```

**예시**:
| 정답 | LLM 응답 | 방식 | 점수 |
|:---|:---|:---|:---:|
| `"PE1"` | `"PE1"` | EM | ✅ **1.0** |
| `"PE1"` | `"pe1"` | EM (대소문자) | ✅ **1.0** |
| `"PE1"` | `"호스트는 PE1"` | Token F1 | ⚠️ **0.5** |
| `"PE1"` | `"PE2"` | 불일치 | ❌ **0.0** |

---

## 📚 Level × Answer Type 분포

| Level | map | number | numeric | set | text | Total |
|:---:|---:|---:|---:|---:|---:|---:|
| **L1** | 40 | 10 | 85 | 128 | 101 | 364 |
| **L2** | - | 1 | 11 | 9 | - | 21 |
| **L3** | - | - | 5 | 15 | 107 | 127 |
| **L4** | - | 45 | - | 7 | 97 | 149 |
| **L5** | - | 11 | - | 3 | 87 | 101 |

---

## 🎯 TA-Acc의 핵심 아이디어

### ❌ 기존 메트릭의 한계
```python
# Exact Match, BLEU, ROUGE 등 텍스트 기반 메트릭
GT   = ["VRF_AI", "VRF_BIO", "VRF_HPC"]
Pred = ["VRF_HPC", "VRF_AI", "VRF_BIO"]  # 순서만 다름

→ Exact Match: 0.0 (완전 오답 처리!)
```

### ✅ TA-Acc (Type-Aware Accuracy)
```python
# Answer Type에 따라 적절한 채점 로직 적용
answer_type = "set"
→ Set F1 Score: 1.0 (순서 무관, 완벽한 정답!)
```

---

## 💡 FAQ

**Q1: Boolean 타입은 없나요?**
- A: **없습니다.** `true`/`false` 답변은 `text` 타입으로 처리되며, 정규화 과정에서 `true`→`예`, `false`→`아니오`로 매핑됩니다.

**Q2: `numeric`과 `number`를 왜 구분하나요?**
- A: `policies.json`에서 의미적 구분을 위해 분리되어 있으나, 채점 시에는 동일한 `_score_numeric()` 함수를 사용합니다.

**Q3: `text` 타입에서 부분 점수가 나오는 이유는?**
- A: Exact Match 실패 시 Token F1을 계산하여 부분 점수를 부여합니다. 이는 LLM의 자연스러운 서술형 답변을 수용하기 위함입니다.

**Q4: IP 주소 비교에서 CIDR이 제거되는 이유는?**
- A: `10.0.0.1/31`과 `10.0.0.1`은 동일한 IP를 나타내므로, CIDR 표기를 제거하여 비교합니다.

---

**문서 생성 일시**: 2026-02-05  
**데이터셋**: Research_Institute_Internal_DC (762 questions, 10 devices)  
**코드 기준**: `analyze_results_netconfigqa.py` (NetConfigQAScorer)
