# NetConfigQA2.0 Type-Aware Accuracy PPT 슬라이드

> **발표 주제**: Type-Aware Accuracy (TA-Acc) - 네트워크 설정 Q&A를 위한 답변 유형별 맞춤 평가 메트릭
>
> **데이터셋**: Research_Institute_Internal_DC (762 questions, 10 devices)

---

# 슬라이드 1: 타이틀

## NetConfigQA2.0
### 네트워크 설정 Q&A를 위한 Type-Aware Accuracy 평가 메트릭

**발표자**: [이름]  
**소속**: 한밭대학교 NLP Lab  
**날짜**: 2026년 2월

---

# 슬라이드 2: 목차

1. **문제 정의**: 기존 메트릭의 한계
2. **해결책**: Type-Aware Accuracy (TA-Acc)
3. **데이터셋 소개**: NetConfigQA2.0
4. **4가지 Answer Type 상세**
   - Numeric: 숫자 추출 비교
   - Set: 순서 무관 F1 Score
   - Map: Key-Value 분리 채점
   - Text: Hybrid Scoring (EM + Token F1)
5. **실제 데이터 예시**
6. **실험 결과**

---

# 슬라이드 3: 문제 정의 - 기존 메트릭의 한계 (1)

## 🚨 치명적 문제: IP 주소 오류가 정답 처리됨

### 실제 질문 예시
```
질문: "PE1 장비의 Loopback0 IP 주소는 무엇입니까?"

정답(Ground Truth): 10.0.0.1
LLM 응답:          10.0.0.2  ← 완전히 다른 장비!
```

### 각 메트릭의 점수
| 메트릭 | 점수 | 판정 | 문제점 |
|:---:|:---:|:---:|:---|
| **Exact Match** | 0% | ✅ 정답 | 올바르게 0점 |
| **Token F1** | 85.7% | ❌ 오답 | 6/7 토큰 일치 → 높은 점수! |
| **BERTScore** | ~90% | ❌ 오답 | "둘 다 IP 주소"라서 유사 |
| **ROUGE-L** | ~86% | ❌ 오답 | 문자열 유사도만 봄 |
| **TA-Acc** | 0% | ✅ 정답 | 숫자 불일치 → 0점 |

> **결론**: Token F1, BERTScore, ROUGE는 **네트워크에서 치명적 오류를 정답 처리**합니다.

---

# 슬라이드 4: 문제 정의 - 기존 메트릭의 한계 (2)

## 🚨 순서만 달라도 0점 처리

### 실제 질문 예시 (데이터셋 ID: SYSTEM_USER_LIST)
```
질문: "PE1 장비에 등록된 로컬 사용자 목록을 알려주세요."

정답(Ground Truth): ["admin", "operator", "guest"]
LLM 응답:          ["guest", "operator", "admin"]  ← 순서만 다름!
```

### 각 메트릭의 점수
| 메트릭 | 점수 | 판정 | 문제점 |
|:---:|:---:|:---:|:---|
| **Exact Match** | 0% | ❌ 오답 | 문자열이 다르므로 0점 |
| **ROUGE-L** | ~67% | ⚠️ 부분 | 순서 영향 받음 |
| **TA-Acc (Set F1)** | 100% | ✅ 정답 | **순서 무관**! 완벽한 일치 |

> **Set 타입은 순서가 중요하지 않습니다!**

---

# 슬라이드 5: 문제 정의 - 기존 메트릭의 한계 (3)

## 🚨 서술형 답변 시 감점

### 실제 질문 예시 (데이터셋 ID: SYSTEM_USER_COUNT)
```
질문: "leaf2 장비에 등록된 로컬 사용자는 총 몇 명입니까?"

정답(Ground Truth): 1
LLM 응답:          "leaf2 장비에는 총 1명의 사용자가 등록되어 있습니다."
```

### 각 메트릭의 점수
| 메트릭 | 점수 | 판정 | 문제점 |
|:---:|:---:|:---:|:---|
| **Exact Match** | 0% | ❌ 오답 | 문자열 불일치 |
| **ROUGE-L** | ~18% | ❌ 오답 | 토큰 겹침 적음 |
| **TA-Acc (Numeric)** | 100% | ✅ 정답 | 숫자 `1` 추출 → 일치! |

> **LLM은 자연스럽게 서술형으로 답변합니다. 이를 수용해야 합니다!**

---

# 슬라이드 6: 해결책 - Type-Aware Accuracy

## 🎯 핵심 아이디어

> **"Answer Type에 따라 적절한 비교 방식을 선택한다"**

### 데이터셋 구조
```json
{
  "question": "PE1 장비에 설정된 VRF 목록을 알려주세요.",
  "answer": "[\"VRF_AI\", \"VRF_BIO\", \"VRF_HPC\"]",
  "answer_type": "set"  ← 이 타입을 보고 비교 방식 결정!
}
```

### 4가지 Answer Type
| Type | 개수 | 비율 | 채점 방식 |
|:---|---:|---:|:---|
| **text** | 392 | 51.4% | 정규화 EM → Token F1 폴백 |
| **set** | 162 | 21.3% | 순서 무관 F1 Score |
| **numeric/number** | 168 | 22.1% | 숫자 추출 후 비교 |
| **map** | 40 | 5.2% | Key 50% + Value 50% |

---

# 슬라이드 7: 데이터셋 소개 - NetConfigQA2.0

## 📊 데이터셋 통계

| 항목 | 값 |
|:---|:---|
| **총 질문 수** | **762개** |
| **네트워크** | Research Institute Internal DC |
| **장비 수** | **10대** (PE 2, P 4, Leaf 4) |
| **난이도** | L1 ~ L5 |
| **카테고리** | 17개 |
| **Positive Testing** | 577개 (75.7%) |
| **Negative Testing** | 185개 (24.3%) |

### 장비 목록
```
PE (Provider Edge):  PE1, PE2
P (Provider):        P1, P2, P3, P4
Leaf (고객 접점):     Leaf1, Leaf2, Leaf3, Leaf4
```

---

# 슬라이드 8: 데이터셋 소개 - 난이도별 분포

## 📈 5단계 난이도 체계

| Level | 설명 | 개수 | 비율 | 예시 |
|:---:|:---|---:|---:|:---|
| **L1** | Single Device Extraction | 364 | 47.8% | 호스트네임, 인터페이스 상태 |
| **L2** | Multi-Device Aggregation | 21 | 2.8% | 전체 VRF 수, OSPF 라우터 수 |
| **L3** | Cross-Device Comparison | 127 | 16.7% | VRF 불일치 검출, BGP 비교 |
| **L4** | Reachability Analysis | 149 | 19.6% | Traceroute, ACL 검증 |
| **L5** | What-If Analysis | 101 | 13.3% | 장애 시뮬레이션, SPOF 탐지 |

### 시각화 (막대 그래프)
```
L1 ████████████████████████████████████  47.8%
L2 █                                      2.8%
L3 ██████████                            16.7%
L4 ████████████                          19.6%
L5 ████████                              13.3%
```

---

# 슬라이드 9: Answer Type 1 - Numeric (숫자)

## 🔢 숫자 추출 후 수치 비교

### 실제 데이터 예시
```json
{
  "id": "SYSTEM_USER_COUNT",
  "level": "L1",
  "question": "leaf2 장비에 등록된 로컬 사용자는 총 몇 명입니까?",
  "answer": "1",
  "answer_type": "numeric"
}
```

### 채점 알고리즘
```python
def score_numeric(pred, gold):
    p_num = extract_number(pred)  # "총 1명" → 1
    g_num = extract_number(gold)  # "1" → 1
    return 1.0 if p_num == g_num else 0.0
```

### 채점 예시
| 정답 | LLM 응답 | 추출 | TA-Acc |
|:---|:---|:---|:---:|
| `1` | `"1"` | 1 == 1 | ✅ **1.0** |
| `1` | `"1명"` | 1 == 1 | ✅ **1.0** |
| `1` | `"one"` | 1 == 1 (영어 변환) | ✅ **1.0** |
| `1` | `"2"` | 1 ≠ 2 | ❌ **0.0** |

---

# 슬라이드 10: Answer Type 1 - Numeric (실제 데이터 더보기)

## 📋 실제 데이터셋 예시

### 예시 1: 라우팅 테이블 엔트리 개수
```json
{
  "id": "ROUTING_TABLE_ENTRY_COUNT",
  "level": "L1",
  "question": "p3 장비의 라우팅 테이블 엔트리는 총 몇 개입니까?",
  "answer": "5",
  "answer_type": "number"
}
```

### 예시 2: 인터페이스 개수
```json
{
  "id": "INTERFACE_COUNT",
  "level": "L1", 
  "question": "PE1 장비에 설정된 인터페이스는 총 몇 개입니까?",
  "answer": "5",
  "answer_type": "numeric"
}
```

### LLM 응답 시나리오
| 정답 | LLM 응답 | EM | Token F1 | **TA-Acc** |
|:---|:---|:---:|:---:|:---:|
| `"5"` | `"5"` | 1.0 | 1.0 | **1.0** |
| `"5"` | `"5개입니다"` | 0.0 | 0.5 | **1.0** ✨ |
| `"5"` | `"총 5개의 인터페이스"` | 0.0 | 0.3 | **1.0** ✨ |
| `"5"` | `"약 5개 정도"` | 0.0 | 0.4 | **1.0** ✨ |

---

# 슬라이드 11: Answer Type 2 - Set (집합)

## 📦 순서 무관 F1 Score

### 실제 데이터 예시
```json
{
  "id": "SYSTEM_USER_LIST",
  "level": "L1",
  "question": "leaf4 장비에 등록된 로컬 사용자 목록을 알려주세요.",
  "answer": "[\"admin\"]",
  "answer_type": "set"
}
```

### 채점 알고리즘
```python
def score_set(pred, gold):
    p_set = parse_set(pred)  # 소문자 정규화
    g_set = parse_set(gold)
    
    intersection = len(p_set & g_set)
    precision = intersection / len(p_set) if p_set else 0.0
    recall = intersection / len(g_set) if g_set else 0.0
    
    f1 = 2 * precision * recall / (precision + recall)
    return f1
```

### 핵심 특징
- ✅ **순서 무관**: `["A", "B"]` = `["B", "A"]`
- ✅ **대소문자 무시**: `["Admin"]` = `["admin"]`
- ✅ **부분 점수**: 일부만 맞아도 점수 부여

---

# 슬라이드 12: Answer Type 2 - Set (실제 데이터 더보기)

## 📋 실제 데이터셋 예시

### 예시 1: OSPF Area 0 라우터 목록 (L5)
```json
{
  "id": "OSPF_AREA0_ROUTERS_GLOBAL",
  "level": "L5",
  "question": "OSPF Backbone Area(Area 0)에 속한 라우터 목록은?",
  "answer": "[\"p1\", \"p2\", \"p3\", \"p4\", \"pe1\"]",
  "answer_type": "set"
}
```

### 채점 시나리오
| 정답 | LLM 응답 | Precision | Recall | **F1 (TA-Acc)** |
|:---|:---|:---:|:---:|:---:|
| `["p1","p2","p3","p4","pe1"]` | `["p1","p2","p3","p4","pe1"]` | 5/5 | 5/5 | **1.00** ✅ |
| `["p1","p2","p3","p4","pe1"]` | `["pe1","p4","p3","p2","p1"]` | 5/5 | 5/5 | **1.00** ✅ 순서 무관! |
| `["p1","p2","p3","p4","pe1"]` | `["p1","p2","p3","p4"]` | 4/4 | 4/5 | **0.89** ⚠️ |
| `["p1","p2","p3","p4","pe1"]` | `["p1","p2","p3","p4","pe2"]` | 4/5 | 4/5 | **0.80** ⚠️ |
| `["p1","p2","p3","p4","pe1"]` | `["spine1","spine2"]` | 0/2 | 0/5 | **0.00** ❌ |

---

# 슬라이드 13: Answer Type 2 - Set (F1 Score 계산)

## 🧮 F1 Score 계산 예시

### 문제
```
질문: "OSPF Area 0에 속한 라우터 목록은?"
정답: ["p1", "p2", "p3", "p4", "pe1"] (5개)
예측: ["p1", "p2", "p3", "p4"]        (4개, 1개 누락)
```

### 계산 과정
```
교집합 = {"p1", "p2", "p3", "p4"} → 4개

Precision = 교집합 / 예측 수 = 4/4 = 1.0
           → "예측한 것 중 얼마나 맞았나?"

Recall = 교집합 / 정답 수 = 4/5 = 0.8
        → "정답 중 얼마나 찾았나?"

F1 = 2 × (1.0 × 0.8) / (1.0 + 0.8)
   = 2 × 0.8 / 1.8
   = 0.889 (88.9%)
```

> **부분 점수 부여**: 1개 빠뜨렸지만 88.9% 점수!

---

# 슬라이드 14: Answer Type 3 - Map (Key-Value)

## 🗺️ Key 50% + Value 50% 채점

### 실제 데이터 예시
```json
{
  "id": "INTERFACE_STATUS_MAP",
  "level": "L1",
  "question": "leaf3 장비의 각 인터페이스 상태를 알려주세요.",
  "answer": "{\"GigabitEthernet0/0\": \"up\", \"GigabitEthernet0/1\": \"down\", 
             \"GigabitEthernet0/2\": \"up\", \"GigabitEthernet0/3\": \"down\"}",
  "answer_type": "map"
}
```

### 채점 알고리즘
```python
def score_map(pred, gold):
    common_keys = set(pred.keys()) & set(gold.keys())
    all_keys = set(pred.keys()) | set(gold.keys())
    
    key_score = len(common_keys) / len(all_keys) * 0.5
    
    val_matches = sum(1 for k in common_keys 
                      if normalize(pred[k]) == normalize(gold[k]))
    val_score = val_matches / len(common_keys) * 0.5
    
    return key_score + val_score
```

---

# 슬라이드 15: Answer Type 3 - Map (실제 데이터 더보기)

## 📋 실제 데이터셋 예시

### 정답 (4개 인터페이스)
```json
{
  "GigabitEthernet0/0": "up",
  "GigabitEthernet0/1": "down",
  "GigabitEthernet0/2": "up",
  "GigabitEthernet0/3": "down"
}
```

### 채점 시나리오
| LLM 응답 | Key | Value | **TA-Acc** |
|:---|:---:|:---:|:---:|
| 완벽 일치 | 4/4 | 4/4 | **1.00** ✅ |
| 순서만 다름 | 4/4 | 4/4 | **1.00** ✅ |
| 1개 Key 누락 | 3/4 | 3/3 | **0.875** ⚠️ |
| 1개 Value 오류 | 4/4 | 3/4 | **0.875** ⚠️ |
| shutdown→down | 4/4 | 4/4 | **1.00** ✅ 정규화! |

### 특수 기능: IP 및 상태 정규화
```python
# CIDR 제거
"10.0.0.1/31" → "10.0.0.1"

# 상태 정규화
"shutdown" → "down"
```

---

# 슬라이드 16: Answer Type 3 - Map (점수 계산)

## 🧮 Map 점수 계산 예시

### 문제
```
정답: {"Gi0/0": "up", "Gi0/1": "down", "Gi0/2": "up", "Gi0/3": "down"}
예측: {"Gi0/0": "up", "Gi0/1": "up"}
     (2개 Key 누락, 1개 Value 오류)
```

### 계산 과정
```
전체 Key = {"Gi0/0", "Gi0/1", "Gi0/2", "Gi0/3"} → 4개
공통 Key = {"Gi0/0", "Gi0/1"} → 2개

Key Score = (공통 / 전체) × 0.5
          = (2/4) × 0.5
          = 0.25

Value 일치 = {"Gi0/0"} → 1개 (Gi0/1은 up≠down)

Value Score = (일치 / 공통) × 0.5
            = (1/2) × 0.5
            = 0.25

Total = Key Score + Value Score
      = 0.25 + 0.25
      = 0.50 (50%)
```

---

# 슬라이드 17: Answer Type 4 - Text (Hybrid)

## 📝 Exact Match → Token F1 폴백

### 실제 데이터 예시
```json
{
  "id": "SYSTEM_HOSTNAME_TEXT",
  "level": "L1",
  "question": "p2 장비의 호스트네임은 무엇입니까?",
  "answer": "\"p2\"",
  "answer_type": "text"
}
```

### 채점 알고리즘 (2단계)
```python
def score_text(pred, gold):
    pred_norm = normalize(pred)  # 소문자, 카운터 제거
    gold_norm = normalize(gold)
    
    # Step 1: Exact Match
    if pred_norm == gold_norm:
        return 1.0
    
    # Step 2: Token F1 (폴백)
    pred_tokens = set(pred_norm.split())
    gold_tokens = set(gold_norm.split())
    # ... F1 계산
```

---

# 슬라이드 18: Answer Type 4 - Text (실제 데이터 더보기)

## 📋 실제 데이터셋 예시

### 예시 1: Traceroute 경로 (L4)
```json
{
  "id": "TRACEROUTE_pe2_pe1",
  "level": "L4",
  "question": "pe2에서 10.0.1.1까지의 경로를 나열해주세요.",
  "answer": "\"pe2 → p3 → p2 → pe1\"",
  "answer_type": "text"
}
```

### 예시 2: 경로 없음 (Negative)
```json
{
  "id": "TRACEROUTE_leaf4_p3",
  "level": "L4",
  "question": "leaf4에서 10.0.0.3까지의 경로를 나열해주세요.",
  "answer": "\"경로 없음\"",
  "answer_type": "text"
}
```

### 채점 시나리오
| 정답 | LLM 응답 | 방식 | **TA-Acc** |
|:---|:---|:---:|:---:|
| `"pe2 → p3 → p2 → pe1"` | `"pe2 → p3 → p2 → pe1"` | EM | **1.0** ✅ |
| `"pe2 → p3 → p2 → pe1"` | `"PE2→P3→P2→PE1"` | EM (정규화) | **1.0** ✅ |
| `"경로 없음"` | `"no route"` | EM? | **?** (향후 개선) |

---

# 슬라이드 19: Negative Testing (할루시네이션 탐지)

## 🔍 없는 정보에 대한 테스트

### 실제 데이터 예시
```json
{
  "id": "SYSTEM_TIMEZONE_TEXT",
  "level": "L1",
  "question": "pe2 장비의 시간대(Timezone)는 무엇입니까?",
  "answer": "null",
  "answer_status": "NOT_CONFIGURED"
}
```

### 목적
> **LLM이 설정되지 않은 정보를 만들어내는지(할루시네이션) 테스트**

### 채점 시나리오
| 정답 | LLM 응답 | 판정 | **TA-Acc** |
|:---|:---|:---:|:---:|
| `null` | `"null"` | ✅ 정답 | **1.0** |
| `null` | `"None"` | ✅ 정답 | **1.0** |
| `null` | `"not configured"` | ✅ 정답 | **1.0** |
| `null` | `""` (빈 문자열) | ✅ 정답 | **1.0** |
| `null` | `"UTC"` | ❌ 할루시네이션! | **0.0** |
| `null` | `"Asia/Seoul"` | ❌ 할루시네이션! | **0.0** |

---

# 슬라이드 20: L4 문제 예시 - Reachability Analysis

## 🛤️ 도달성 분석 (Batfish 기반)

### 실제 데이터 예시

#### 예시 1: 경로 존재
```json
{
  "id": "TRACEROUTE_pe2_pe1",
  "level": "L4",
  "question": "pe2에서 10.0.1.1까지의 네트워크 경로(장비 순서)를 나열해주세요.",
  "answer": "\"pe2 → p3 → p2 → pe1\"",
  "answer_type": "text"
}
```

#### 예시 2: 경로 없음
```json
{
  "id": "TRACEROUTE_leaf4_p3",
  "level": "L4", 
  "question": "leaf4에서 10.0.0.3까지의 네트워크 경로를 나열해주세요.",
  "answer": "\"경로 없음\"",
  "answer_type": "text"
}
```

### L4 질문 통계
- **총 149개** (19.6%)
- Traceroute, Bounded Path, ACL Check 등

---

# 슬라이드 21: L5 문제 예시 - What-If Analysis

## 🔮 장애 시뮬레이션 (Batfish Fork Snapshot)

### 실제 데이터 예시

#### 예시 1: SPOF 탐지
```json
{
  "id": "SPOF_DETECTION_GLOBAL",
  "level": "L5",
  "question": "단일 장비 장애 시 통신이 두절되는 구간(SPOF)이 존재합니까?",
  "answer": "\"없음\"",
  "answer_type": "set"
}
```

#### 예시 2: 대체 경로 분석
```json
{
  "id": "K_FAILURE_leaf1_leaf3",
  "level": "L5",
  "question": "leaf1에서 172.16.3.2로 가는 대체 경로들을 모두 나열해주세요.",
  "answer": "[\"leaf1 → pe1\", \"leaf1\"]",
  "answer_type": "set"
}
```

### L5 질문 통계
- **총 101개** (13.3%)
- SPOF Detection, K-Failure, Link/Node Failure 시뮬레이션

---

# 슬라이드 22: Level × Type 분포

## 📊 난이도별 Answer Type 분포

| Level | map | number | numeric | set | text | **Total** |
|:---:|---:|---:|---:|---:|---:|---:|
| **L1** | 40 | 10 | 85 | 128 | 101 | **364** |
| **L2** | - | 1 | 11 | 9 | - | **21** |
| **L3** | - | - | 5 | 15 | 107 | **127** |
| **L4** | - | 45 | - | 7 | 97 | **149** |
| **L5** | - | 11 | - | 3 | 87 | **101** |

### 인사이트
- **L1에 map 집중** (40개): 장비별 인터페이스 상태
- **L4에 number 집중** (45개): 홉 수, 경로 길이
- **L3~L5에 text 다수**: 분석 결과, 판단 근거

---

# 슬라이드 23: 전체 채점 파이프라인

## 🔄 Scoring Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        TA-Acc Pipeline                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 입력 전처리 (공통)                                           │
│     ├─ <think>...</think> 태그 제거                             │
│     ├─ Markdown 코드 블록 제거                                  │
│     ├─ 따옴표/공백 정규화                                       │
│     └─ null/none/n/a 표현 통일                                  │
│                                                                 │
│  2. Answer Type 라우팅                                          │
│     │                                                           │
│     ├─ numeric/number → _score_numeric() → 숫자 추출 비교       │
│     ├─ set            → _score_set()     → F1 Score            │
│     ├─ map            → _score_map()     → Key-Value 분리      │
│     └─ text           → _score_text()    → EM → Token F1      │
│                                                                 │
│  3. 점수 반환 (0.0 ~ 1.0)                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

# 슬라이드 24: 기존 메트릭 vs TA-Acc 비교

## 📈 예상 실험 결과

| Model | Exact Match | ROUGE-L | BLEU | Token F1 | **TA-Acc** |
|:---|:---:|:---:|:---:|:---:|:---:|
| GPT-4 | 42.3% | 58.7% | 51.2% | 54.1% | **73.5%** |
| Claude-3 | 38.1% | 55.3% | 47.9% | 50.8% | **69.2%** |
| Llama-3-70B | 31.5% | 48.2% | 42.1% | 45.3% | **61.8%** |

### 점수 차이 발생 원인

| Answer Type | EM | TA-Acc | 차이 원인 |
|:---|:---:|:---:|:---|
| **set** | 낮음 | 높음 | 순서만 달라도 EM=0 |
| **numeric** | 낮음 | 높음 | 서술형 답변 시 EM=0 |
| **map** | 낮음 | 높음 | JSON 순서/공백 차이 시 EM=0 |
| **text** | 비슷 | 비슷 | Hybrid라 Token F1과 유사 |

---

# 슬라이드 25: 관련 연구

## 📚 유사한 접근 방식

| 벤치마크 | 도메인 | 평가 방식 | 유사점 |
|:---|:---|:---|:---|
| **Spider** | Text-to-SQL | Execution Accuracy | 결과 동일하면 정답 |
| **KILT** | Knowledge QA | Normalized EM | 정규화 후 비교 |
| **TriviaQA** | QA | Normalized EM | 대소문자/공백 정규화 |
| **SQuAD** | Reading Comprehension | Token F1 | 토큰 기반 부분 점수 |

### 핵심 인용

> "For structured data extraction tasks, token-level metrics like F1 or ROUGE are insufficient because they fail to capture semantic equivalence of structured outputs."

> "In network configuration domain, a single character difference in IP address represents a completely different device."

---

# 슬라이드 26: 결론

## 🎯 Type-Aware Accuracy의 3가지 핵심 가치

### 1. 타입별 최적화된 평가
- **Numeric**: 숫자만 추출하여 수치 비교
- **Set**: 순서 무관 F1 Score
- **Map**: Key-Value 분리 채점 + IP 정규화
- **Text**: Hybrid (EM 우선, Token F1 폴백)

### 2. 실무 친화적
- LLM의 자연스러운 서술형 답변 수용
- 불필요한 감점 최소화
- 네트워크 도메인 지식 반영 (CIDR, shutdown)

### 3. 확장 가능성
- 새로운 타입 추가 용이 (예: ipv4, cidr, date)
- 도메인별 커스터마이징 가능

---

# 슬라이드 27: 한 문장 요약

## 💡 Take-Home Message

> **"EM/F1/BERT/ROUGE는 자연어 텍스트용이고,**
> **저희 데이터는 구조화된 정형 데이터라서**
> **데이터 타입별 정확성 비교를 사용했습니다."**

### 핵심 근거 4가지

1. **Token F1의 한계**: IP 주소 `10.0.0.1` vs `10.0.0.2`가 85% 정답 처리
2. **순서 불변성 필요**: `["A","B"]` = `["B","A"]` (Set 타입)
3. **형식 불변성 필요**: `one` = `1` = `1.0` (Numeric 타입)
4. **네트워크 특화**: CIDR 제거, shutdown→down 매핑

---

# 슬라이드 28: Q&A

## 🙋 질문 & 토의

### 예상 질문

**Q1: Boolean 타입은 없나요?**
> A: 코드에서는 `text` 타입으로 처리합니다. `true`→`예`, `false`→`아니오`로 정규화됩니다.

**Q2: 왜 numeric과 number가 따로 있나요?**
> A: policies.json에서 의미적으로 구분하지만, 채점 시에는 동일한 로직을 사용합니다.

**Q3: Token F1은 언제 사용되나요?**
> A: Text 타입에서 Exact Match 실패 시 폴백으로 사용됩니다.

---

**감사합니다!**

> **코드**: https://github.com/hbnu-nlplab/GIA  
> **데이터셋**: Research_Institute_Internal_DC (762 questions)
