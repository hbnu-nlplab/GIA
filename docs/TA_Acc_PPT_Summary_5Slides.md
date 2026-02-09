# NetConfigQA2.0 Type-Aware Accuracy (5-Slide Storytelling)

> **발표 흐름(Narrative)**:
> 1. **Data**: 우리 데이터는 다양한 타입(Set, Map 등)이 섞여 있다.
> 2. **Problem**: 기존 단일 메트릭(EM, F1)으로는 이 다양성을 평가할 수 없다.
> 3. **Solution**: 그래서 타입별로 채점 방식을 달리하는 TA-Acc를 제안한다.
> 4. **How**: 구체적으로 타입별(Set, Map, Numeric) 적용 예시.
> 5. **Conclusion**: 이를 통해 네트워크 설정 검증에 최적화된 정확한 평가를 달성했다.

---

# 슬라이드 1: NetConfigQA 데이터셋의 다양성 (Our Data)

## "단순 텍스트가 아닌, 다양한 구조(Structure)를 가진 답변들"

우리 데이터셋(NetConfigQA)은 네트워크 설정 검증을 위해 **4가지 고유한 답변 타입**을 포함합니다.

| Type | 실제 데이터 예시 (Ground Truth) | 비율 |
|:---:|:---|:---:|
| **Set**<br>(List) | `["p1", "p2", "p3"]` (순서 없는 라우터 목록) | 21.3% |
| **Map**<br>(JSON) | `{"Gi0/0": "up", "Gi0/1": "down"}` (인터페이스 상태) | 5.2% |
| **Numeric** | `5`, `100` (OSPF Cost, 개수) | 22.1% |
| **Text** | `pe1`, `not configured` (호스트명, 설정 상태) | 51.4% |

> **핵심**: "이렇게 다양한 형식이 섞여 있는데, **하나의 잣대(Metric)로 평가할 수 있을까요?**"

---

# 슬라이드 2: 기존 단일 메트릭 평가의 실패 (Problem)

## "하나의 메트릭을 일괄 적용하면, 심각한 오류가 발생합니다."

### ❌ Exact Match (EM)의 실패 (Set Type)
- **질문**: "OSPF 라우터 목록은?" (정답: `["A", "B"]`)
- **모델 답변**: `["B", "A"]` (순서만 다름 → 정답이어야 함)
- **평가**: **0점** (문자열 불일치) 😱
  → *모델은 맞았는데 틀렸다고 채점됨 (False Negative)*

### ❌ Token F1의 실패 (Numeric Type)
- **질문**: "관리 IP 주소는?" (정답: `10.0.0.1`)
- **모델 답변**: `10.0.0.2` (완전히 다른 장비 → 오답이어야 함)
- **평가**: **85.7점** (7개 중 6개 토큰 일치) 😱
  → *치명적 오류를 높은 점수로 평가함 (False Positive)*

---

# 슬라이드 3: 해결책 - Type-Aware Accuracy (Solution)

## "답변 타입에 따라 '맞춤형 채점 방식'을 적용하자!"

우리는 데이터의 타입(Answer Type)을 먼저 식별하고, 각 타입에 **가장 적합한 평가 로직**을 동적으로 적용하는 **TA-Acc**를 제안합니다.

### 🔄 TA-Acc 파이프라인
```
[Model Output]
     ↓
[Answer Type 식별] (Set? Map? Numeric?)
     ↓
[맞춤형 채점 로직 적용]
  ├─ Set     → 순서 무관 F1 Score
  ├─ Map     → Key-Value 구조적 비교
  ├─ Numeric → 값(Value) 중심 비교
  └─ Text    → 정규화 + Hybrid EM
     ↓
[Final Score] (Micro-Average)
```

---

# 슬라이드 4: 타입별 상세 평가 방식 (How)

## "구조와 의미를 이해하는 스마트한 채점"

### 1. Set & Map Type (구조 중심)
- **Set**: `["A", "B"]` == `["B", "A"]` (**순서 불변성** 보장)
- **Map**: `{"a":"up", "b":"down"}` vs `{"a":"up", "b":"shutdown"}`
  - 기존 EM은 0점이지만, TA-Acc는 **부분 점수** 부여 및 `shutdown`→`down` **정규화** 지원

### 2. Numeric & Text Type (의미 중심)
- **Numeric**: `"five"`, `"5"`, `"총 5개"` → 모두 숫자 **`5`**로 추출하여 비교 (**형식 불변성**)
- **Text**: `"not configured"`, `"null"`, `"None"` → 모두 **'설정 없음'**으로 통일하여 평가 (**Negative Testing**)

---

# 슬라이드 5: 결론 및 효과 (Conclusion)

## "네트워크 설정 검증에 최적화된 정확한 평가"

### 🎯 TA-Acc 도입 효과
1. **억울한 오답 제거**: 순서/형식 차이로 인한 감점 방지
2. **치명적 오류 검출**: IP/숫자 미세 오류를 정확히 0점 처리
3. **도메인 특화**: 네트워크 용어(shutdown/down) 및 구조(JSON) 완벽 이해

### 💡 Take-Home Message
> **"네트워크 설정 데이터는 단순 텍스트가 아닌 '정형 데이터(Structured Data)'입니다.**
> **따라서 단일 메트릭이 아닌, 타입별 특성을 고려한 Type-Aware Evaluation이 필수적입니다."**

