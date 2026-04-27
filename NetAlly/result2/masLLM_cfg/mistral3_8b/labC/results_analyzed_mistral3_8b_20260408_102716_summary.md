# NetConfigQA Comparison Report

> **Generated on**: 2026-04-27 11:57:33

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 29.78 | 9.48 | 29.41 | 24.98 | 5.84 | 89.78 | 28.45 | 28.99 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 22.88 | N/A | 22.53 | 31.16 | 41.39 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 47.33 | 38.93 | 25.66 | 7.86 | 11.61 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | Explicit NC | Semantic NC | Compliance | Gap (OK-Explicit) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 34.36 | 8.33 | 78.08 | 10.67 | 26.03 |

> `Explicit NC` = exact `NOT_CONFIGURED`; `Semantic NC` = relaxed metric-consistent negative answer; `Compliance` = explicit / semantic.
