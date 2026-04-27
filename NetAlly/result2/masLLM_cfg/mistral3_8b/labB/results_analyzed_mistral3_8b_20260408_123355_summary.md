# NetConfigQA Comparison Report

> **Generated on**: 2026-04-27 11:57:56

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 38.01 | 12.79 | 37.61 | 30.78 | 7.85 | 90.52 | 36.11 | 35.85 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 24.16 | N/A | 28.00 | 45.21 | 41.06 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 46.25 | 57.51 | 36.96 | 10.61 | 7.81 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | Explicit NC | Semantic NC | Compliance | Gap (OK-Explicit) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mistral3_8b | 45.86 | 8.06 | 77.23 | 10.43 | 37.80 |

> `Explicit NC` = exact `NOT_CONFIGURED`; `Semantic NC` = relaxed metric-consistent negative answer; `Compliance` = explicit / semantic.
