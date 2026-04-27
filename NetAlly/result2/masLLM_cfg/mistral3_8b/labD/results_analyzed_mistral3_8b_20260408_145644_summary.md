# NetConfigQA Comparison Report

> **Generated on**: 2026-04-27 11:57:22

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| mas_v3 | 24.82 | 8.28 | 24.55 | 20.03 | 4.73 | 89.17 | 22.87 | 23.60 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mas_v3 | 24.90 | N/A | 17.38 | 23.99 | 40.06 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mas_v3 | 48.30 | 56.91 | 22.33 | 5.67 | 9.32 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | Explicit NC | Semantic NC | Compliance | Gap (OK-Explicit) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| mas_v3 | 26.56 | 8.63 | 79.32 | 10.88 | 17.93 |

> `Explicit NC` = exact `NOT_CONFIGURED`; `Semantic NC` = relaxed metric-consistent negative answer; `Compliance` = explicit / semantic.
