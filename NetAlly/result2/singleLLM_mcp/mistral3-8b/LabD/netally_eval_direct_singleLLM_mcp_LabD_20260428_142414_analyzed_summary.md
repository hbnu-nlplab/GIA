# NetConfigQA Comparison Report

> **Generated on**: 2026-04-28 18:20:25

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 55.86 | 22.59 | 55.64 | 54.12 | 19.24 | 94.68 | 56.67 | 56.37 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 47.01 | N/A | 57.44 | 61.78 | 44.03 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 47.26 | 84.29 | 64.58 | 64.39 | 27.95 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | Explicit NC | Semantic NC | Compliance | Gap (OK-Explicit) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 64.49 | 15.29 | 90.65 | 16.87 | 49.20 |

> `Explicit NC` = exact `NOT_CONFIGURED`; `Semantic NC` = relaxed metric-consistent negative answer; `Compliance` = explicit / semantic.
