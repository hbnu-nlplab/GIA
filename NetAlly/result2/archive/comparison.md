# NetConfigQA Comparison Report

> **Generated on**: 2026-04-23 20:02:34

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 46.65 | 15.68 | 46.46 | 59.75 | 19.17 | 95.99 | 66.06 | 66.91 |
| NetAlly-MAS+MCP | 63.31 | 24.77 | 63.01 | 73.34 | 25.44 | 97.38 | 76.63 | 79.50 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 58.43 | N/A | 47.91 | 71.71 | 89.19 |
| NetAlly-MAS+MCP | 60.77 | N/A | 72.00 | 82.35 | 92.90 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 78.31 | 90.00 | 80.42 | 18.95 | 12.62 |
| NetAlly-MAS+MCP | 79.47 | 94.74 | 81.31 | 80.36 | 66.41 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | Explicit NC | Semantic NC | Compliance | Gap (OK-Explicit) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 66.91 | N/A | N/A | N/A | N/A |
| NetAlly-MAS+MCP | 79.50 | N/A | N/A | N/A | N/A |

> `Explicit NC` = exact `NOT_CONFIGURED`; `Semantic NC` = relaxed metric-consistent negative answer; `Compliance` = explicit / semantic.
