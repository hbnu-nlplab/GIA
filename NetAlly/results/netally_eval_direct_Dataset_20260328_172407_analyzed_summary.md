# NetConfigQA Comparison Report

> **Generated on**: 2026-03-28 18:43:15

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | N/A | N/A | N/A | 47.00 | N/A | N/A | 53.44 | 62.00 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 66.67 | N/A | 30.00 | 72.22 | 91.67 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 75.00 | 95.00 | 55.00 | 65.00 | 20.00 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | NOT_CONFIGURED | Gap (OK-NC) |
| :--- | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 62.00 | N/A | N/A |

