# NetConfigQA Comparison Report

> **Generated on**: 2026-03-27 23:34:05

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | N/A | N/A | N/A | 17.50 | N/A | N/A | 27.68 | 42.50 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | N/A | N/A | 35.48 | 66.67 | N/A |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 0.00 | 0.00 | 0.00 | 85.00 | 0.00 |

---

### 4. Positive vs Negative Testing

| 모델 | OK | NOT_CONFIGURED | Gap (OK-NC) |
| :--- | :---: | :---: | :---: |
| NetAlly-MAS+MCP | 42.50 | N/A | N/A |

