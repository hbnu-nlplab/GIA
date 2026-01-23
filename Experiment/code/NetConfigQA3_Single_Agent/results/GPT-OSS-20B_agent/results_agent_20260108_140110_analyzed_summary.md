# NetConfigQA Comparison Report

> **Generated on**: 2026-01-08 14:01:54

### 1. Agent & NLP Metrics

| 모델 | TA Acc | Tool Calls | Steps | Tokens | Time | EM | BertScore | f1(Token) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 24.27% | 3.4 | 6.5 | 569 | 38.0s | 20.0 | 87.0 | 25.0 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 0.00 | 0.00 | 30.44 | 15.00 | 0.00 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 100.00 | 0.00 | 23.70 | 4.00 | 0.00 |

