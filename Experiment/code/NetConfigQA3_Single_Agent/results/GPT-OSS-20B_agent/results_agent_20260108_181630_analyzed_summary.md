# NetConfigQA Comparison Report

> **Generated on**: 2026-01-08 18:39:15

### 1. Agent & NLP Metrics

| 모델 | TA Acc | Tool Calls | Steps | Tokens | Time | EM | BertScore | f1(Token) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 54.17% | 2.4 | 3.5 | 414 | 16.6s | 43.5 | 93.7 | 52.5 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 82.25 | 83.33 | 34.83 | 30.00 | 72.67 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 89.60 | 70.00 | 47.78 | 15.65 | 13.04 |

