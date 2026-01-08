# NetConfigQA Comparison Report

> **Generated on**: 2026-01-07 19:18:27

### 1. Agent & NLP Metrics

| 모델 | TA Acc | Tool Calls | Steps | Tokens | Time | EM | BertScore | f1(Token) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 34.47% | 1.3 | 0.9 | 255 | 7.2s | 28.2 | 89.6 | 28.2 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 70.06 | 72.28 | 14.54 | 1.49 | 63.95 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 68.30 | 47.62 | 3.15 | 0.00 | 0.00 |

