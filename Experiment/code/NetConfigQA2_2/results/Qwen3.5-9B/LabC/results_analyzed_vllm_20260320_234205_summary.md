# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:39:03

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-9B | 41.94 | 18.44 | 40.92 | 31.00 | 10.18 | 92.72 | 40.30 | 35.52 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-9B | 42.73 | N/A | 33.96 | 29.86 | 46.08 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-9B | 54.24 | 66.67 | 41.29 | 11.84 | 10.32 |

