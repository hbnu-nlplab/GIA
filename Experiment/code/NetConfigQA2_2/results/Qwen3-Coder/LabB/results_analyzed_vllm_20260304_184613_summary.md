# NetConfigQA Comparison Report

> **Generated on**: 2026-03-06 13:01:13

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Qwen3-Coder | 0.00 | 0.00 | 0.00 | 32.40 | 0.00 | 92.36 | 38.45 | 36.14 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3-Coder | 37.78 | 0.00 | 34.99 | 30.62 | 44.21 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3-Coder | 49.83 | 31.52 | 35.82 | 6.12 | 12.17 |

