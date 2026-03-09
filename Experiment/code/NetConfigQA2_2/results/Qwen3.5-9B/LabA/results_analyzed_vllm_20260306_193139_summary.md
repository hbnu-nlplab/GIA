# NetConfigQA Comparison Report

> **Generated on**: 2026-03-06 20:37:05

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-9B | 0.00 | 0.00 | 0.00 | 65.59 | 0.00 | 0.00 | 72.97 | 72.47 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-9B | 75.16 | 0.00 | 52.56 | 73.79 | 95.15 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-9B | 91.48 | 80.45 | 68.92 | 23.29 | 20.50 |

