# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:38:44

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-4B | 26.92 | 13.54 | 26.02 | 25.10 | 6.63 | 86.25 | 27.52 | 32.92 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-4B | 40.02 | N/A | 30.42 | 28.29 | 37.60 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3.5-4B | 36.62 | 55.71 | 43.12 | 6.06 | 1.94 |

