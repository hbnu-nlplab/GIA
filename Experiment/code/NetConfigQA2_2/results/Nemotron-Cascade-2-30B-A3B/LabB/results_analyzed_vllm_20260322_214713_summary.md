# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:38:09

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 37.87 | 17.49 | 36.87 | 29.02 | 6.60 | 88.57 | 32.01 | 36.12 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 48.76 | N/A | 33.29 | 35.13 | 38.41 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 47.03 | 67.84 | 42.81 | 6.77 | 1.56 |

