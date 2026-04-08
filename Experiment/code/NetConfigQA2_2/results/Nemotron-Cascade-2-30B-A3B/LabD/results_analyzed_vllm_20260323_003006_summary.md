# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:38:19

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 20.74 | 8.96 | 20.24 | 16.59 | 3.69 | 84.79 | 18.45 | 21.04 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 43.11 | N/A | 17.11 | 14.14 | 41.36 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 42.96 | 50.00 | 44.99 | 2.05 | 0.62 |

