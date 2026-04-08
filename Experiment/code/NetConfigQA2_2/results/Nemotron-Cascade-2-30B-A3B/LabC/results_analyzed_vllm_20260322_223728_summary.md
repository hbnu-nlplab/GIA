# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:38:13

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 28.24 | 12.84 | 27.51 | 22.21 | 5.48 | 86.72 | 24.70 | 27.60 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 46.72 | N/A | 25.45 | 18.96 | 41.11 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Nemotron-Cascade-2-30B-A3B | 44.99 | 54.44 | 35.30 | 5.56 | 1.29 |

