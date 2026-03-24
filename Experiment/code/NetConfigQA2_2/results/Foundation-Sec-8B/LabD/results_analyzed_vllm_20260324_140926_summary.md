# NetConfigQA Comparison Report

> **Generated on**: 2026-03-24 14:10:13

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 10.00 | 0.00 | 10.00 | 10.00 | 1.78 | 84.18 | 10.00 | 10.00 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | N/A | N/A | 10.00 | N/A | N/A |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 0.00 | 0.00 | 0.00 | 0.00 | 10.00 |

