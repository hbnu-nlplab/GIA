# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:37:26

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 36.10 | 13.89 | 35.05 | 22.53 | 7.98 | 91.71 | 33.68 | 26.75 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 25.13 | N/A | 18.20 | 29.75 | 37.35 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 27.38 | 45.45 | 38.95 | 20.32 | 10.16 |

