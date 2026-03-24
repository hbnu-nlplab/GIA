# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:37:31

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 27.61 | 9.75 | 26.70 | 14.55 | 5.58 | 91.27 | 26.49 | 17.19 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 22.47 | N/A | 12.21 | 14.45 | 31.18 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Foundation-Sec-8B | 26.23 | 34.01 | 8.29 | 8.49 | 7.10 |

