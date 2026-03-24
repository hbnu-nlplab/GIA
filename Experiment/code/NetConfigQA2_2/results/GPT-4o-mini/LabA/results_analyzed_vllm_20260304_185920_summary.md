# NetConfigQA Comparison Report

> **Generated on**: 2026-03-23 02:37:41

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| GPT-4o-mini | 37.20 | 19.77 | 35.76 | 27.93 | 8.81 | 91.48 | 34.25 | 33.28 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-4o-mini | 57.60 | N/A | 30.98 | 23.30 | 37.36 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-4o-mini | 35.37 | 52.39 | 43.25 | 10.27 | 8.50 |

