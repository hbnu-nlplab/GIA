# NetConfigQA Comparison Report

> **Generated on**: 2026-03-06 12:56:33

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 0.00 | 0.00 | 0.00 | 59.81 | 0.00 | 95.92 | 63.10 | 70.60 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 72.06 | 0.00 | 50.85 | 76.38 | 89.80 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| GPT-OSS-20B | 88.35 | 90.71 | 67.86 | 19.18 | 15.60 |

