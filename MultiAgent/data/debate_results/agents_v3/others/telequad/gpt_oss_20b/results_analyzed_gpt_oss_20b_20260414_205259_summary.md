# NetConfigQA Comparison Report

> **Generated on**: 2026-04-15 11:08:14

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| gpt_oss_20b | 0.77 | 0.69 | 0.76 | 0.38 | 0.51 | 0.95 | 0.74 | 77.28 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| gpt_oss_20b | 0.00 | 0.00 | 77.28 | 0.00 | 0.00 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| gpt_oss_20b | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

