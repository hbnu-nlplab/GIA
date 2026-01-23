# NetConfigQA Comparison Report

> **Generated on**: 2026-01-02 15:43:58

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Mistral3-8B | 28.12 | 10.36 | 27.93 | 20.08 | 6.32 | 87.49 | 30.38 | 41.57 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Mistral3-8B | 4.19 | 48.51 | 37.52 | 1.49 | 72.84 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Mistral3-8B | 57.20 | 14.29 | 50.03 | 15.82 | 18.25 |

