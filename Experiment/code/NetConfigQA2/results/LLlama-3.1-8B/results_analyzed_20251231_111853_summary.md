# NetConfigQA Comparison Report

> **Generated on**: 2026-01-02 15:44:43

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| LLlama-3.1-8B | 31.88 | 14.36 | 31.42 | 17.59 | 7.86 | 89.65 | 30.19 | 29.08 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| LLlama-3.1-8B | 67.94 | 15.84 | 30.17 | 11.94 | 32.18 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| LLlama-3.1-8B | 36.75 | 37.14 | 30.45 | 18.40 | 13.79 |

